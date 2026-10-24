"""Native CLI recovery and backup lifecycle for the booted NixOS service."""
import hashlib
import json
import os
import pwd
import shutil
import pathlib
import subprocess
import sys
import time

configuration = "/var/lib/positron-release/positron.toml"
directory = pathlib.Path("/var/lib/positron-recovery")
state_path = pathlib.Path("/root/positron-backup-state.json")
repository = "/var/lib/positron-repository"
repository_id = "11111111-1111-4111-8111-111111111111"


def run(arguments, credential=None, owner=False):
    command = (["runuser", "-u", "positron", "--"] if owner else []) + arguments
    result = subprocess.run(command, input=credential, capture_output=True, timeout=180)
    if result.returncode:
        detail = (result.stdout + result.stderr).decode(errors="replace")
        for secret in claim.values():
            detail = detail.replace(secret, "<redacted>")
        raise RuntimeError("native lifecycle command failed: " + " ".join(command) + ": " + detail[:4096])
    return result.stdout.decode()


def fields(text):
    return dict(field.split("=", 1) for field in text.split() if "=" in field)


def observe_snapshot(status, started, outcome, error="none"):
    record = {"event": "upgrade_snapshot", "outcome": outcome, "error": error,
              "elapsed_ms": int((time.monotonic() - started) * 1000)}
    identifier = status.get("operation_id", "")
    if (len(identifier) == 32 and any(character != "0" for character in identifier)
            and all(character in "0123456789abcdef" for character in identifier)):
        record["operation_id"] = identifier
    if status.get("status") in ["Pending", "Running", "Succeeded", "Failed", "Cancelled"]:
        record["status"] = status["status"]
    if status.get("stage") in ["None"] + ["Some(" + stage + ")" for stage in
            ["Preflight", "Draining", "Snapshot", "Publishing", "AwaitingRestart", "Verifying", "Succeeded"]]:
        record["stage"] = status["stage"]
    revision = status.get("revision", "")
    if revision.isascii() and revision.isdecimal() and len(revision) <= 20:
        record["revision"] = int(revision)
    if status.get("rollback_available") in ["true", "false"]:
        record["rollback_available"] = status["rollback_available"] == "true"
    for child, kind in [("snapshot", "BackupSnapshot"), ("verification", "BackupVerification")]:
        if status.get(child) in ["present", "absent"]:
            record[child] = status[child]
        if status.get(child + "_kind") == kind:
            record[child + "_kind"] = kind
        for field, allowed in [
                ("phase", ["Accepted", "Preflight", "BackupCapture", "BackupTransfer",
                           "BackupVerification", "BackupPublication", "BackupCancellation", "Published", "Cancelled"]),
                ("status", ["Pending", "Running", "Succeeded", "Failed", "Cancelled"])]:
            key = child + "_" + field
            if status.get(key) in allowed:
                record[key] = status[key]
        for field in ["revision", "progress_percent", "checkpoint_sequence"]:
            key = child + "_" + field
            value = status.get(key, "")
            if value.isascii() and value.isdecimal() and len(value) <= 20:
                number = int(value)
                if number <= (100 if field == "progress_percent" else 18446744073709551615):
                    record[key] = number
        key = child + "_checkpoint_sha256"
        value = status.get(key, "")
        if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
            record[key] = value
    print(json.dumps(record), flush=True)


def advance_snapshot(common, started):
    command = ["runuser", "-u", "positron", "--", "positron", "upgrade", "offline", "advance"]
    try:
        result = subprocess.run(command + common + ["--seconds", "60"],
                                input=None, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired:
        observe_snapshot({}, started, "failed", "command_timeout")
        raise RuntimeError("offline upgrade advance failed: command_timeout") from None
    if result.returncode:
        category = {
            b"positron: upgrade remains resumable; inspect and retry after trusted time or capacity recovers": "resumable",
            b"positron: authenticated completed Drain is required; resume the source process control path": "drain_incomplete",
            b"positron: installed artifact does not match the accepted signed release": "artifact_mismatch",
            b"positron: installed release or operation authority rejected": "authentication_rejected",
            b"positron: unsupported release or format transition": "unsupported_transition",
            b"positron: upgrade precondition changed; inspect the accepted operation": "precondition_changed",
            b"positron: offline request does not match the accepted upgrade": "invalid_request",
            b"positron: upgrade recovery state or exclusive volume ownership unavailable": "unsafe_state",
            b"positron: upgrade outcome unknown; inspect the same operation before retrying": "outcome_unknown",
            b"positron: upgrade verification failed; use the explicit rollback or fresh-target restore boundary": "verification_failed",
        }.get(result.stderr.strip(), "other")
        observe_snapshot({}, started, "failed", category)
        raise RuntimeError("offline upgrade advance failed: " + category)
    try:
        status = fields(result.stdout.decode())
    except UnicodeDecodeError:
        observe_snapshot({}, started, "failed", "invalid_receipt")
        raise RuntimeError("offline upgrade advance failed: invalid_receipt") from None
    observe_snapshot(status, started, "advanced")
    return status


claim = fields(pathlib.Path("/root/positron-claim").read_text())
credential = claim["administrator_secret"].encode()
transport = ["--endpoint", "127.0.0.1:4311", "--credential-stdin", "--allow-plaintext"]

def admit(kind, action, arguments):
    deadline = time.monotonic() + 60

    def execute(command):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("native lifecycle admission deadline exhausted")
        try:
            result = subprocess.run(command, input=credential, capture_output=True, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise RuntimeError("native lifecycle admission outcome unknown at deadline") from None
        if time.monotonic() >= deadline:
            raise RuntimeError("native lifecycle admission deadline exhausted")
        return result

    def repository_failure(result):
        return {
            b"positron: invalid repository request": "invalid_request",
            b"positron: system administration authentication rejected": "authentication_rejected",
            b"positron: repository operation unavailable": "operation_unavailable",
            b"positron: stale resource generation; inspect current state before retrying": "stale_generation",
            b"positron: operation precondition failed; inspect current state before retrying": "precondition_failed",
            b"positron: idempotency key conflicts with an accepted request": "idempotency_conflict",
            b"positron: administration unavailable; inspect or retry the same operation": "administration_unavailable",
            b"positron: capacity unavailable; retry the same idempotent request": "capacity_unavailable",
            b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying": "transport_unknown",
        }.get(result.stderr.strip(), "other")

    def operation(result):
        if result.returncode:
            raise RuntimeError("repository admission reconciliation refused: code=" + repository_failure(result))
        try:
            receipt = fields(result.stdout.decode())
            identifier = receipt["operation_id"]
            # Match the canonical public operation ID emitted by the repository CLI.
            if (len(identifier) != 32 or not any(character != "0" for character in identifier)
                    or any(character not in "0123456789abcdef" for character in identifier)
                    or receipt["status"] not in ["pending", "running", "succeeded"]):
                raise ValueError("invalid receipt")
        except (UnicodeDecodeError, KeyError, ValueError):
            raise RuntimeError("repository admission reconciliation invalid receipt") from None
        if time.monotonic() >= deadline:
            raise RuntimeError("native lifecycle admission deadline exhausted")
        return receipt

    while True:
        command = None
        result = execute(["positron", "repository", "status"] + transport)
        if result.returncode == 0:
            try:
                current_generation = fields(result.stdout.decode())["catalog_generation"]
                if (not current_generation.isascii() or not current_generation.isdecimal()
                        or len(current_generation) > 20 or int(current_generation) > 18446744073709551615):
                    raise ValueError("invalid generation")
            except (UnicodeDecodeError, KeyError, ValueError):
                raise RuntimeError("repository status invalid receipt") from None
            command = ["positron", kind, action] + transport + arguments + ["--expected-generation", current_generation]
            result = execute(command)
        elif repository_failure(result) not in ["stale_generation", "administration_unavailable", "capacity_unavailable"]:
            raise RuntimeError("repository status refused: code=" + repository_failure(result))
        if result.returncode == 0:
            receipt = fields(result.stdout.decode())
            if time.monotonic() >= deadline:
                raise RuntimeError("native lifecycle admission deadline exhausted")
            return receipt
        if command is not None and kind == "repository" and action == "init" and repository_failure(result) == "transport_unknown":
            # Inspect first; only canonical exact replay can verify the full original binding.
            if arguments.count("--idempotency-key") != 1:
                raise RuntimeError("repository admission reconciliation requires one key")
            key_index = arguments.index("--idempotency-key") + 1
            if key_index >= len(arguments):
                raise RuntimeError("repository admission reconciliation requires one key")
            inspected = operation(execute(["positron", "repository", "lookup"] + transport +
                ["--idempotency-key", arguments[key_index]]))
            replayed = operation(execute(command))
            if replayed["operation_id"] != inspected["operation_id"]:
                raise RuntimeError("repository admission reconciliation changed operation")
            return replayed
        retryable = any(message in result.stderr for message in [b"stale resource generation", b"administration unavailable", b"capacity unavailable"])
        if not retryable or time.monotonic() >= deadline:
            if kind == "upgrade" and action == "start":
                category = {
                    b"positron: invalid upgrade request": "invalid_request",
                    b"positron: system administration authentication rejected": "authentication_rejected",
                    b"positron: upgrade operation unavailable": "operation_unavailable",
                    b"positron: stale resource generation; inspect current state before retrying": "stale_generation",
                    b"positron: upgrade precondition failed; inspect current state before retrying": "precondition_failed",
                    b"positron: idempotency key conflicts with an accepted request": "idempotency_conflict",
                    b"positron: administration unavailable; inspect or retry the same operation": "administration_unavailable",
                    b"positron: capacity unavailable; retry the same idempotent request": "capacity_unavailable",
                    b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying": "transport_unknown",
                }.get(result.stderr.strip(), "other")
                raise RuntimeError("native service refused lifecycle admission: code=" + category)
            raise RuntimeError("native service refused lifecycle admission")
        time.sleep(0.1)



if sys.argv[1] == "recovery":
    identity = str(directory / "owner.txt")
    run(["age-keygen", "-o", identity], owner=True)
    recipient = run(["age-keygen", "-y", identity], owner=True).strip()
    # The CLI's bounded protected reference contains one native X25519 key.
    identity_file = pathlib.Path(identity)
    keys = [line for line in identity_file.read_text().splitlines()
            if line.startswith("AGE-SECRET-KEY-")]
    assert len(keys) == 1
    identity_file.write_text(keys[0] + "\n")
    common = ["--data-dir", "/var/lib/positron", "--secrets-dir", "/var/lib/positron-secrets",
              "--bundle", str(directory / "instance.age")]
    pin = fields(run(["positron", "keys", "recovery", "create"] + common +
                     ["--recipient", recipient], owner=True))
    run(["positron", "keys", "recovery", "verify"] + common +
        ["--identity-file", identity], owner=True)
    state_path.write_text(json.dumps({"pin": pin}))
elif sys.argv[1] == "backup":
    state = json.loads(state_path.read_text())
    common = ["--locator", repository, "--repository-id", repository_id]
    initialized = admit("repository", "init", common +
        ["--idempotency-key", "22222222-2222-4222-8222-222222222222"])
    completed = fields(run(["positron", "repository", "wait"] + transport +
        ["--operation-id", initialized["operation_id"], "--wait-seconds", "60"], credential))
    assert completed["status"] == "succeeded"
    assert completed["operation_id"] == initialized["operation_id"]
    assert completed["repository_id"] == repository_id
    accepted = admit("backup", "create", common +
        ["--retention-seconds", "3600", "--idempotency-key", "33333333-3333-4333-8333-333333333333"])
    while True:
        result = subprocess.run(["positron", "backup", "wait"] + transport +
            ["--operation-id", accepted["operation_id"], "--wait-seconds", "60"],
            input=credential, capture_output=True, timeout=180)
        completed = fields(result.stdout.decode())
        if result.returncode == 0:
            break
        if (completed.get("operation_id") != accepted["operation_id"]
                or completed.get("status") not in ["pending", "running"]
                or b"operation outcome remains unknown; inspect the same operation ID before retrying" not in result.stderr):
            raise RuntimeError("same-operation backup wait refused without a resumable pending outcome")
    assert completed["status"] == "succeeded"
    assert completed["operation_id"] == accepted["operation_id"]
    assert completed["manifest_checksum"]
    state["snapshot"] = accepted["operation_id"]
    state["checksum"] = completed["manifest_checksum"]
    state_path.write_text(json.dumps(state))
elif sys.argv[1] == "prepare-upgrade":
    root = pathlib.Path("/var/lib/positron-release")
    inputs = json.loads(pathlib.Path("/etc/positron-upgrade-inputs.json").read_text())
    base = pathlib.Path(configuration).read_text()
    query = root / "query.input"
    query.write_text(claim["query_secret"])
    query.chmod(0o600)
    owner = pwd.getpwnam("positron")
    os.chown(query, owner.pw_uid, owner.pw_gid)
    run(["env", "POSITRON_TEST_UPGRADE_ROOT=" + str(root),
         "POSITRON_TEST_UPGRADE_SOURCE=" + inputs["source"],
         "POSITRON_TEST_UPGRADE_CANDIDATE=" + inputs["candidate"],
         "POSITRON_TEST_UPGRADE_COMMIT=" + inputs["commit"], inputs["fixture"],
         "--ignored", "--exact", "prepare_nixos_signed_upgrade_fixture"], owner=True)
    document = pathlib.Path(configuration).read_text()
    document = document.replace(json.dumps(str(root / "data")), json.dumps("/var/lib/positron"))
    document = document.replace(json.dumps(str(root / "secrets")), json.dumps("/var/lib/positron-secrets"))
    document += "\n" + "\n".join(line for line in base.splitlines() if not line.strip().startswith("schema_version"))
    pathlib.Path(configuration).write_text(document)
    state = json.loads(state_path.read_text())
    state["target_manifest"] = (root / "candidate.digest").read_text()
    state["source_hash"] = hashlib.sha256(pathlib.Path(inputs["source"]).read_bytes()).hexdigest()
    state["target_hash"] = hashlib.sha256(pathlib.Path(inputs["candidate"]).read_bytes()).hexdigest()
    assert state["source_hash"] != state["target_hash"]
    state_path.write_text(json.dumps(state))
elif sys.argv[1] == "upgrade":
    state = json.loads(state_path.read_text())
    accepted = admit("upgrade", "start", ["--candidate-manifest", state["target_manifest"],
        "--repository-id", repository_id, "--retention-seconds", "3600",
        "--idempotency-key", "55555555-5555-4555-8555-555555555555"])
    state["upgrade"] = accepted["operation_id"]
    state_path.write_text(json.dumps(state))
elif sys.argv[1] == "publish-upgrade":
    state = json.loads(state_path.read_text())
    common = ["--config", configuration, "--operation-id", state["upgrade"]]
    started = time.monotonic()
    # Emulated ARM needs about 200 seconds for the snapshot before independent
    # verification starts. Bound the full fixture journey, retaining 60-second turns.
    deadline = started + 600
    while True:
        status = advance_snapshot(common, started)
        if status["stage"] == "Some(Publishing)":
            break
        if time.monotonic() >= deadline:
            observe_snapshot(status, started, "deadline")
            raise RuntimeError("authenticated upgrade snapshot did not complete")
    reference = fields(run(["positron", "upgrade", "offline", "restore-reference"] + common, owner=True))
    assert reference["fresh_target_required"] == "true" and reference["manifest_checksum"]
    state["upgrade_snapshot"] = reference["snapshot_id"]
    status = fields(run(["positron", "upgrade", "offline", "publish"] + common, owner=True))
    assert status["stage"] == "Some(AwaitingRestart)"
    root = pathlib.Path("/var/lib/positron-release/export")
    shutil.copyfile(root / "candidate.manifest", root / "current.manifest")
    shutil.copyfile(root / "inventory.json", root / "current.inventory.json")
    state_path.write_text(json.dumps(state))
elif sys.argv[1] == "upgraded":
    state = json.loads(state_path.read_text())
    inputs = json.loads(pathlib.Path("/etc/positron-upgrade-inputs.json").read_text())
    deadline = time.monotonic() + 60
    while True:
        status = fields(run(["positron", "upgrade", "status"] + transport + ["--operation-id", state["upgrade"]], credential))
        if status["status"] == "succeeded":
            break
        if status["status"] == "failed" or time.monotonic() >= deadline:
            raise RuntimeError("target startup attestation did not complete")
        time.sleep(0.1)
    assert status["target_version"] == inputs["version"]
    assert status["target_manifest"] == state["target_manifest"]
    assert status["source_artifact"] == state["source_hash"]
    assert status["target_artifact"] == state["target_hash"]
else:
    state = json.loads(state_path.read_text())
    arguments = ["--config", configuration, "--locator", repository, "--repository-id", repository_id,
                 "--snapshot-id", state["snapshot"], "--expected-manifest-checksum", state["checksum"],
                 "--idempotency-key", "44444444-4444-4444-8444-444444444444",
                 "--bundle", str(directory / "instance.age"), "--identity-file", str(directory / "owner.txt"),
                 "--output", "json"]
    for key in ["instance", "root_key_id", "root_created_at", "root_fingerprint", "integrity_public_key", "integrity_fingerprint"]:
        arguments.extend(["--" + key.replace("_", "-"), state["pin"][key]])
    accepted = json.loads(run(["positron", "backup", "restore", "start"] + arguments, owner=True))
    completed = json.loads(run(["positron", "backup", "restore", "wait"] + arguments +
        ["--operation-id", accepted["operation"]["id"], "--wait-seconds", "60"], owner=True))
    assert completed["operation"]["status"] == "succeeded"
