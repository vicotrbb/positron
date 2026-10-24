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


claim = fields(pathlib.Path("/root/positron-claim").read_text())
credential = claim["administrator_secret"].encode()
transport = ["--endpoint", "127.0.0.1:4311", "--credential-stdin", "--allow-plaintext"]

def generation():
    return fields(run(["positron", "repository", "status"] + transport, credential))["catalog_generation"]

def admit(kind, action, arguments):
    deadline = time.monotonic() + 60
    attempt = 0
    while True:
        attempt += 1
        result = subprocess.run(["positron", kind, action] + transport + arguments +
            ["--expected-generation", generation()], input=credential, capture_output=True, timeout=60)
        if result.returncode == 0:
            return fields(result.stdout.decode())
        retryable = any(message in result.stderr for message in [b"stale resource generation", b"administration unavailable", b"capacity unavailable"])
        if not retryable or time.monotonic() >= deadline:
            # Closed failure attribution only; transport refusal stays unknown.
            failure = {
                b"positron: invalid repository request": "invalid_request",
                b"positron: invalid backup request": "invalid_request",
                b"positron: system administration authentication rejected": "authentication_rejected",
                b"positron: repository operation unavailable": "operation_unavailable",
                b"positron: backup operation unavailable": "operation_unavailable",
                b"positron: stale resource generation; inspect current state before retrying": "stale_generation",
                b"positron: operation precondition failed; inspect current state before retrying": "precondition_failed",
                b"positron: idempotency key conflicts with an accepted request": "idempotency_conflict",
                b"positron: administration unavailable; inspect or retry the same operation": "administration_unavailable",
                b"positron: capacity unavailable; retry the same idempotent request": "capacity_unavailable",
                b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying": "transport_unknown",
            }.get(result.stderr.strip(), "other")
            role = {("repository", "init"): "repository_init", ("backup", "create"): "backup_create"}.get((kind, action), "other")
            elapsed_ms = int((time.monotonic() - (deadline - 60)) * 1000)
            raise RuntimeError(f"native service refused lifecycle admission: operation={role} "
                f"code={failure} returncode={result.returncode} attempt={attempt} elapsed_ms={elapsed_ms}")
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
    deadline = time.monotonic() + 180
    while True:
        status = fields(run(["positron", "upgrade", "offline", "advance"] + common + ["--seconds", "60"], owner=True))
        if status["stage"] == "Some(Publishing)":
            break
        if time.monotonic() >= deadline:
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
