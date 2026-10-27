"""Public data/backup/restore/upgrade assertions for the actual Compose service."""
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
import uuid

CONFIG = "/etc/positron/positron.toml"
EXPORT = "/etc/positron/fixtures/export"
BACKUPS = "/var/lib/positron-backups"
REPOSITORY = "11111111-1111-4111-8111-111111111111"
ADMIN_IMAGE = "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe"


def fields(output):
    return dict(field.split("=", 1) for field in output.decode().split() if "=" in field)


class DataLifecycle:
    def __init__(self, case, root, project, compose, docker, claim):
        self.case, self.root, self.project, self.compose, self.docker = case, root, project, compose, docker
        self.keys = fields(claim)
        self.admin = self.keys["administrator_secret"]
        self.query_key = self.keys["query_secret"]

    def prepare(self, container, config):
        fixture = self.root / "fixture"
        fixture.mkdir()
        self.docker("cp", f"{container}:/usr/bin/positron", str(fixture / "current"))
        environment = dict(os.environ, POSITRON_TEST_COMPOSE_FIXTURE_ROOT=str(fixture), POSITRON_TEST_COMPOSE_CURRENT_BINARY=str(fixture / "current"))
        subprocess.run([os.environ["POSITRON_TEST_COMPOSE_HELPER"], "--ignored", "--exact", "prepare_compose_lifecycle_inputs"], input=self.query_key.encode(), env=environment, check=True, capture_output=True)
        generated = (fixture / "positron.toml").read_text()
        section = generated.split("[release.installation]", 1)[1].replace(str(fixture), "/etc/positron/fixtures")
        config += "\n[release.installation]" + section
        self.config = config
        files = {"positron.toml": config.encode()}
        for path in (fixture / "export").iterdir():
            files[f"fixtures/export/{path.name}"] = path.read_bytes()
        self.install(files)
        # Backups are an explicit writable production mount, not a /tmp fixture.
        self.docker("run", "--rm", "-v", f"{self.project}_backups:{BACKUPS}", ADMIN_IMAGE,
                    "install", "-d", "-o", "65532", "-g", "65532", "-m", "0700", BACKUPS, f"{BACKUPS}/repository")
        self.recipient = (fixture / "export/recipient").read_text()
        self.candidate_digest = (fixture / "export/candidate-digest").read_text()
        candidate_context = self.root / "candidate-image"
        candidate_context.mkdir()
        shutil.copyfile(fixture / "candidate.tar.gz", candidate_context / "native.tar.gz")
        recipe = Path(__file__).parent.parent / "oci"
        shutil.copyfile(recipe / "MPL-2.0.txt", candidate_context / "MPL-2.0.txt")
        candidate_tag = f"positron119-candidate-{self.project}"
        self.docker("buildx", "build", "--load", "--build-arg", "SOURCE_DATE_EPOCH=0", "--file", str(recipe / "Dockerfile"), "--tag", candidate_tag, str(candidate_context))
        self.candidate_image = json.loads(self.docker("image", "inspect", candidate_tag))[0]["Id"]
        self.candidate_tag = candidate_tag
        # Compare the actual candidate OCI executable to the signed fixture input.
        probe = f"{self.project}-candidate-files"
        self.docker("create", "--name", probe, self.candidate_image)
        try:
            copied = self.docker("cp", f"{probe}:/usr/bin/positron", "-")
            with tarfile.open(fileobj=io.BytesIO(copied)) as archive:
                self.case.assertEqual(archive.extractfile(archive.getmembers()[0]).read(), (fixture / "export/candidate-executable").read_bytes())
        finally:
            self.docker("rm", probe)

    def install(self, files):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            directories = sorted({str(parent) for name in files for parent in Path(name).parents if str(parent) != "."}, key=lambda name: (len(Path(name).parts), name))
            for name in directories:
                member = tarfile.TarInfo(name)
                member.type, member.mode, member.uid, member.gid = tarfile.DIRTYPE, 0o700, 65532, 65532
                archive.addfile(member)
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.uid, member.gid = len(data), 0o600, 65532, 65532
                archive.addfile(member, io.BytesIO(data))
        self.docker("run", "--rm", "-i", "-v", f"{self.project}_configuration:/config", ADMIN_IMAGE, "tar", "-xf", "-", "-C", "/config", input=payload.getvalue())

    def offline(self, *args, compose=None):
        return (compose or self.compose)("run", "--rm", "--no-deps", "positron", *args)

    def online(self, family, action=None, *args, credential=None, compose=None, timeout=35):
        command = [family] + ([action] if action else [])
        return (compose or self.compose)("exec", "-T", "positron", "/usr/bin/positron", *command, "--endpoint", "127.0.0.1:8080", "--server-name", "localhost", "--trust-file", "/etc/positron/tls/ca.pem", "--credential-stdin", *args, input=(credential or self.admin).encode(), timeout=timeout)

    def query(self, compose=None):
        started = time.monotonic()
        while True:
            try:
                response = json.loads(self.online("query", None, "--request", f"{EXPORT}/query.json", credential=self.query_key, compose=compose, timeout=max(0.1, started + 35 - time.monotonic())))
                break
            except subprocess.CalledProcessError as error:
                # The native CLI already decodes the canonical wire rejection.
                # Match its exact capacity diagnostic, as the archive test does.
                if error.stdout or error.stderr != b"positron: query capacity unavailable; retry after backoff\n" or time.monotonic() + 1 >= started + 5: raise
                time.sleep(1)
        def objects(value):
            if isinstance(value, dict):
                yield value
                for child in value.values(): yield from objects(child)
            elif isinstance(value, list):
                for child in value: yield from objects(child)
        rows = list(objects(response))
        self.case.assertEqual(sum(value == "compose-retained" for row in rows for value in row.values() if isinstance(value, str)), 1)
        terminal = [row for row in rows if row.get("state") == "complete"]
        self.case.assertEqual(len(terminal), 1)
        self.case.assertEqual(terminal[0]["stats"]["records"], "1")
        return terminal[0]["stats"]["resultDigest"]

    def ingest(self):
        port = self.compose("port", "positron", "4318").decode().strip().rsplit(":", 1)[1]
        body = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [{"timeUnixNano": "42", "body": {"stringValue": "compose-retained"}}]}]}]}).encode()
        context = ssl.create_default_context(cafile=str(self.root / "ca.pem"))
        denied = urllib.request.Request(f"https://localhost:{port}/v1/logs", data=body, headers={"Authorization": "Bearer invalid", "Content-Type": "application/json"})
        with self.case.assertRaises(urllib.error.HTTPError) as failure:
            urllib.request.urlopen(denied, context=context, timeout=5)
        self.case.assertEqual(failure.exception.code, 401)
        deadline = time.monotonic() + 30
        while True:
            request = urllib.request.Request(f"https://localhost:{port}/v1/logs", data=body, headers={"Authorization": "Bearer " + self.keys["ingest_secret"], "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, context=context, timeout=5) as response:
                    self.case.assertEqual(response.status, 200)
                break
            except urllib.error.HTTPError as error:
                if error.code != 429 or error.headers.get("Retry-After") != "1" or time.monotonic() + 1 >= deadline: raise
                time.sleep(1)

    def mutate(self, family, action, *args):
        deadline = time.monotonic() + 30
        key = str(uuid.uuid4())
        while True:
            status = fields(self.online("repository", "status"))
            try:
                output = self.online(family, action, *args, "--expected-generation", status["catalog_generation"], "--idempotency-key", key)
                break
            except subprocess.CalledProcessError as error:
                if b"stale resource generation" not in error.stderr or time.monotonic() >= deadline: raise
        operation = fields(output)["operation_id"]
        deadline = time.monotonic() + 300
        while True:
            try:
                result = fields(self.online(family, "wait", "--operation-id", operation, "--wait-seconds", "30"))
                self.case.assertEqual(result["status"], "succeeded")
                return operation, result
            except subprocess.CalledProcessError as error:
                if b"outcome remains unknown" not in error.stderr or time.monotonic() >= deadline: raise

    def backup(self):
        self.compose("stop")
        output = self.offline("keys", "recovery", "create", "--data-dir", "/var/lib/positron", "--secrets-dir", "/var/lib/positron-secrets", "--bundle", f"{BACKUPS}/recovery.age", "--recipient", self.recipient)
        self.pin = fields(output)
        self.offline("keys", "recovery", "verify", "--data-dir", "/var/lib/positron", "--secrets-dir", "/var/lib/positron-secrets", "--bundle", f"{BACKUPS}/recovery.age", "--identity-file", f"{EXPORT}/recovery.identity")
        self.compose("up", "--detach", "--wait", "--wait-timeout", "90", "--pull", "never")
        self.mutate("repository", "init", "--locator", f"{BACKUPS}/repository", "--repository-id", REPOSITORY)
        self.snapshot, result = self.mutate("backup", "create", "--locator", f"{BACKUPS}/repository", "--repository-id", REPOSITORY, "--retention-seconds", "3600")
        self.checksum = result["manifest_checksum"]
        _, verified = self.mutate("backup", "verify", "--repository-id", REPOSITORY, "--snapshot-id", self.snapshot, "--expected-manifest-checksum", self.checksum)
        self.case.assertIn("verification_report", verified)

    def restore(self, expected):
        self.compose("stop")
        restored_project = self.project + "restore"
        # A separate deployment keeps the same container paths but receives fresh
        # data/key volumes. Only the verified repository and protected config are shared.
        override = self.root / "restore.yaml"
        override.write_text(f'''volumes:
  configuration:
    external: true
    name: {self.project}_configuration
  backups:
    external: true
    name: {self.project}_backups
''')
        command = ["compose", "--project-name", restored_project, "--file", str(self.root / "compose.yaml"), "--file", str(self.root / "override.yaml"), "--file", str(override)]
        def restored(*args, **kwargs):
            return self.docker(*command, *args, **kwargs)
        try:
            restored("create", "--pull", "never")
            args = ["backup", "restore", "start", "--output", "json", "--config", CONFIG,
                    "--locator", f"{BACKUPS}/repository", "--repository-id", REPOSITORY,
                    "--snapshot-id", self.snapshot, "--expected-manifest-checksum", self.checksum,
                    "--idempotency-key", str(uuid.uuid4()), "--bundle", f"{BACKUPS}/recovery.age",
                    "--identity-file", f"{EXPORT}/recovery.identity"]
            for flag, key in [("--instance", "instance"), ("--root-key-id", "root_key_id"), ("--root-created-at", "root_created_at"), ("--root-fingerprint", "root_fingerprint"), ("--integrity-public-key", "integrity_public_key"), ("--integrity-fingerprint", "integrity_fingerprint")]:
                args += [flag, self.pin[key]]
            operation = json.loads(self.offline(*args, compose=restored))["operation"]["id"]
            args[2] = "wait"
            deadline = time.monotonic() + 300
            while True:
                result = json.loads(self.offline(*args, "--operation-id", operation, "--wait-seconds", "30", compose=restored))
                if result["operation"]["status"] == "succeeded": break
                self.case.assertIn(result["operation"]["status"], ["pending", "running"])
                if time.monotonic() >= deadline: raise AssertionError("native Restore did not complete")
            restored("up", "--detach", "--wait", "--wait-timeout", "90", "--pull", "never")
            self.case.assertEqual(self.query(restored), expected)
        finally:
            restored("down", "--volumes")
        self.compose("up", "--detach", "--wait", "--wait-timeout", "90", "--pull", "never")
        self.case.assertEqual(self.query(), expected)

    def upgrade(self, expected):
        container = self.compose("ps", "--quiet", "positron").decode().strip()
        # A planned image replacement suspends the Docker restart policy so the
        # source's automatic native Upgrade Drain remains observable.
        self.docker("update", "--restart=no", container)
        status = fields(self.online("repository", "status"))
        accepted = fields(self.online("upgrade", "start", "--candidate-manifest", self.candidate_digest,
            "--repository-id", REPOSITORY, "--retention-seconds", "3600", "--expected-generation", status["catalog_generation"], "--idempotency-key", str(uuid.uuid4())))
        operation = accepted["operation_id"]
        self.case.assertEqual(self.docker("wait", container, timeout=300).strip(), b"0")
        deadline = time.monotonic() + 300
        while True:
            state = fields(self.offline("upgrade", "offline", "advance", "--config", CONFIG, "--operation-id", operation, "--seconds", "30"))
            if state["stage"] == "Some(Publishing)": break
            self.case.assertEqual(state["status"], "Running")
            if time.monotonic() >= deadline: raise AssertionError("native Upgrade snapshot did not finish")
        self.offline("upgrade", "offline", "publish", "--config", CONFIG, "--operation-id", operation)
        fixture = self.root / "fixture/export"
        self.install({"fixtures/export/current.manifest": (fixture / "candidate.manifest").read_bytes(),
                      "fixtures/export/current.inventory.json": (fixture / "inventory.json").read_bytes()})
        deployment = self.root / "compose.yaml"
        original = deployment.read_text()
        before = json.loads(self.docker("inspect", container))[0]
        old_image = before["Config"]["Image"]
        self.case.assertNotEqual(old_image, self.candidate_image)
        deployment.write_text(original.replace(old_image, self.candidate_image))
        self.compose("up", "--detach", "--force-recreate", "--wait", "--wait-timeout", "90", "--pull", "never")
        candidate = self.compose("ps", "--quiet", "positron").decode().strip()
        after = json.loads(self.docker("inspect", candidate))[0]
        self.case.assertEqual(after["Image"], self.candidate_image)
        retained = lambda state: {m["Destination"]: m["Name"] for m in state["Mounts"] if m["Type"] == "volume"}
        self.case.assertEqual(retained(before), retained(after))
        self.case.assertEqual(self.query(), expected)
