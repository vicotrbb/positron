"""Actual Compose lifecycle integration; uses the same native OCI build as CI."""
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from data_lifecycle import ADMIN_IMAGE, DataLifecycle
from tls_fixture import material


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, capture_output=True, **kwargs).stdout


class ComposeContract(unittest.TestCase):
    def test_installed_recovery_identity_has_protected_parent_and_file(self):
        project = "positron119permissions" + uuid.uuid4().hex[:10]
        volume = project + "_configuration"
        lifecycle = DataLifecycle.__new__(DataLifecycle)
        lifecycle.project, lifecycle.docker = project, docker
        try:
            lifecycle.install({"fixtures/export/recovery.identity": b"private-fixture"})
            metadata = docker("run", "--rm", "-v", f"{volume}:/config:ro", ADMIN_IMAGE,
                              "stat", "-c", "%u:%g:%a", "/config/fixtures", "/config/fixtures/export", "/config/fixtures/export/recovery.identity")
            self.assertEqual(metadata.decode().splitlines(), ["65532:65532:700", "65532:65532:700", "65532:65532:600"])
        finally:
            docker("volume", "rm", volume)

    def test_tls_initialization_claim_health_restart_drain_and_retained_volumes(self):
        image = os.environ["POSITRON_TEST_OCI_IMAGE"]
        identity = json.loads(docker("image", "inspect", image))[0]["Id"]
        project = "positron119" + uuid.uuid4().hex[:10]
        with tempfile.TemporaryDirectory(prefix="positron-compose-") as directory:
            root = Path(directory)
            # A local immutable image ID exercises unpublished bytes without a registry.
            template = Path(__file__).with_name("compose.yaml.in").read_text()
            root.joinpath("compose.yaml").write_text(template.replace("@SOURCE@", "local-test").replace("@STOP_GRACE_SECONDS@", "3605").replace(
                "ghcr.io/vicotrbb/positron@sha256:@INDEX_SHA256@", identity))
            root.joinpath("override.yaml").write_text('''services:
  positron:
    ports: !override ["127.0.0.1::4318"]
    volumes: !override
      - data:/var/lib/positron
      - secrets:/var/lib/positron-secrets
      - configuration:/etc/positron:ro
      - backups:/var/lib/positron-backups
volumes:
  configuration:
''')
            command = ["compose", "--project-name", project, "--file", str(root / "compose.yaml"), "--file", str(root / "override.yaml")]
            def compose(*args, **kwargs):
                return docker(*command, *args, **kwargs)
            compose("create", "--pull", "never")
            container = compose("ps", "--all", "--quiet", "positron").decode().strip()
            try:
                # Extract the actual generated contract, rather than a second config model.
                archived = docker("cp", f"{container}:/usr/share/positron/positron.toml.example", "-")
                with tarfile.open(fileobj=io.BytesIO(archived)) as archive:
                    config = archive.extractfile(archive.getmembers()[0]).read().decode()
                tls = "".join(f'{name}_tls_certificate_file = "/etc/positron/tls/server.pem"\n{name}_tls_private_key_file = "/etc/positron/tls/server-key.pem"\n' for name in ("operations", "api", "otlp_grpc", "otlp_http", "loki_push"))
                config = config.replace("[listener]\n", "[listener]\n" + tls)
                config = config.replace('otlp_http_bind_address = "127.0.0.1:4318"', 'otlp_http_bind_address = "0.0.0.0:4318"')
                root.joinpath("positron.toml").write_text(config)
                material(root)
                payload = io.BytesIO()
                with tarfile.open(fileobj=payload, mode="w") as archive:
                    for source, name, mode in [("positron.toml", "positron.toml", 0o600), ("server-key.pem", "tls/server-key.pem", 0o600), ("server.pem", "tls/server.pem", 0o644), ("ca.pem", "tls/ca.pem", 0o644)]:
                        data = root.joinpath(source).read_bytes()
                        member = tarfile.TarInfo(name)
                        member.size, member.mode, member.uid, member.gid = len(data), mode, 65532, 65532
                        archive.addfile(member, io.BytesIO(data))
                # Provisioning helper is not part of the application or running stack.
                docker("run", "--rm", "-i", "-v", f"{project}_configuration:/config", "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe", "tar", "-xf", "-", "-C", "/config", input=payload.getvalue())
                compose("up", "--detach", "--wait", "--wait-timeout", "90", "--pull", "never")
                state = json.loads(docker("inspect", container))[0]
                self.assertTrue(state["HostConfig"]["ReadonlyRootfs"])
                self.assertEqual(state["Config"]["User"], "65532:65532")
                self.assertEqual(state["HostConfig"]["Memory"], 2 * 1024 ** 3)
                self.assertEqual(state["State"]["Health"]["Status"], "healthy")
                self.assertNotIn(b"administrator_secret=", compose("logs"))
                invalid_tls = subprocess.run(["docker", *command, "exec", "-T", "positron", "/usr/bin/positron", "doctor", "--ready", "--endpoint", "127.0.0.1:13133", "--server-name", "wrong.invalid", "--trust-file", "/etc/positron/tls/ca.pem"], capture_output=True)
                self.assertEqual(invalid_tls.returncode, 3)
                self.assertIn(b"DOCTOR_ONLINE_INSPECTION_UNAVAILABLE", invalid_tls.stdout)

                compose("stop")
                self.assertEqual(json.loads(docker("inspect", container))[0]["State"]["ExitCode"], 0)
                claim = compose("run", "--rm", "--no-deps", "positron", "bootstrap", "claim", "--config", "/etc/positron/positron.toml")
                self.assertIn(b"administrator_secret=", claim)
                repeated = subprocess.run(["docker", *command, "run", "--rm", "--no-deps", "positron", "bootstrap", "claim", "--config", "/etc/positron/positron.toml"], capture_output=True)
                self.assertNotEqual(repeated.returncode, 0)
                self.assertEqual(repeated.stdout, b"")
                lifecycle = DataLifecycle(self, root, project, compose, docker, claim)
                lifecycle.prepare(container, config)
                compose("up", "--detach", "--wait", "--wait-timeout", "90", "--pull", "never")
                lifecycle.ingest()
                expected = lifecycle.query(stage="initial")
                compose("kill", "--signal", "SIGKILL")
                compose("up", "--detach", "--wait", "--wait-timeout", "90", "--pull", "never")
                self.assertEqual(lifecycle.query(stage="restart"), expected)
                lifecycle.backup()
                lifecycle.restore(expected)
                lifecycle.upgrade(expected)
                compose("down")
                for name in ("data", "secrets", "backups"):
                    docker("volume", "inspect", f"{project}_{name}")
                compose("up", "--detach", "--wait", "--wait-timeout", "90", "--pull", "never")
                self.assertEqual(lifecycle.query(stage="reinstall"), expected)
                compose("stop")
                verified = compose("run", "--rm", "--no-deps", "positron", "verify", "--offline", "--config", "/etc/positron/positron.toml")
                self.assertIn(b"verified", verified)
            finally:
                inspected = subprocess.run(["docker", "inspect", container], capture_output=True)
                if inspected.returncode == 0:
                    health = json.loads(inspected.stdout)[0].get("State", {}).get("Health", {})
                    if health.get("Status") == "unhealthy":
                        # The native probe emits closed non-secret Doctor facts.
                        # Never print arbitrary process output or request headers.
                        prefixes = ("report_version=", "mode=", "status=", "finding_code=", "severity=", "evidence_scope=", "safe_command=")
                        probes = [{"exit_code": entry.get("ExitCode"), "output": "\n".join(line for line in entry.get("Output", "").splitlines() if line.startswith(prefixes))[:2048]} for entry in health.get("Log", [])[-3:]]
                        print(json.dumps({"health_status": health.get("Status"), "last_probes": probes}))
                result = subprocess.run(["docker", *command, "logs"], capture_output=True)
                # Logs contain no claim; reveal useful failure context only.
                if b"administrator_secret=" not in result.stdout:
                    print(result.stdout.decode(errors="replace"))
                subprocess.run(["docker", *command, "down", "--volumes"], check=True, capture_output=True)
                if "lifecycle" in locals() and hasattr(lifecycle, "candidate_tag"):
                    docker("image", "rm", lifecycle.candidate_tag)


if __name__ == "__main__":
    unittest.main()
