"""Public OCI image contract. Requires an actual native archive, never a mock binary."""
import json
import io
import hashlib
import tarfile
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
import unittest


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, capture_output=True, **kwargs).stdout


class ImageContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = os.environ.get("POSITRON_TEST_OCI_IMAGE", "positron-118-test")
        archive = os.environ.get("POSITRON_TEST_OCI_ARCHIVE")
        if archive:
            with tempfile.TemporaryDirectory(prefix="positron-118-") as directory:
                Path(directory, "native.tar.gz").write_bytes(Path(archive).read_bytes())
                Path(directory, "MPL-2.0.txt").write_bytes(Path(__file__).with_name("MPL-2.0.txt").read_bytes())
                docker("buildx", "build", "--load", "--build-arg", "SOURCE_DATE_EPOCH=0", "--file", str(Path(__file__).with_name("Dockerfile")),
                       "--tag", cls.image, directory)

    def test_default_uid_initialization_drain_recovery_and_missing_keys(self):
        self.lifecycle(65532)

    def test_arbitrary_uid_initialization_drain_recovery_and_missing_keys(self):
        self.lifecycle(17293)

    def lifecycle(self, uid):
        suffix = uuid.uuid4().hex[:12]
        name = f"positron-118-{suffix}"
        volumes = {kind: f"{name}-{kind}" for kind in ("data", "secrets", "config", "missing-secrets")}
        for volume in volumes.values():
            docker("volume", "create", volume)
        mounts = []
        for kind, volume in volumes.items():
            if kind == "missing-secrets":
                continue
            destination = {"data": "/var/lib/positron", "secrets": "/var/lib/positron-secrets",
                           "config": "/etc/positron"}[kind]
            mounts += ["--mount", f"type=volume,src={volume},dst={destination},volume-nocopy" + (",readonly" if kind == "config" else "")]
        common = ["--read-only", "--tmpfs",
                  f"/run/positron:rw,nosuid,nodev,noexec,uid={uid},gid={uid},mode=0700", *mounts]
        if uid != 65532:
            common += ["--user", f"{uid}:{uid}", "--env",
                       "POSITRON__LISTENER__CONTROL_PATH=/run/positron/custom.sock"]
        config = 'schema_version = 1\n[runtime]\nshutdown_grace_seconds = 5\n[listener]\n'
        if uid != 65532:
            config += 'control_path = "/run/positron/control.sock"\n'
        for index, listener in enumerate(("operations", "api", "otlp_grpc", "otlp_http", "loki_push")):
            address = "127.0.0.1" if listener == "operations" else "0.0.0.0"
            config += f'{listener}_bind_address = "{address}:{4319 + index}"\n{listener}_transport = "plaintext"\n' 
        config += '[storage]\ndata_directory = "/var/lib/positron"\nsecrets_directory = "/var/lib/positron-secrets"\n[security]\nlocal_key_file = "/var/lib/positron-secrets/local-root-key.v1"\n'
        try:
            # Administrative mount provisioning is outside the application image.
            setup_mounts = []
            for kind, volume in volumes.items():
                setup_mounts += ["--mount", f"type=volume,src={volume},dst=/{kind}"]
            docker("run", "--rm", "-i", *setup_mounts,
                   "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe",
                   "sh", "-eu", "-c", f'cat > /config/positron.toml; chown -R {uid}:{uid} /data /secrets /config /missing-secrets; chmod 700 /data /secrets /config /missing-secrets; chmod 600 /config/positron.toml',
                   input=config.encode())
            def launch():
                docker("run", "--detach", "--name", name, *common, 
                       self.image, "serve", "--init-if-empty", "--config", "/etc/positron/positron.toml")
                state = json.loads(docker("inspect", name))[0]["State"]
                if state["Status"] == "exited":
                    diagnostic = subprocess.run(["docker", "run", "--rm", *common, self.image,
                                                 "doctor", "--offline", "--config", "/etc/positron/positron.toml"], capture_output=True)
                    self.fail(subprocess.run(["docker", "logs", name], capture_output=True).stderr.decode() + diagnostic.stdout.decode() + diagnostic.stderr.decode())
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    # Probe the real Operations Listener from its network namespace.
                    # The helper stays outside the minimal application image.
                    probe = subprocess.run(["docker", "run", "--rm", "--network", f"container:{name}",
                        "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe",
                        "/usr/libexec/platform-python", "-c",
                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4319/health/ready',timeout=1)"],
                        capture_output=True)
                    if probe.returncode == 0:
                        return
                    if json.loads(docker("inspect", name))[0]["State"]["Status"] == "exited":
                        self.fail(subprocess.run(["docker", "logs", name], capture_output=True).stderr.decode())
                    time.sleep(0.1)
                self.fail("container readiness deadline expired")
            launch()
            self.assertNotIn(b"administrator_secret=", docker("logs", name))
            docker("kill", "--signal", "TERM", name)
            self.assertEqual(docker("wait", name).strip(), b"0")
            docker("rm", name)
            claim = docker("run", "--rm", *common, self.image, "bootstrap", "claim",
                           "--config", "/etc/positron/positron.toml")
            self.assertIn(b"administrator_secret=", claim)
            retry = subprocess.run(["docker", "run", "--rm", *common, self.image, "bootstrap", "claim",
                                    "--config", "/etc/positron/positron.toml"], capture_output=True)
            self.assertNotEqual(retry.returncode, 0)
            self.assertEqual(retry.stdout, b"")
            launch()
            docker("kill", "--signal", "KILL", name)
            self.assertEqual(docker("wait", name).strip(), b"137")
            docker("rm", name)
            launch()
            docker("kill", "--signal", "TERM", name)
            self.assertEqual(docker("wait", name).strip(), b"0")
            docker("rm", name)
            # Existing data with a fresh secrets mount must fail closed.
            missing = common.copy()
            secret_mount = f"type=volume,src={volumes['secrets']},dst=/var/lib/positron-secrets,volume-nocopy"
            missing[missing.index(secret_mount)] = f"type=volume,src={volumes['missing-secrets']},dst=/var/lib/positron-secrets,volume-nocopy"
            def retained_data():
                return docker("run", "--rm", *setup_mounts,
                    "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe",
                    "sh", "-c", "find /data -type f -exec sha256sum {} + | sort")
            before = retained_data()
            missing_name = f"{name}-missing"
            docker("run", "--detach", "--name", missing_name, *missing, self.image, "serve",
                   "--init-if-empty", "--config", "/etc/positron/positron.toml")
            # The native recovery process may stay alive for inspection. Its
            # readiness must remain closed; an exit is also an explicit refusal.
            time.sleep(1)
            state = json.loads(docker("inspect", missing_name))[0]["State"]
            if state["Status"] == "running":
                observed = docker("run", "--rm", "--network", f"container:{missing_name}",
                    "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe",
                    "/usr/libexec/platform-python", "-c",
                    "import urllib.request,urllib.error; "
                    "exec(\"try: print(urllib.request.urlopen('http://127.0.0.1:4319/health/ready',timeout=2).status)\\nexcept urllib.error.HTTPError as error: print(error.code)\")")
                self.assertEqual(observed.strip(), b"503")
            else:
                self.assertNotEqual(state["ExitCode"], 0)
            docker("rm", "--force", missing_name)
            self.assertEqual(before, retained_data())
            empty = docker("run", "--rm", *setup_mounts,
                "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe",
                "find", "/missing-secrets", "-mindepth", "1", "-type", "f")
            self.assertEqual(empty, b"")
            launch()
            docker("kill", "--signal", "TERM", name)
            self.assertEqual(docker("wait", name).strip(), b"0")
            docker("rm", name)
        finally:
            subprocess.run(["docker", "rm", "--force", "--volumes", f"{name}-missing"], capture_output=True)
            subprocess.run(["docker", "rm", "--force", "--volumes", name], capture_output=True)
            for volume in volumes.values():
                docker("volume", "rm", volume)

    def test_image_preserves_the_exact_native_binary_and_generated_contract(self):
        archive = os.environ.get("POSITRON_TEST_OCI_ARCHIVE")
        if not archive:
            self.skipTest("requires the exact native archive construction input")
        name = f"positron-118-files-{uuid.uuid4().hex[:12]}"
        docker("create", "--name", name, self.image)
        try:
            exported = docker("export", name)
        finally:
            docker("rm", name)
        with tarfile.open(fileobj=io.BytesIO(exported)) as image, tarfile.open(archive) as native:
            for installed, original in [
                ("usr/bin/positron", "positron/bin/positron"),
                ("usr/share/positron/config.schema.json", "positron/share/config.schema.json"),
                ("usr/share/positron/configuration.md", "positron/share/configuration.md"),
                ("usr/share/positron/positron.toml.example", "positron/etc/positron.toml.example"),
            ]:
                self.assertEqual(image.extractfile(installed).read(), native.extractfile(original).read())
            self.assertEqual(image.extractfile("usr/share/licenses/ca-certificates/MPL-2.0.txt").read(),
                             Path(__file__).with_name("MPL-2.0.txt").read_bytes())
            runtime_licenses = docker("run", "--rm",
                "rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe",
                "tar", "-C", "/", "-cf", "-", "usr/share/licenses/glibc", "usr/share/licenses/libgcc")
            with tarfile.open(fileobj=io.BytesIO(runtime_licenses)) as upstream:
                for license_file in upstream.getmembers():
                    if license_file.isfile():
                        self.assertEqual(image.extractfile(license_file.name).read(),
                                         upstream.extractfile(license_file).read())
            roots = image.extractfile("etc/ssl/certs/ca-certificates.crt").read()
            self.assertEqual(hashlib.sha256(roots).hexdigest(), "796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe")
            names = set(image.getnames())
            for prohibited in ("bin/sh", "bin/bash", "usr/bin/python3", "usr/bin/dnf", "usr/bin/apt"):
                self.assertNotIn(prohibited, names)

    def test_image_is_the_single_binary_with_explicit_runtime_contract(self):
        image = json.loads(docker("image", "inspect", self.image))[0]
        config = image["Config"]
        self.assertEqual(config["Entrypoint"], ["/usr/bin/positron"])
        self.assertEqual(config["Cmd"], ["serve", "--init-if-empty"])
        self.assertEqual(config["User"], "65532:65532")
        self.assertEqual(config["StopSignal"], "SIGTERM")
        self.assertEqual(len(image["RootFS"]["Layers"]), 1)
        output = docker("run", "--rm", "--read-only", "--user", "17293:17293",
                        self.image, "config", "effective", "--redacted")
        self.assertIn(b"/var/lib/positron", output)
        self.assertNotIn(b"administrator_secret=", output)
        result = subprocess.run(["docker", "run", "--rm", "--entrypoint", "/bin/sh", self.image],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
