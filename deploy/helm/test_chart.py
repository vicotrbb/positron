"""Integration tests of the generated artifact through the real Helm CLI."""
import os
import http.server
import ssl
import sys
import tempfile
import threading
from pathlib import Path
import subprocess
import unittest


class HelmChart(unittest.TestCase):
    chart = Path(os.environ["POSITRON_TEST_HELM_CHART"]).resolve()

    def render(self, *extra):
        return subprocess.run([
            "helm", "template", "sample", str(self.chart),
            "--set", "storageClass=standard", "--set", "tlsSecret=positron-tls",
            *extra,
        ], capture_output=True, text=True, check=False)

    def test_standalone_restricted_resources_and_native_probes(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        import yaml
        objects = list(yaml.safe_load_all(result.stdout))
        by_kind = {}
        for obj in objects:
            by_kind.setdefault(obj["kind"], []).append(obj)
        self.assertEqual(set(by_kind), {"StatefulSet", "Service", "ConfigMap", "PersistentVolumeClaim"})
        stateful = by_kind["StatefulSet"][0]
        self.assertEqual(stateful["spec"]["replicas"], 1)
        self.assertEqual(stateful["spec"]["updateStrategy"], {"type": "OnDelete"})
        pod = stateful["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        preparer, = pod["initContainers"]
        self.assertEqual(preparer["args"], ["bootstrap", "prepare-storage", "--config", "/etc/positron/config/positron.toml"])
        container, = pod["containers"]
        self.assertEqual(preparer["image"], container["image"])
        for spec in [preparer, container]:
            configuration, = [mount for mount in spec["volumeMounts"] if mount["name"] == "configuration"]
            self.assertEqual(configuration["mountPath"], "/etc/positron/config")
            self.assertNotIn("subPath", configuration)
        tls, = [mount for mount in container["volumeMounts"] if mount["name"] == "tls"]
        self.assertEqual(tls["mountPath"], "/etc/positron/tls")
        self.assertNotIn("subPath", tls)
        self.assertFalse(preparer["securityContext"]["allowPrivilegeEscalation"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertIn("--live", container["startupProbe"]["exec"]["command"])
        self.assertIn("--live", container["livenessProbe"]["exec"]["command"])
        self.assertIn("--ready", container["readinessProbe"]["exec"]["command"])
        self.assertIn("--trust-file", container["readinessProbe"]["exec"]["command"])
        self.assertNotIn("lifecycle", container)  # SIGTERM goes straight to native Drain.
        self.assertEqual(len(by_kind["PersistentVolumeClaim"]), 3)
        for pvc in by_kind["PersistentVolumeClaim"]:
            self.assertEqual(pvc["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")
            self.assertEqual(pvc["spec"]["volumeMode"], "Filesystem")
            self.assertEqual(pvc["spec"]["accessModes"], ["ReadWriteOnce"])
        config = by_kind["ConfigMap"][0]["data"]["positron.toml"]
        import tomllib
        native = tomllib.loads(config)
        self.assertEqual(native["storage"]["data_directory"], "/var/lib/positron/instance")
        self.assertEqual(native["storage"]["secrets_directory"], "/var/lib/positron-secrets/instance")
        self.assertEqual(native["listener"]["api_bind_address"], "0.0.0.0:8080")
        self.assertEqual(native["listener"]["api_tls_private_key_file"], "/etc/positron/tls/server-key.pem")

    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_CURRENT_BINARY"), "requires the built native probe executable")
    def test_native_doctor_rejects_partially_invalid_overlap_trust(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "compose"))
        from tls_fixture import material
        class Operations(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *args): pass
        with tempfile.TemporaryDirectory(prefix="positron-doctor-bundle-") as directory:
            root = Path(directory)
            material(root)
            trust = root / "trust.pem"
            trust.write_bytes((root / "ca.pem").read_bytes() + b"invalid trailing trust material")
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Operations)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / "server.pem", root / "server-key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                command = [os.environ["POSITRON_TEST_HELM_CURRENT_BINARY"], "doctor", "--live", "--endpoint", f"127.0.0.1:{server.server_port}", "--server-name", "localhost", "--trust-file", str(trust)]
                self.assertNotEqual(subprocess.run(command, capture_output=True, timeout=10).returncode, 0)
                trust.write_bytes((root / "ca.pem").read_bytes())
                self.assertEqual(subprocess.run(command, capture_output=True, timeout=10).returncode, 0)
            finally:
                server.shutdown()
                thread.join(timeout=10)
                server.server_close()

    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_CURRENT_BINARY"), "requires the built native executable")
    def test_projected_tls_generation_reloads_in_the_existing_process_and_retains_valid_identity(self):
        import yaml
        import socket
        import time
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "compose"))
        from tls_fixture import material
        binary = os.environ["POSITRON_TEST_HELM_CURRENT_BINARY"]
        objects = list(yaml.safe_load_all(self.render().stdout))
        configuration, = [obj["data"]["positron.toml"] for obj in objects if obj["kind"] == "ConfigMap"]
        with tempfile.TemporaryDirectory(prefix="p120-tls-", dir="/private/tmp" if sys.platform == "darwin" else "/tmp") as directory:
            root = Path(directory)
            first, second, invalid = [root / name for name in ["first", "second", "invalid"]]
            for generation in [first, second]:
                generation.mkdir()
                material(generation)
            overlap = (first / "ca.pem").read_bytes() + b"\n" + (second / "ca.pem").read_bytes()
            for generation in [first, second]: (generation / "ca.pem").write_bytes(overlap)
            invalid.mkdir()
            (invalid / "ca.pem").write_bytes(overlap)
            (invalid / "server.pem").write_bytes((second / "server.pem").read_bytes())
            (invalid / "server-key.pem").write_bytes(b"invalid candidate key")
            projected = root / "tls"
            projected.mkdir()
            (projected / "..data").symlink_to(first)
            for name in ["ca.pem", "server.pem", "server-key.pem"]: (projected / name).symlink_to("..data/" + name)
            bindings = []
            for _ in range(5):
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                bindings.append(listener)
            import re
            endpoints = [listener.getsockname()[1] for listener in bindings]
            for role, port in zip(["operations", "api", "otlp_grpc", "otlp_http", "loki_push"], endpoints):
                configuration = re.sub(rf'{role}_bind_address = "[^"]+"', f'{role}_bind_address = "127.0.0.1:{port}"', configuration)
            for original, replacement in [("/etc/positron/tls", str(projected)), ("/var/lib/positron/instance", str(root / "data")), ("/var/lib/positron-secrets/instance", str(root / "secrets")), ("/var/lib/positron-backups", str(root / "backups")), ("/run/positron/control/control.sock", str(root / "control.sock"))]:
                configuration = configuration.replace(original, replacement)
            config = root / "positron.toml"
            config.write_text(configuration)
            subprocess.run([binary, "bootstrap", "prepare-storage", "--config", str(config)], check=True, capture_output=True, timeout=15)
            for listener in bindings: listener.close()
            process = subprocess.Popen([binary, "serve", "--init-if-empty", "--config", str(config)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                trust = ssl.create_default_context(cafile=str(projected / "..data/ca.pem"))
                def identity():
                    with socket.create_connection(("127.0.0.1", endpoints[0]), timeout=3) as connection:
                        with trust.wrap_socket(connection, server_hostname="localhost") as tls: return tls.getpeercert(binary_form=True)
                def wait_identity(expected):
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        self.assertIsNone(process.poll(), "native process exited during reload")
                        try:
                            observed = identity()
                            if expected is None or observed == expected: return observed
                        except (OSError, ssl.SSLError): pass
                        time.sleep(0.05)
                    self.fail("native listener did not publish expected TLS identity")
                old = wait_identity(None)
                probe = [binary, "doctor", "--ready", "--endpoint", f"127.0.0.1:{endpoints[0]}", "--server-name", "localhost", "--trust-file", str(projected / "..data/ca.pem")]
                deadline = time.monotonic() + 20
                while subprocess.run(probe, capture_output=True, timeout=10).returncode:
                    self.assertLess(time.monotonic(), deadline, "native process did not become ready")
                    time.sleep(0.05)
                claim = subprocess.run([binary, "bootstrap", "claim", "--control-path", str(root / "control.sock")], capture_output=True, check=True, timeout=10)
                administrator = dict(line.split(b"=", 1) for line in claim.stdout.splitlines())[b"administrator_secret"]
                def effective_digest():
                    result = subprocess.run([binary, "doctor", "--online", "--endpoint", f"127.0.0.1:{endpoints[0]}", "--server-name", "localhost", "--trust-file", str(projected / "..data/ca.pem"), "--credential-stdin"], input=administrator + b"\n", capture_output=True, timeout=10)
                    self.assertIn(result.returncode, [0, 3], "native online inspection failed")
                    report = dict(line.split(b"=", 1) for line in result.stdout.splitlines() if b"=" in line)
                    self.assertEqual(report[b"process_phase"], b"serving")
                    self.assertEqual(report[b"configuration_contract"], b"valid")
                    if result.returncode == 3:
                        self.assertEqual(report[b"status"], b"inspection_incomplete")
                        self.assertEqual(report[b"finding_code"], b"DOCTOR_RUNTIME_FACTS_INCOMPLETE")
                        self.assertEqual(report[b"backup_verification_disposition"], b"not_shipped")
                    digest = report[b"effective_configuration_digest"]
                    self.assertRegex(digest.decode(), r"^[a-f0-9]{64}$")
                    return digest
                initial_digest = effective_digest()
                expected = ssl.PEM_cert_to_DER_cert((second / "server.pem").read_text())
                self.assertNotEqual(old, expected)
                def reload(generation):
                    (projected / "..next").symlink_to(generation)
                    (projected / "..next").replace(projected / "..data")
                    result = subprocess.run([binary, "config", "reload", "--control-path", str(root / "control.sock")], capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, b"status=reload_requested\n")
                config.write_text(configuration.replace('log_level = "info"', 'log_level = "debug"'))
                reload(second)
                self.assertEqual(wait_identity(expected), expected)
                live_digest = effective_digest()
                self.assertNotEqual(live_digest, initial_digest)
                config.write_text(configuration.replace('log_level = "info"', 'log_level = "warn"'))
                reload(invalid)
                time.sleep(0.5)
                self.assertEqual(effective_digest(), live_digest)
                for _ in range(3):
                    self.assertEqual(identity(), expected)
                    result = subprocess.run([binary, "doctor", "--ready", "--endpoint", f"127.0.0.1:{endpoints[0]}", "--server-name", "localhost", "--trust-file", str(projected / "..data/ca.pem")], capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                config.write_text("invalid native configuration")
                reload(first)
                time.sleep(0.5)
                self.assertEqual(identity(), expected)
                config.write_text(configuration.replace('log_level = "info"', 'log_level = "warn"'))
                reload(first)
                self.assertEqual(wait_identity(old), old)
                self.assertNotEqual(effective_digest(), live_digest)
                self.assertIsNone(process.poll())
            finally:
                process.terminate()
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_CURRENT_BINARY"), "requires the built native probe executable")
    def test_live_but_not_ready_process_satisfies_startup_and_liveness_without_admitting_traffic(self):
        import yaml
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "compose"))
        from tls_fixture import material
        rendered = self.render()
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        workload, = [obj for obj in yaml.safe_load_all(rendered.stdout) if obj["kind"] == "StatefulSet"]
        container, = workload["spec"]["template"]["spec"]["containers"]
        class Operations(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == "/health/live" else 503)
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *args): pass
        with tempfile.TemporaryDirectory(prefix="positron-helm-probes-") as directory:
            root = Path(directory)
            material(root)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Operations)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / "server.pem", root / "server-key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for _ in range(3):
                    for probe, expected in [("startupProbe", True), ("livenessProbe", True), ("readinessProbe", False)]:
                        arguments = list(container[probe]["exec"]["command"])
                        arguments[0] = os.environ["POSITRON_TEST_HELM_CURRENT_BINARY"]
                        arguments[arguments.index("--endpoint") + 1] = "127.0.0.1:" + str(server.server_port)
                        arguments[arguments.index("--trust-file") + 1] = str(root / "ca.pem")
                        result = subprocess.run(arguments, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode == 0, expected, probe)
            finally:
                server.shutdown()
                thread.join(timeout=10)
                server.server_close()

    def test_refuses_unsafe_or_unknown_values(self):
        for value in ["replicas=2", "replicas=-1", "image=positron:latest", "storageClass=", "tlsSecret=",
                      "identity.uid=0", "terminationGracePeriodSeconds=30", "configuration=",
                      "storage.data=0Gi", "unknown=value", "maintenance.enabled=true"]:
            with self.subTest(value=value):
                self.assertNotEqual(self.render("--set", value).returncode, 0)

    def test_fresh_restore_uses_distinct_data_keys_and_only_explicit_existing_inputs(self):
        result = self.render("--set", "replicas=0", "--set", "backupClaim=verified-source-backups",
                             "--set", "operationInputsClaim=private-native-inputs")
        self.assertEqual(result.returncode, 0, result.stderr)
        import yaml
        objects = list(yaml.safe_load_all(result.stdout))
        claims = [obj["metadata"]["name"] for obj in objects if obj["kind"] == "PersistentVolumeClaim"]
        self.assertEqual(sorted(claims), ["sample-positron-data", "sample-positron-secrets"])
        stateful, = [obj for obj in objects if obj["kind"] == "StatefulSet"]
        pod = stateful["spec"]["template"]["spec"]
        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        self.assertEqual(volumes["backups"]["persistentVolumeClaim"]["claimName"], "verified-source-backups")
        self.assertEqual(volumes["operation-inputs"]["persistentVolumeClaim"]["claimName"], "private-native-inputs")
        mounted = {volume["name"]: volume for volume in pod["containers"][0]["volumeMounts"]}
        self.assertTrue(mounted["operation-inputs"]["readOnly"])

    def test_existing_inputs_cannot_alias_this_instances_data_key_or_repository_claims(self):
        for value in ["backupClaim=sample-positron-data", "backupClaim=sample-positron-secrets",
                      "operationInputsClaim=sample-positron-data", "operationInputsClaim=sample-positron-secrets",
                      "operationInputsClaim=sample-positron-backups"]:
            with self.subTest(value=value):
                self.assertNotEqual(self.render("--set", value).returncode, 0)

    def test_job_cannot_capture_bootstrap_credentials_or_start_a_second_server(self):
        for arguments in [['bootstrap', 'claim'], ['serve', '--init-if-empty']]:
            result = self.render("--set", "replicas=0", "--set", "maintenance.enabled=true",
                                 "--set-json", "maintenance.args=" + __import__('json').dumps(arguments))
            self.assertNotEqual(result.returncode, 0)

    def test_offline_job_requires_zero_replicas_and_explicit_native_arguments(self):
        result = self.render("--set", "replicas=0", "--set", "maintenance.enabled=true",
                             "--set-json", 'maintenance.args=["verify","--offline","--config","/etc/positron/config/positron.toml"]')
        self.assertEqual(result.returncode, 0, result.stderr)
        import yaml
        job, = [obj for obj in yaml.safe_load_all(result.stdout) if obj["kind"] == "Job"]
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["template"]["spec"]["restartPolicy"], "Never")
        self.assertEqual(job["spec"]["template"]["spec"]["containers"][0]["args"][0], "verify")


if __name__ == "__main__":
    unittest.main()
