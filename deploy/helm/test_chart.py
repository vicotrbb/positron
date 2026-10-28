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
        self.assertEqual(preparer["args"], ["bootstrap", "prepare-storage", "--config", "/etc/positron/positron.toml"])
        container, = pod["containers"]
        self.assertEqual(preparer["image"], container["image"])
        for spec in [preparer, container]:
            configuration, = [mount for mount in spec["volumeMounts"] if mount["name"] == "configuration"]
            self.assertEqual(configuration["mountPath"], "/etc/positron/positron.toml")
            self.assertEqual(configuration["subPath"], "positron.toml")
        self.assertTrue(all(mount.get("subPath") for mount in container["volumeMounts"] if mount["name"] == "tls"))
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
                             "--set-json", 'maintenance.args=["verify","--offline","--config","/etc/positron/positron.toml"]')
        self.assertEqual(result.returncode, 0, result.stderr)
        import yaml
        job, = [obj for obj in yaml.safe_load_all(result.stdout) if obj["kind"] == "Job"]
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["template"]["spec"]["restartPolicy"], "Never")
        self.assertEqual(job["spec"]["template"]["spec"]["containers"][0]["args"][0], "verify")


if __name__ == "__main__":
    unittest.main()
