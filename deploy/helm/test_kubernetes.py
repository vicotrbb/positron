"""Public lifecycle integration against one explicitly selected isolated kind target."""
import base64
import json
import hashlib
import select
import socket
import ssl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "compose"))
from tls_fixture import material


def command(arguments, *, data=None, timeout=60, check=True):
    result = subprocess.run(arguments, input=data, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{arguments[0]} failed ({result.returncode}): {result.stderr.decode(errors='replace')[:2048]}")
    return result


def assert_retained_claims(case, before, after, extra_names=()):
    case.assertEqual(set(after), set(before) | set(extra_names))
    for name, identity in before.items():
        case.assertEqual(after[name], identity)
    case.assertEqual(len(set(after.values())), len(after))


class KubernetesLifecycle(unittest.TestCase):
    def test_native_tls_initialization_restart_drain_and_retained_private_mounts(self):
        self.exercise_native(False, False)

    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_FIXTURE_HELPER"), "requires the existing native signed-input helper")
    def test_native_data_keys_backup_and_verified_fresh_restore(self):
        self.exercise_native(True, False)

    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_CANDIDATE_IMAGE"), "requires an independently compiled native candidate image")
    def test_native_upgrade_preserves_verified_data_and_drain(self):
        self.exercise_native(True, True)

    def exercise_native(self, include_data, include_upgrade):
        kubeconfig = Path(os.environ["POSITRON_TEST_KUBECONFIG"]).resolve(strict=True)
        chart = Path(os.environ["POSITRON_TEST_HELM_CHART"]).resolve(strict=True)
        image = os.environ["POSITRON_TEST_HELM_IMAGE"]
        context = command(["kubectl", "--kubeconfig", str(kubeconfig), "config", "current-context"]).stdout.decode().strip()
        self.assertTrue(context.startswith("kind-positron-120-"), "dedicated isolated kind context required")
        namespace = "positron120-" + uuid.uuid4().hex[:10]
        release = "native"
        workload = release + "-positron"
        pod = workload + "-0"
        kubectl = ["kubectl", "--kubeconfig", str(kubeconfig), "--namespace", namespace]
        helm = ["helm", "--kubeconfig", str(kubeconfig), "--namespace", namespace]
        def kube(*args, data=None, **kwargs):
            return command([*kubectl, *args], data=data, **kwargs)
        def apply(value):
            return kube("apply", "-f", "-", data=json.dumps(value).encode())
        def ready():
            deadline = time.monotonic() + 180
            while kube("get", "pod", pod, check=False).returncode:
                if time.monotonic() >= deadline:
                    raise AssertionError("StatefulSet did not create its pod")
                time.sleep(0.2)
            kube("wait", "--for=condition=Ready", f"pod/{pod}", "--timeout=180s", timeout=190)
        def private_modes():
            current = json.loads(kube("get", "pod", pod, "-o", "json").stdout)
            node = current["spec"]["nodeName"]
            self.assertTrue(node.startswith("positron-120-"))
            for suffix in ["data", "secrets"]:
                claim = json.loads(kube("get", "pvc", workload + "-" + suffix, "-o", "json").stdout)
                volume = json.loads(kube("get", "pv", claim["spec"]["volumeName"], "-o", "json").stdout)
                path = volume["spec"]["hostPath"]["path"] + "/instance"
                metadata = command(["docker", "exec", node, "stat", "-c", "%u:%a", path]).stdout
                self.assertEqual(metadata.strip(), b"65532:700")
                if suffix == "secrets":
                    key = command(["docker", "exec", node, "stat", "-c", "%u:%a", path + "/local-root-key.v1"]).stdout
                    self.assertEqual(key.strip(), b"65532:600")
        def scale(replicas):
            kube("scale", f"statefulset/{workload}", f"--replicas={replicas}")
            if replicas:
                ready()
            else:
                kube("wait", "--for=delete", f"pod/{pod}", "--timeout=180s", timeout=190)
        namespace_object = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
            "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "v1.35"}}}
        apply(namespace_object)
        installed = False
        completed = False
        try:
            with tempfile.TemporaryDirectory(prefix="positron-helm-tls-") as directory:
                root = Path(directory)
                material(root)
                def tls_secret():
                    return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "positron-tls"},
                            "type": "Opaque", "data": {name: base64.b64encode((root / name).read_bytes()).decode()
                            for name in ["server.pem", "server-key.pem", "ca.pem"]}}
                apply(tls_secret())
                values = {"image": image, "storageClass": "standard", "tlsSecret": "positron-tls"}
                values_file = root / "values.json"
                values_file.write_text(json.dumps(values))
                command([*helm, "install", release, str(chart), "-f", str(values_file)])
                installed = True
                ready()
                private_modes()
                state = json.loads(kube("get", "pod", pod, "-o", "json").stdout)
                self.assertEqual(state["status"]["initContainerStatuses"][0]["state"]["terminated"]["exitCode"], 0)
                self.assertTrue(state["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"])
                probe = ["doctor", "--ready", "--endpoint", "127.0.0.1:13133", "--server-name", "localhost", "--trust-file", "/etc/positron/tls/..data/ca.pem"]
                self.assertEqual(kube("exec", pod, "--", "/usr/bin/positron", *probe).stdout, b"status=ready\n")
                probe[1] = "--live"
                self.assertEqual(kube("exec", pod, "--", "/usr/bin/positron", *probe).stdout, b"status=live\n")
                probe[probe.index("localhost")] = "wrong.invalid"
                self.assertNotEqual(kube("exec", pod, "--", "/usr/bin/positron", *probe, check=False).returncode, 0)
                for container in ["prepare-storage", "positron"]:
                    self.assertNotIn(b"administrator_secret=", kube("logs", pod, "-c", container).stdout)
                # Exec stdout is returned to the caller, never the main container log.
                claim = kube("exec", pod, "--", "/usr/bin/positron", "bootstrap", "claim", "--control-path", "/run/positron/control/control.sock").stdout
                self.assertTrue(claim.startswith(b"administrator_secret=pos_"))
                repeated = kube("exec", pod, "--", "/usr/bin/positron", "bootstrap", "claim", "--control-path", "/run/positron/control/control.sock", check=False)
                self.assertNotEqual(repeated.returncode, 0)
                self.assertEqual(repeated.stdout, b"")
                for container in ["prepare-storage", "positron"]:
                    self.assertNotIn(b"administrator_secret=", kube("logs", pod, "-c", container).stdout)
                lifecycle = None
                if include_data:
                    from native_lifecycle import NativeLifecycle
                    configuration = json.loads(kube("get", "configmap", workload, "-o", "json").stdout)["data"]["positron.toml"]
                    lifecycle = NativeLifecycle(self, root, kube, apply, scale, pod, helm, chart, values, claim)
                    lifecycle.prepare(configuration)
                    lifecycle.ingest()
                    expected = lifecycle.query(stage="initial")
                # Restart reattaches the same PVCs under fsGroup OnRootMismatch.
                claims = json.loads(kube("get", "pvc", "-o", "json").stdout)["items"]
                retained = {item["metadata"]["name"]: item["metadata"]["uid"] for item in claims}
                kube("delete", "pod", pod, "--wait=true", "--timeout=180s", timeout=190)
                ready()
                self.assertEqual(retained, {item["metadata"]["name"]: item["metadata"]["uid"] for item in json.loads(kube("get", "pvc", "-o", "json").stdout)["items"]})
                private_modes()
                if lifecycle:
                    self.assertEqual(lifecycle.query(stage="restart"), expected)
                    lifecycle.backup()
                    print("native_backup_verified=true", flush=True)
                    lifecycle.restore(expected)
                    print("native_fresh_restore_query_verified=true", flush=True)
                    if include_upgrade:
                        lifecycle.upgrade(expected)
                # Whole Secret projections rotate through the native owner, without Pod replacement.
                prior_state = json.loads(kube("get", "pod", pod, "-o", "json").stdout)
                old_ca = (root / "ca.pem").read_bytes()
                material(root)
                (root / "ca.pem").write_bytes(old_ca + b"\n" + (root / "ca.pem").read_bytes())
                valid_key = (root / "server-key.pem").read_bytes()
                forward = subprocess.Popen([*kubectl, "port-forward", "pod/" + pod, "0:13133", "--address", "127.0.0.1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([forward.stdout], [], [], 15)[0], "TLS port-forward did not bind")
                    port = int(forward.stdout.readline().decode().split("127.0.0.1:", 1)[1].split(" ", 1)[0])
                    trust = ssl.create_default_context(cafile=str(root / "ca.pem"))
                    def active_identity():
                        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                            with trust.wrap_socket(connection, server_hostname="localhost") as tls:
                                return tls.getpeercert(binary_form=True)
                    prior_identity = active_identity()
                    new_identity = ssl.PEM_cert_to_DER_cert((root / "server.pem").read_text())
                    self.assertNotEqual(prior_identity, new_identity)
                    def publish_and_reload():
                        apply(tls_secret())
                        node = prior_state["spec"]["nodeName"]
                        projected_key = "/var/lib/kubelet/pods/" + prior_state["metadata"]["uid"] + "/volumes/kubernetes.io~secret/tls/server-key.pem"
                        expected_hash = hashlib.sha256((root / "server-key.pem").read_bytes()).hexdigest()
                        deadline = time.monotonic() + 180
                        while True:
                            observed = command(["docker", "exec", node, "sha256sum", projected_key], check=False).stdout.decode().split()
                            if observed and observed[0] == expected_hash: break
                            self.assertLess(time.monotonic(), deadline, "Secret generation did not project")
                            time.sleep(0.2)
                        result = kube("exec", pod, "--", "/usr/bin/positron", "config", "reload", "--control-path", "/run/positron/control/control.sock")
                        self.assertEqual(result.stdout, b"status=reload_requested\n")
                    publish_and_reload()
                    deadline = time.monotonic() + 30
                    while active_identity() != new_identity:
                        self.assertLess(time.monotonic(), deadline, "native TLS reload did not publish new identity")
                        time.sleep(0.1)
                    (root / "server-key.pem").write_bytes(b"invalid candidate key")
                    publish_and_reload()
                    time.sleep(0.5)
                    probe[probe.index("wrong.invalid")] = "localhost"
                    for _ in range(3):
                        self.assertEqual(active_identity(), new_identity)
                        self.assertEqual(kube("exec", pod, "--", "/usr/bin/positron", *probe).stdout, b"status=live\n")
                    (root / "server-key.pem").write_bytes(valid_key)
                    publish_and_reload()
                    ready()
                    after_rotation = json.loads(kube("get", "pod", pod, "-o", "json").stdout)
                    self.assertEqual(after_rotation["metadata"]["uid"], prior_state["metadata"]["uid"])
                    self.assertEqual(after_rotation["status"]["containerStatuses"][0]["restartCount"], prior_state["status"]["containerStatuses"][0]["restartCount"])
                finally:
                    forward.terminate()
                    try: forward.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        forward.kill()
                        forward.wait(timeout=5)
                    forward.stdout.close()
                    forward.stderr.close()
                scale(0)
                command([*helm, "uninstall", release])
                installed = False
                after = json.loads(kube("get", "pvc", "-o", "json").stdout)["items"]
                assert_retained_claims(self, retained, {item["metadata"]["name"]: item["metadata"]["uid"] for item in after}, ["restored-positron-data", "restored-positron-secrets"] if include_data else [])
                completed = True
        finally:
            if "lifecycle" in locals() and lifecycle:
                if not completed: lifecycle.diagnostics()
                lifecycle.close()
            if completed:
                if installed:
                    command([*helm, "uninstall", release], check=False)
                kube("delete", "namespace", namespace, "--wait=false", check=False)
            else:
                # Retain the isolated runtime/PVC state; never dump credentials or payloads.
                print("retained_failed_namespace=" + namespace, flush=True)


if __name__ == "__main__":
    unittest.main()
