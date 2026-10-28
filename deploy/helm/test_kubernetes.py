"""Public lifecycle integration against an explicitly selected owned kind or k3d target."""
import base64
import json
import select
import socket
import ssl
import os
import re
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


def wait_operand(lifecycle, *, previous_uid=None, pending=False, timeout=180):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise AssertionError("operand transition did not complete within its readiness budget")
        result = lifecycle.kube("get", "pod", lifecycle.pod, "-o", "json", "--request-timeout=3s", timeout=min(5, remaining), check=False)
        if not result.returncode:
            state = json.loads(result.stdout)
            changed = previous_uid is None or state["metadata"]["uid"] != previous_uid
            conditions = state.get("status", {}).get("conditions", [])
            ready = any(item["type"] == "Ready" and item["status"] == "True" for item in conditions)
            unscheduled = any(item["type"] == "PodScheduled" and item["status"] == "False" and item.get("reason") == "Unschedulable" for item in conditions)
            if changed and (unscheduled if pending else ready): return state
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def drain_operand(case, lifecycle, state, image, ca, expected):
    worker = state["spec"]["nodeName"]
    selector = "positron-interruption=" + state["metadata"]["namespace"]
    lifecycle.kube("label", "pod", lifecycle.pod, selector)
    pending = None
    try:
        lifecycle.kube("drain", worker, "--ignore-daemonsets", "--delete-emptydir-data", "--pod-selector=" + selector, "--timeout=90s", timeout=100)
        pending = wait_operand(lifecycle, previous_uid=state["metadata"]["uid"], pending=True)
        case.assertEqual(pending["status"]["phase"], "Pending")
        case.assertFalse(pending["spec"].get("nodeName"))
        case.assertFalse(pending["status"].get("podIP"))
        slices = json.loads(lifecycle.kube("get", "endpointslices", "-l", "kubernetes.io/service-name=native-positron", "-o", "json").stdout)
        case.assertFalse(any(endpoint.get("conditions", {}).get("ready") for item in slices["items"] for endpoint in (item.get("endpoints") or [])))
        with case.assertRaises((subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            lifecycle.query_on_node(worker, state["status"]["podIP"], image, ca, stage="wire")
    finally:
        lifecycle.kube("uncordon", worker)
        recovered = wait_operand(lifecycle)
        case.assertEqual(recovered["spec"]["nodeName"], worker)
    case.assertEqual(recovered["metadata"]["uid"], pending["metadata"]["uid"])
    case.assertNotEqual(recovered["metadata"]["uid"], state["metadata"]["uid"])
    case.assertEqual(lifecycle.query_on_node(worker, recovered["status"]["podIP"], image, ca, stage="wire"), expected)
    return recovered


def evict_operand(case, lifecycle, state):
    namespace, uid = state["metadata"]["namespace"], state["metadata"]["uid"]
    eviction = {"apiVersion": "policy/v1", "kind": "Eviction", "metadata": {"name": lifecycle.pod, "namespace": namespace},
                "deleteOptions": {"preconditions": {"uid": uid}}}
    lifecycle.kube("create", "--raw", f"/api/v1/namespaces/{namespace}/pods/{lifecycle.pod}/eviction", "-f", "-", data=json.dumps(eviction).encode())
    replacement = wait_operand(lifecycle, previous_uid=uid)
    case.assertNotEqual(replacement["metadata"]["uid"], uid)
    return replacement


def api_outage(case, lifecycle, control_plane, state, image, ca, expected):
    if not re.fullmatch(r"positron-120-[a-z0-9]+(?:-[a-z0-9]+)*-control-plane", control_plane):
        raise ValueError("explicit owned kind control plane required")
    docker = ["docker", "exec", control_plane]
    containers = json.loads(command([*docker, "crictl", "ps", "--name", "kube-apiserver", "-o", "json"]).stdout)["containers"]
    case.assertEqual(len(containers), 1)
    pid = json.loads(command([*docker, "crictl", "inspect", containers[0]["id"]]).stdout)["info"]["pid"]
    case.assertIs(type(pid), int)
    case.assertGreater(pid, 1)
    case.assertEqual(command([*docker, "cat", f"/proc/{pid}/comm"]).stdout, b"kube-apiserver\n")
    try:
        command([*docker, "kill", "-STOP", str(pid)], timeout=5)
        unavailable = lifecycle.kube("get", "pod", lifecycle.pod, "--request-timeout=3s", timeout=5, check=False)
        case.assertNotEqual(unavailable.returncode, 0, "the API request must actually fail")
        case.assertEqual(lifecycle.query_on_node(state["spec"]["nodeName"], state["status"]["podIP"], image, ca, stage="wire"), expected)
    finally:
        # Resume only this verified API process, even when the query or STOP acknowledgement fails.
        command([*docker, "kill", "-CONT", str(pid)], timeout=5)
        recovered = wait_operand(lifecycle)
        case.assertEqual(recovered["metadata"]["uid"], state["metadata"]["uid"])


def storage_identities(lifecycle, *, worker=None):
    claims = json.loads(lifecycle.kube("get", "pvc", "-o", "json").stdout)["items"]
    identities = {}
    for claim in claims:
        volume = json.loads(lifecycle.kube("get", "pv", claim["spec"]["volumeName"], "-o", "json").stdout)
        if worker:
            terms = volume["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"]
            lifecycle.case.assertTrue(terms)
            for term in terms:
                lifecycle.case.assertTrue(any(expression["key"] == "kubernetes.io/hostname" and expression["operator"] == "In" and expression["values"] == [worker] for expression in term.get("matchExpressions", [])))
        lifecycle.case.assertEqual(volume["spec"]["claimRef"]["uid"], claim["metadata"]["uid"])
        identities[claim["metadata"]["name"]] = [claim["metadata"]["uid"], volume["metadata"]["name"], volume["metadata"]["uid"]]
    return identities


def exercise_interruptions(case, lifecycle, control_plane, image, ca, expected):
    state = wait_operand(lifecycle)
    worker = state["spec"]["nodeName"]
    nodes = json.loads(lifecycle.kube("get", "nodes", "-o", "json").stdout)["items"]
    case.assertEqual({node["metadata"]["name"] for node in nodes}, {control_plane, worker})
    case.assertNotEqual(control_plane, worker)
    for node in nodes:
        taints = node["spec"].get("taints", [])
        case.assertEqual(any(taint["effect"] == "NoSchedule" for taint in taints), node["metadata"]["name"] == control_plane)
        case.assertFalse(node["spec"].get("unschedulable", False))
    retained = storage_identities(lifecycle, worker=worker)
    original_image = state["spec"]["containers"][0]["image"]
    def verify(stage, observed):
        case.assertEqual(storage_identities(lifecycle), retained)
        case.assertEqual(observed["spec"]["containers"][0]["image"], original_image)
        case.assertEqual(lifecycle.query_on_node(observed["spec"]["nodeName"], observed["status"]["podIP"], image, ca, stage="wire"), expected)
        print(json.dumps({"interruption": stage, "namespace": observed["metadata"]["namespace"], "pod_uid": observed["metadata"]["uid"],
                          "node": observed["spec"]["nodeName"], "image": original_image, "result_digest": expected, "storage": retained}), flush=True)
    verify("healthy", state)
    api_outage(case, lifecycle, control_plane, state, image, ca, expected)
    verify("api_recovered", wait_operand(lifecycle))
    state = evict_operand(case, lifecycle, state)
    verify("eviction_recovered", state)
    state = drain_operand(case, lifecycle, state, image, ca, expected)
    verify("local_path_drain_recovered", state)


def owned_storage_class(context, storage_class, expected_context):
    if not expected_context or context != expected_context:
        raise ValueError("context must match the explicitly owned cluster creation")
    if not re.fullmatch(r"(?:kind|k3d)-positron-120-[a-z0-9]+(?:-[a-z0-9]+)*", context):
        raise ValueError("dedicated isolated kind or k3d context required")
    if not storage_class or storage_class != storage_class.strip():
        raise ValueError("explicit storage class required")
    return storage_class


def inspect_private_modes(case, kube, apply, workload):
    from data_lifecycle import ADMIN_IMAGE
    state = json.loads(kube("get", "statefulset", workload, "-o", "json").stdout)
    case.assertEqual(state["spec"]["replicas"], 0, "stop the live owner before private inspection")
    release = workload.removesuffix("-positron")
    pods = json.loads(kube("get", "pods", "-l", "app.kubernetes.io/instance=" + release, "-o", "json").stdout)
    case.assertEqual(pods["items"], [], "no live PVC owner may overlap private inspection")
    name = "native-private-inspection"
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                            "fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "inspect", "image": ADMIN_IMAGE,
            "command": ["stat", "-c", "%u:%g:%a:%i", "/data/instance", "/secrets/instance", "/secrets/instance/local-root-key.v1"],
            "securityContext": security, "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "50m", "memory": "64Mi"}},
            "volumeMounts": [{"name": "data", "mountPath": "/data", "readOnly": True}, {"name": "secrets", "mountPath": "/secrets", "readOnly": True}]}],
        "volumes": [{"name": suffix, "persistentVolumeClaim": {"claimName": workload + "-" + suffix, "readOnly": True}} for suffix in ["data", "secrets"]]}}
    apply(pod)
    try:
        kube("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/" + name, "--timeout=180s", timeout=190)
        status = json.loads(kube("get", "pod", name, "-o", "json").stdout)
        case.assertEqual(status["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"], 0)
        rows = kube("logs", name).stdout.decode().splitlines()
        case.assertEqual(len(rows), 3)
        metadata = [tuple(int(field) for field in row.split(":")) for row in rows]
        for observed, mode in zip(metadata, [700, 700, 600]):
            case.assertEqual(len(observed), 4)
            case.assertEqual(observed[:3], (65532, 65532, mode))
            case.assertGreater(observed[3], 0)
        return metadata
    finally:
        kube("delete", "pod", name, "--wait=true", "--timeout=90s", timeout=100)
        kube("wait", "--for=delete", "pod/" + name, "--timeout=90s", timeout=100)


def listener_rejection_count(kube, pod, timeout=10):
    output = kube("logs", pod, "--tail=200", "--limit-bytes=32768", timeout=timeout).stdout
    count = 0
    for line in output.splitlines():
        try: record = json.loads(line)
        except (ValueError, UnicodeDecodeError): continue
        if isinstance(record, dict) and record.get("event") == "configuration_reload_rejected" and record.get("category") == "listener_unavailable": count += 1
    return count


def reload_projected_identity(kube, pod, identity, expected, timeout=180, rejection_baseline=None):
    deadline = time.monotonic() + timeout
    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0: raise AssertionError("native TLS generation did not establish the expected public outcome")
        return budget
    while True:
        result = kube("exec", pod, "--", "/usr/bin/positron", "config", "reload", "--control-path", "/run/positron/control/control.sock", timeout=min(10, remaining()))
        if result.stdout != b"status=reload_requested\n": raise AssertionError("native reload was not acknowledged")
        try: observed = identity(remaining())
        except OSError: observed = None
        if observed == expected and (rejection_baseline is None or listener_rejection_count(kube, pod, timeout=min(10, remaining())) > rejection_baseline): return
        time.sleep(min(1, remaining()))


def assert_retained_claims(case, before, after, extra_names=()):
    case.assertEqual(set(after), set(before) | set(extra_names))
    for name, identity in before.items():
        case.assertEqual(after[name], identity)
    case.assertEqual(len(set(after.values())), len(after))


class KubernetesLifecycle(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_INTERRUPTION_CONTROL_PLANE"), "requires an explicitly owned two-node kind topology")
    def test_native_api_outage_eviction_and_local_path_drain(self):
        self.exercise_native(True, False, include_interruptions=True)

    def test_native_tls_initialization_restart_drain_and_retained_private_mounts(self):
        self.exercise_native(False, False)

    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_FIXTURE_HELPER"), "requires the existing native signed-input helper")
    def test_native_data_keys_backup_and_verified_fresh_restore(self):
        self.exercise_native(True, False)

    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_CANDIDATE_IMAGE"), "requires an independently compiled native candidate image")
    def test_native_upgrade_preserves_verified_data_and_drain(self):
        self.exercise_native(True, True)

    def exercise_native(self, include_data, include_upgrade, include_interruptions=False):
        kubeconfig = Path(os.environ["POSITRON_TEST_KUBECONFIG"]).resolve(strict=True)
        chart = Path(os.environ["POSITRON_TEST_HELM_CHART"]).resolve(strict=True)
        image = os.environ["POSITRON_TEST_HELM_IMAGE"]
        context = command(["kubectl", "--kubeconfig", str(kubeconfig), "config", "current-context"]).stdout.decode().strip()
        storage_class = owned_storage_class(context, os.environ.get("POSITRON_TEST_HELM_STORAGE_CLASS", "standard"), os.environ.get("POSITRON_TEST_HELM_CONTEXT", ""))
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
            scale(0)
            observed = inspect_private_modes(self, kube, apply, workload)
            scale(1)
            return observed
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
                values = {"image": image, "storageClass": storage_class, "tlsSecret": "positron-tls"}
                values_file = root / "values.json"
                values_file.write_text(json.dumps(values))
                command([*helm, "install", release, str(chart), "-f", str(values_file)])
                installed = True
                ready()
                private_before_restart = private_modes()
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
                    if include_interruptions:
                        control_plane = os.environ["POSITRON_TEST_HELM_INTERRUPTION_CONTROL_PLANE"]
                        self.assertEqual(control_plane, context.removeprefix("kind-") + "-control-plane")
                        exercise_interruptions(self, lifecycle, control_plane, image.split("@", 1)[1], root / "ca.pem", expected)
                # Restart reattaches the same PVCs under fsGroup OnRootMismatch.
                claims = json.loads(kube("get", "pvc", "-o", "json").stdout)["items"]
                retained = {item["metadata"]["name"]: item["metadata"]["uid"] for item in claims}
                kube("delete", "pod", pod, "--wait=true", "--timeout=180s", timeout=190)
                ready()
                self.assertEqual(retained, {item["metadata"]["name"]: item["metadata"]["uid"] for item in json.loads(kube("get", "pvc", "-o", "json").stdout)["items"]})
                self.assertEqual(private_modes(), private_before_restart)
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
                forward = subprocess.Popen([*kubectl, "port-forward", "pod/" + pod, "0:13133", "--address", "127.0.0.1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    self.assertTrue(select.select([forward.stdout], [], [], 15)[0], "TLS port-forward did not bind")
                    port = int(forward.stdout.readline().decode().split("127.0.0.1:", 1)[1].split(" ", 1)[0])
                    trust = ssl.create_default_context(cafile=str(root / "ca.pem"))
                    def active_identity(timeout=5):
                        deadline = time.monotonic() + timeout
                        with socket.create_connection(("127.0.0.1", port), timeout=min(5, timeout)) as connection:
                            budget = deadline - time.monotonic()
                            if budget <= 0: raise TimeoutError("TLS observation deadline expired")
                            connection.settimeout(min(5, budget))
                            with trust.wrap_socket(connection, server_hostname="localhost") as tls:
                                return tls.getpeercert(binary_form=True)
                    prior_identity = active_identity()
                    new_identity = ssl.PEM_cert_to_DER_cert((root / "server.pem").read_text())
                    self.assertNotEqual(prior_identity, new_identity)
                    def publish_and_reload(expected, rejected=False):
                        baseline = listener_rejection_count(kube, pod) if rejected else None
                        apply(tls_secret())
                        reload_projected_identity(kube, pod, active_identity, expected, rejection_baseline=baseline)
                    publish_and_reload(new_identity)
                    (root / "server-key.pem").write_bytes(b"invalid candidate key")
                    publish_and_reload(new_identity, rejected=True)
                    probe[probe.index("wrong.invalid")] = "localhost"
                    for _ in range(3):
                        self.assertEqual(active_identity(), new_identity)
                        self.assertEqual(kube("exec", pod, "--", "/usr/bin/positron", *probe).stdout, b"status=live\n")
                    overlap = (root / "ca.pem").read_bytes()
                    material(root)
                    (root / "ca.pem").write_bytes(overlap + b"\n" + (root / "ca.pem").read_bytes())
                    trust.load_verify_locations(cafile=str(root / "ca.pem"))
                    repaired_identity = ssl.PEM_cert_to_DER_cert((root / "server.pem").read_text())
                    self.assertNotEqual(repaired_identity, new_identity)
                    publish_and_reload(repaired_identity)
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
