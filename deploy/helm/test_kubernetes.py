"""Public lifecycle integration against an explicitly selected owned kind or k3d target."""
import base64
import copy
import http.client
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
import yaml

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
    exercise_duplicate_writer(case, lifecycle, state, expected)
    api_outage(case, lifecycle, control_plane, state, image, ca, expected)
    verify("api_recovered", wait_operand(lifecycle))
    state = evict_operand(case, lifecycle, state)
    verify("eviction_recovered", state)
    state = drain_operand(case, lifecycle, state, image, ca, expected)
    verify("local_path_drain_recovered", state)


def duplicate_writer_pod(state):
    spec = copy.deepcopy(state["spec"])
    spec.pop("initContainers", None)
    spec.pop("hostname", None)
    spec.pop("subdomain", None)
    spec["restartPolicy"] = "Never"
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "native-duplicate-writer"}, "spec": spec}


def openbao_destination(configuration, endpoint):
    return configuration + f"\n[security.provider_access]\nuri = '{endpoint}/v1/transit/keys/positron'\nversion = '1'\nauthentication = 'openbao-token'\ntoken_file = '/etc/positron/operations/export/openbao-token'\ntrust_roots_file = '/etc/positron/operations/export/openbao-ca.pem'\n"


class OpenBaoFixture:
    image = "openbao/openbao:2.7.1@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
    configuration = b'api_addr = "https://native-openbao:8200"\nstorage "inmem" {}\nlistener "tcp" { \n  address = "0.0.0.0:8200"\n  tls_cert_file = "/config/server.pem"\n  tls_key_file = "/config/server-key.pem"\n }\n'

    def __init__(self, case, lifecycle):
        self.case, self.lifecycle = case, lifecycle
        self.root = lifecycle.root / "openbao"
        self.root.mkdir(mode=0o700)
        material(self.root)
        (self.root / "server.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:native-openbao\n")
        command(["openssl", "x509", "-req", "-in", str(self.root / "server.csr"), "-CA", str(self.root / "ca.pem"),
                 "-CAkey", str(self.root / "ca-key.pem"), "-CAcreateserial", "-days", "1", "-sha256",
                 "-extfile", str(self.root / "server.ext"), "-out", str(self.root / "server.pem")])
        lifecycle.apply({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "native-openbao"},
                         "data": {name: base64.b64encode(data).decode() for name, data in
                                  [("server.hcl", self.configuration), ("server.pem", (self.root / "server.pem").read_bytes()),
                                   ("server-key.pem", (self.root / "server-key.pem").read_bytes())]}})
        security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
        lifecycle.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "native-openbao"}, "spec": {
            "replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app": "native-openbao"}},
            "template": {"metadata": {"labels": {"app": "native-openbao"}}, "spec": {
                "automountServiceAccountToken": False, "shareProcessNamespace": True,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{"name": "openbao", "image": self.image, "args": ["server", "-config=/config/server.hcl"],
                                "securityContext": security, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "512Mi"}},
                                "readinessProbe": {"tcpSocket": {"port": 8200}, "periodSeconds": 1},
                                "volumeMounts": [{"name": "configuration", "mountPath": "/config", "readOnly": True}]}],
                "volumes": [{"name": "configuration", "secret": {"secretName": "native-openbao", "defaultMode": 0o440}}]}}}})
        lifecycle.apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "native-openbao"},
                         "spec": {"selector": {"app": "native-openbao"}, "ports": [{"port": 8200}]}})
        lifecycle.kube("rollout", "status", "deployment/native-openbao", "--timeout=180s", timeout=190)
        self.forward = subprocess.Popen(["kubectl", *lifecycle.helm[1:], "port-forward", "service/native-openbao", "0:8200", "--address", "127.0.0.1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            case.assertTrue(select.select([self.forward.stdout], [], [], 15)[0], "provider port-forward did not bind")
            self.port = int(self.forward.stdout.readline().decode().split("127.0.0.1:", 1)[1].split(" ", 1)[0])
            self.trust = ssl.create_default_context(cafile=str(self.root / "ca.pem"))
            initialized = self.request("PUT", "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
            self.request("PUT", "/v1/sys/unseal", {"key": initialized["keys_base64"][0]})
            token = initialized["root_token"]
            case.assertEqual(self.request("GET", "/v1/sys/health")["version"], "2.7.1")
            self.request("POST", "/v1/sys/mounts/transit", {"type": "transit"}, token)
            self.request("POST", "/v1/transit/keys/positron", {"type": "aes256-gcm96", "derived": True, "convergent_encryption": False}, token)
            policy = 'path "transit/keys/positron" { capabilities = ["read"] }\npath "transit/encrypt/positron" { capabilities = ["update"] }\npath "transit/decrypt/positron" { capabilities = ["update"] }'
            self.request("PUT", "/v1/sys/policies/acl/positron", {"policy": policy}, token)
            limited = self.request("POST", "/v1/auth/token/create", {"policies": ["positron"], "ttl": "10m", "renewable": True, "num_uses": 0}, token)["auth"]
            case.assertTrue(limited["renewable"])
            case.assertGreater(limited["lease_duration"], 0)
            lifecycle.install({"inputs/export/openbao-token": limited["client_token"].encode(), "inputs/export/openbao-ca.pem": (self.root / "ca.pem").read_bytes()})
        finally:
            self.close()

    def request(self, method, path, value=None, token=None):
        connection = http.client.HTTPSConnection("native-openbao", 8200, timeout=10, context=self.trust)
        connection.sock = self.trust.wrap_socket(socket.create_connection(("127.0.0.1", self.port), timeout=10), server_hostname="native-openbao")
        try:
            headers = {"Content-Type": "application/json"}
            if token: headers["X-Vault-Token"] = token
            connection.request(method, path, body=None if value is None else json.dumps(value).encode(), headers=headers)
            response = connection.getresponse()
            payload = response.read(32769)
            self.case.assertLessEqual(len(payload), 32768)
            self.case.assertIn(response.status, [200, 204], "owned provider request failed")
            return json.loads(payload) if payload else {}
        finally:
            connection.close()

    def close(self):
        self.forward.terminate()
        try: self.forward.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.forward.kill()
            self.forward.wait(timeout=5)
        self.forward.stdout.close()
        self.forward.stderr.close()


def exercise_provider_outage(case, lifecycle, expected):
    from data_lifecycle import fields
    OpenBaoFixture(case, lifecycle)
    destination = openbao_destination(lifecycle.config, "https://native-openbao:8200")
    reference = "/etc/positron/operations/export/openbao-target.toml"
    lifecycle.install({"inputs/export/openbao-target.toml": destination.encode()})
    for phase in ["prepare", "activate"]:
        status = fields(lifecycle.online("keys", "migrate", "status"))
        accepted = fields(lifecycle.online("keys", "migrate", phase, "--target-config", reference,
                                         "--expected-generation", status["catalog_generation"], "--idempotency-key", str(uuid.uuid4())))
        operation = accepted["operation_id"]
        outcome = fields(lifecycle.online("keys", "migrate", "wait", "--operation-id", operation, "--wait-seconds", "60", timeout=65))
        case.assertEqual(outcome["operation_id"], operation)
        case.assertEqual(outcome["status"], "succeeded")
    status = fields(lifecycle.online("keys", "migrate", "status"))
    case.assertEqual(status["active_provider_family"], "7")
    case.assertEqual(status["active_provider_version"], "1")
    lifecycle.config = destination
    lifecycle.values["configuration"] = destination
    lifecycle.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "native-positron"}, "data": {"positron.toml": destination}})
    case.assertEqual(lifecycle.query(stage="openbao_activated"), expected)
    provider = json.loads(lifecycle.kube("get", "pods", "-l", "app=native-openbao", "-o", "json").stdout)["items"]
    case.assertEqual(len(provider), 1)
    provider_pod = provider[0]["metadata"]["name"]
    process = lifecycle.kube("exec", provider_pod, "--", "pidof", "bao").stdout.strip()
    case.assertRegex(process, rb"\A[1-9][0-9]{0,9}\Z")
    pid = int(process)
    case.assertGreater(pid, 1, "namespace init ignores SIGSTOP")
    case.assertEqual(lifecycle.kube("exec", provider_pod, "--", "cat", f"/proc/{pid}/comm").stdout, b"bao\n")
    try:
        lifecycle.kube("exec", provider_pod, "--", "/bin/sh", "-c", f"kill -STOP {pid}", timeout=5)
        state = lifecycle.kube("exec", provider_pod, "--", "cat", f"/proc/{pid}/status").stdout
        case.assertIn(b"State:\tT (stopped)", state)
        case.assertEqual(lifecycle.query(stage="openbao_cached_outage"), expected)
        # Expiry is governed by the configured five-second native cache lease.
        time.sleep(5.1)
        with case.assertRaises(subprocess.CalledProcessError) as unavailable:
            lifecycle.query(stage="openbao_unavailable")
        case.assertEqual(unavailable.exception.stderr, b"positron: query unavailable; inspect instance readiness\n")
        probe = ["/usr/bin/positron", "doctor", "--live", "--endpoint", "127.0.0.1:13133", "--server-name", "localhost",
                 "--trust-file", "/etc/positron/tls/..data/ca.pem"]
        case.assertEqual(lifecycle.kube("exec", lifecycle.pod, "--", *probe).stdout, b"status=live\n")
        probe[2] = "--ready"
        case.assertNotEqual(lifecycle.kube("exec", lifecycle.pod, "--", *probe, check=False).returncode, 0)
        lifecycle.scale(0)
        lifecycle.kube("scale", "statefulset/native-positron", "--replicas=1")
        lifecycle.kube("wait", "--for=jsonpath={.status.phase}=Running", "pod/" + lifecycle.pod, "--timeout=90s", timeout=100)
        ready = lifecycle.kube("wait", "--for=condition=Ready", "pod/" + lifecycle.pod, "--timeout=5s", timeout=10, check=False)
        case.assertNotEqual(ready.returncode, 0)
        live = lifecycle.kube("exec", lifecycle.pod, "--", "/usr/bin/positron", "doctor", "--live", "--endpoint", "127.0.0.1:13133",
                              "--server-name", "localhost", "--trust-file", "/etc/positron/tls/..data/ca.pem")
        case.assertEqual(live.stdout, b"status=live\n")
        cold = json.loads(lifecycle.kube("get", "pod", lifecycle.pod, "-o", "json").stdout)
        case.assertEqual({item["name"]: item["restartCount"] for item in cold["status"]["containerStatuses"]}, {"positron": 0})
    finally:
        failure = sys.exception()
        try:
            lifecycle.kube("exec", provider_pod, "--", "/bin/sh", "-c", f"kill -CONT {pid}", timeout=5)
        except Exception:
            if failure is None: raise RuntimeError("owned OpenBao process resume unavailable") from None
            failure.add_note("owned OpenBao process resume unavailable")
    recovered = wait_operand(lifecycle)
    case.assertEqual(recovered["metadata"]["uid"], cold["metadata"]["uid"])
    case.assertEqual({item["name"]: item["restartCount"] for item in recovered["status"]["containerStatuses"]}, {"positron": 0})
    case.assertEqual(lifecycle.query(stage="openbao_recovered"), expected)


def exercise_duplicate_writer(case, lifecycle, state, expected):
    retained = storage_identities(lifecycle)
    challenger = duplicate_writer_pod(state)
    name = challenger["metadata"]["name"]
    lifecycle.apply(challenger)
    try:
        lifecycle.kube("wait", "--for=jsonpath={.status.phase}=Running", "pod/" + name, "--timeout=90s", timeout=100)
        probe = ["/usr/bin/positron", "doctor", "--live", "--endpoint", "127.0.0.1:13133", "--server-name", "localhost",
                 "--trust-file", "/etc/positron/tls/..data/ca.pem"]
        deadline = time.monotonic() + 30
        while True:
            result = lifecycle.kube("exec", name, "--", *probe, check=False, timeout=5)
            if result.returncode == 0:
                case.assertEqual(result.stdout, b"status=live\n")
                break
            if time.monotonic() >= deadline:
                raise AssertionError("duplicate owner did not remain live within its startup budget")
            time.sleep(0.2)
        probe[2] = "--ready"
        case.assertNotEqual(lifecycle.kube("exec", name, "--", *probe, check=False).returncode, 0)
        observed = json.loads(lifecycle.kube("get", "pod", name, "-o", "json").stdout)
        case.assertEqual(observed["spec"]["nodeName"], state["spec"]["nodeName"])
        case.assertFalse(any(item["type"] == "Ready" and item["status"] == "True" for item in observed["status"].get("conditions", [])))
        records = [json.loads(line) for line in lifecycle.kube("logs", name, "--tail=100", "--limit-bytes=32768").stdout.splitlines()]
        case.assertTrue(any(record.get("event") == "process_recovering" for record in records))
        case.assertTrue(any(record.get("event") == "dependency_storage_unavailable" for record in records))
        with case.assertRaises(subprocess.CalledProcessError) as refused:
            lifecycle.query(compose=name, stage="duplicate_writer_refused")
        case.assertEqual(refused.exception.stderr, b"positron: query transport or response unavailable\n")
        case.assertEqual(lifecycle.query(stage="original_owner_retained"), expected)
        case.assertEqual(storage_identities(lifecycle), retained)
    finally:
        lifecycle.kube("delete", "pod", name, "--wait=true", "--timeout=90s", timeout=100)


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


def reload_projected_identity(kube, pod, identity, expected, administrator, timeout=180, rejection_baseline=None):
    deadline = time.monotonic() + timeout
    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0: raise AssertionError("native TLS generation did not establish the expected public outcome")
        return budget
    while True:
        try:
            result = kube("exec", "-i", pod, "--", "/usr/bin/positron", "config", "reload", "--control-path", "/run/positron/control/control.sock", "--credential-stdin", data=administrator, timeout=min(10, remaining()))
        except Exception as failure:
            try:
                observation_deadline = min(deadline, time.monotonic() + 1)
                reasons = set()
                while True:
                    budget = observation_deadline - time.monotonic()
                    if budget <= 0: break
                    output = kube("logs", pod, "--tail=200", "--limit-bytes=32768", timeout=budget).stdout
                    for line in output[:32768].splitlines():
                        try: record = json.loads(line)
                        except (ValueError, UnicodeDecodeError): continue
                        if isinstance(record, dict) and record.get("event") == "owner_inspection_unavailable" and isinstance(record.get("reason"), str) and record["reason"] in {"phase", "catalog_operation", "owner_reference", "configuration_reference", "key_custody", "resource_admission", "catalog", "identity", "security_time", "collector"}:
                            reasons.add(record["reason"])
                    if reasons: break
                    time.sleep(min(0.05, max(0, observation_deadline - time.monotonic())))
                for reason in sorted(reasons): failure.add_note("native owner inspection unavailable: " + reason)
                if not reasons: failure.add_note("native owner diagnostic unavailable")
            except Exception:
                failure.add_note("native owner diagnostic unavailable")
            raise
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
    @unittest.skipUnless(os.environ.get("POSITRON_TEST_HELM_FIXTURE_HELPER"), "requires the existing native signed-input helper")
    def test_native_openbao_outage_and_cold_recovery(self):
        self.exercise_native(True, False, include_provider=True)

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

    def exercise_native(self, include_data, include_upgrade, include_interruptions=False, include_provider=False):
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
                if include_provider:
                    configuration = yaml.safe_load(command([*helm, "show", "values", str(chart)]).stdout)["configuration"]
                    configuration = re.sub(r"(?m)^\s*key_cache_lease_seconds\s*=.*\n", "", configuration)
                    self.assertIn("[security]\n", configuration)
                    values["configuration"] = configuration.replace("[security]\n", "[security]\nkey_cache_lease_seconds = 5\n", 1)
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
                    if include_provider:
                        exercise_provider_outage(self, lifecycle, expected)
                    if include_interruptions:
                        control_plane = os.environ["POSITRON_TEST_HELM_INTERRUPTION_CONTROL_PLANE"]
                        self.assertEqual(control_plane, context.removeprefix("kind-") + "-control-plane")
                        exercise_interruptions(self, lifecycle, control_plane, image, root / "ca.pem", expected)
                # Restart reattaches the same PVCs under fsGroup OnRootMismatch.
                claims = json.loads(kube("get", "pvc", "-o", "json").stdout)["items"]
                retained = {item["metadata"]["name"]: item["metadata"]["uid"] for item in claims}
                kube("delete", "pod", pod, "--wait=true", "--timeout=180s", timeout=190)
                ready()
                self.assertEqual(retained, {item["metadata"]["name"]: item["metadata"]["uid"] for item in json.loads(kube("get", "pvc", "-o", "json").stdout)["items"]})
                self.assertEqual(private_modes(), private_before_restart)
                if lifecycle and not include_provider:
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
                        reload_projected_identity(kube, pod, active_identity, expected, claim.splitlines()[0].split(b"=", 1)[1], rejection_baseline=baseline)
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
                assert_retained_claims(self, retained, {item["metadata"]["name"]: item["metadata"]["uid"] for item in after}, ["restored-positron-data", "restored-positron-secrets"] if include_data and not include_provider else [])
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
