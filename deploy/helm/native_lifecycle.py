"""Exact-cluster adapter for the existing public native lifecycle assertions."""
import io
import hashlib
import json
import os
import re
import select
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import uuid
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "compose"))
import data_lifecycle
from data_lifecycle import DataLifecycle, fields

INPUTS = "/etc/positron/operations"
BACKUPS = "/var/lib/positron-backups/private"
CONFIG = "/etc/positron/config/positron.toml"
REPOSITORY = "11111111-1111-4111-8111-111111111111"


IMAGE_MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
IMAGE_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")


def image_metadata(path):
    with Path(path).open("rb") as source:
        encoded = source.read(1_048_577)
    if len(encoded) > 1_048_576:
        raise ValueError("runtime OCI metadata exceeds its bound")
    value = json.loads(encoded)
    if not isinstance(value, dict) or value.get("schemaVersion") != 2:
        raise ValueError("runtime OCI schema version 2 required")
    return encoded, value


def query_image_descriptor(node_image, index_file, architecture):
    match = re.fullmatch(r"ghcr[.]io/vicotrbb/positron@(sha256:[a-f0-9]{64})", node_image)
    encoded, root = image_metadata(index_file)
    if not match or "sha256:" + hashlib.sha256(encoded).hexdigest() != match[1]:
        raise ValueError("node image does not match the captured OCI descriptor")
    if architecture not in ("amd64", "arm64"):
        raise ValueError("qualified Linux runtime architecture required")
    media_type = root.get("mediaType")
    if media_type in IMAGE_MANIFEST_TYPES:
        return match[1], {"mediaType": media_type, "digest": match[1], "size": len(encoded)}
    entries = root.get("manifests")
    if media_type not in IMAGE_INDEX_TYPES or not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        raise ValueError("bounded runtime image index required")
    direct = [entry for entry in entries if isinstance(entry, dict) and entry.get("mediaType") in IMAGE_MANIFEST_TYPES]
    selected = [entry for entry in direct if isinstance(entry.get("platform"), dict) and entry["platform"].get("os") == "linux" and entry["platform"].get("architecture") == architecture]
    if not selected and len(direct) == 1 and "platform" not in direct[0]:
        selected = direct
    if len(selected) != 1:
        raise ValueError("one qualified runtime image manifest required")
    descriptor, = selected
    if not isinstance(descriptor.get("digest"), str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", descriptor["digest"]) or type(descriptor.get("size")) is not int or not 0 < descriptor["size"] <= 1_048_576:
        raise ValueError("bounded image manifest descriptor required")
    return match[1], descriptor


def checked_query_image(node_image, *, timeout):
    host_image = os.environ.get("POSITRON_TEST_HELM_QUERY_IMAGE", "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", host_image):
        raise ValueError("immutable Docker host image ID required")
    index = Path(os.environ["POSITRON_TEST_HELM_INDEX_FILE"])
    architecture = os.environ["POSITRON_TEST_HELM_ARCHITECTURE"]
    root_digest, descriptor = query_image_descriptor(node_image, index, architecture)
    manifest_path = index if descriptor["digest"] == root_digest else index.with_name("query-manifest-" + descriptor["digest"].removeprefix("sha256:") + ".json")
    encoded, manifest = image_metadata(manifest_path)
    if len(encoded) != descriptor["size"] or "sha256:" + hashlib.sha256(encoded).hexdigest() != descriptor["digest"] or manifest.get("mediaType") != descriptor["mediaType"]:
        raise ValueError("selected runtime image manifest binding changed")
    config = manifest.get("config")
    if not isinstance(config, dict) or not isinstance(config.get("digest"), str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", config["digest"]) or config.get("mediaType") not in ("application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json") or type(config.get("size")) is not int or not 0 < config["size"] <= 1_048_576:
        raise ValueError("bounded runtime OCI config descriptor required")
    if host_image not in (descriptor["digest"], config["digest"]):
        raise ValueError("Docker host image does not match the captured node payload")
    inspected = subprocess.run(["docker", "image", "inspect", "--format", "[{{json .Id}},{{json .Os}},{{json .Architecture}}]", host_image], capture_output=True, timeout=timeout, check=True)
    if len(inspected.stdout) > 1024 or json.loads(inspected.stdout) != [host_image, "linux", architecture]:
        raise ValueError("Docker host image identity changed or platform differs")
    return host_image


class NativeLifecycle(DataLifecycle):
    def __init__(self, case, root, kube, apply, scale, pod, helm, chart, values, claim):
        self.case, self.root, self.kube, self.apply, self.scale = case, root, kube, apply, scale
        self.pod, self.helm, self.chart, self.values = pod, helm, chart, values
        self.keys = fields(claim)
        self.admin, self.query_key = self.keys["administrator_secret"], self.keys["query_secret"]
        data_lifecycle.EXPORT = INPUTS + "/export"
        data_lifecycle.BACKUPS = BACKUPS
        self.backup_claim = "native-positron-backups"
        self.inputs_claim = "native-operation-inputs"
        self.fixture = root / "fixture"
        self.fixture.mkdir(mode=0o700)
        self.sequence = 0
        self.forwarders = []
        self.last_operation = None

    def compose(self, action, *args, **kwargs):
        if action == "port":
            process = subprocess.Popen(["kubectl", *self.helm[1:], "port-forward", "pod/" + self.pod, "0:4318", "--address", "127.0.0.1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.forwarders.append(process)
            if not select.select([process.stdout], [], [], 15)[0]: raise AssertionError("port-forward did not bind")
            address = process.stdout.readline().decode().split()[2]
            return address.encode()
        if action == "stop": self.scale(0)
        elif action == "up": self.scale(1)
        else: raise AssertionError("unsupported test lifecycle action")

    def close(self):
        for process in self.forwarders:
            process.terminate()
            process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()

    def online(self, family, action=None, *args, credential=None, compose=None, timeout=35):
        if callable(compose):
            return super().online(family, action, *args, credential=credential, compose=compose, timeout=timeout)
        arguments = [family] + ([action] if action else [])
        if action == "wait" and "--operation-id" in args:
            self.last_operation = (family, args[args.index("--operation-id") + 1])
        result = self.kube("exec", "-i", "-c", "positron", compose or self.pod, "--", "/usr/bin/positron", *arguments,
                           "--endpoint", "127.0.0.1:8080", "--server-name", "localhost",
                           "--trust-file", "/etc/positron/tls/..data/ca.pem", "--credential-stdin", *args,
                           data=(credential or self.admin).encode(), timeout=timeout, check=False)
        if result.returncode:
            # Strip only kubectl's exact process-exit footer; preserve native diagnostics.
            error = re.sub(br"command terminated with exit code [0-9]+\n$", b"", result.stderr)
            raise subprocess.CalledProcessError(result.returncode, ["positron", family], output=result.stdout, stderr=error)
        return result.stdout

    def query_on_node(self, node, pod_ip, image, ca, *, stage):
        import ipaddress
        if not re.fullmatch(r"(?:k3d-)?positron-120-[a-z0-9]+(?:-[a-z0-9]+)*", node):
            raise ValueError("explicit owned node required")
        address = ipaddress.ip_address(pod_ip)
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ValueError("captured operand Pod IP required")
        public = self.root / "query-public"
        public.mkdir(mode=0o755, exist_ok=True)
        for name, source in [("ca.pem", Path(ca)), ("query.json", self.fixture / "export/query.json")]:
            destination = public / name
            contents = source.read_bytes()
            if destination.exists():
                if destination.read_bytes() != contents:
                    raise ValueError("captured public query inputs changed during interruption")
            else:
                destination.write_bytes(contents)
                destination.chmod(0o444)
        endpoint = f"[{address}]:8080" if address.version == 6 else f"{address}:8080"
        def transport(action, *arguments, **options):
            if action != "exec" or arguments[:4] != ("-T", "positron", "/usr/bin/positron", "query"):
                raise ValueError("direct transport is restricted to the native read-only query")
            deadline = time.monotonic() + options["timeout"]
            host_image = checked_query_image(image, timeout=min(10, options["timeout"]))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("direct query deadline expired during image inspection")
            native = list(arguments[3:])
            native[native.index("--endpoint") + 1] = endpoint
            client = "positron-120-query-" + uuid.uuid4().hex
            command = ["docker", "run", "--rm", "-i", "--name", client, "--pull=never", "--network", "container:" + node,
                       "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532",
                       "-v", f"{public / 'ca.pem'}:/etc/positron/tls/ca.pem:ro",
                       "-v", f"{public / 'query.json'}:{INPUTS}/export/query.json:ro", host_image, *native]
            try:
                result = subprocess.run(command, input=options["input"], timeout=remaining, capture_output=True, check=True)
                return result.stdout
            except subprocess.CalledProcessError as error:
                if error.returncode != 125:
                    raise
                reason = "image_unavailable" if b"No such image" in (error.stderr or b"") else "start_refused"
                raise RuntimeError(f"owned direct query container start failed (docker_exit=125, reason={reason})") from None
            finally:
                cleanup = subprocess.run(["docker", "rm", "-f", client], capture_output=True, timeout=10, check=False)
                absent = b"Error response from daemon: No such container: " + client.encode() + b"\n"
                if cleanup.returncode and cleanup.stderr != absent:
                    raise RuntimeError("owned direct query client cleanup failed")
        return self.query(compose=transport, stage=stage)

    def diagnostics(self):
        if not self.last_operation: return
        family, operation = self.last_operation
        try:
            result = fields(self.online(family, "lookup", "--operation-id", operation, timeout=10))
            selected = {key: value for key, value in result.items() if key in ["status", "phase", "stage", "operation_revision", "failure_code"] and re.fullmatch(r"[A-Za-z0-9_():.-]{1,128}", value)}
            print(json.dumps({"native_operation": operation, "family": family, "lookup": selected}), flush=True)
        except Exception:
            print("native_operation_lookup_unavailable", flush=True)

    def render(self, release, values):
        candidate = self.root / "job-values.json"
        candidate.write_text(json.dumps(values))
        result = subprocess.run([*self.helm, "template", release, str(self.chart), "-f", str(candidate)],
                                check=True, capture_output=True)
        return list(yaml.safe_load_all(result.stdout))

    def offline(self, *args, compose=None):
        release = compose or "native"
        target = release + "-positron"
        state = json.loads(self.kube("get", "statefulset", target, "-o", "json").stdout)
        self.case.assertEqual(state["spec"]["replicas"], 0)
        pods = json.loads(self.kube("get", "pods", "-l", f"app.kubernetes.io/instance={release}", "-o", "json").stdout)
        self.case.assertEqual(pods["items"], [], "no live data PVC owner may overlap offline work")
        self.sequence += 1
        arguments = [str(value) for value in args]
        arguments = [value + "/instance" if value in ["/var/lib/positron", "/var/lib/positron-secrets"] else value for value in arguments]
        values = dict(self.values, replicas=0, operationInputsClaim=self.inputs_claim)
        if release != "native": values["backupClaim"] = self.backup_claim
        values["maintenance"] = {"enabled": True, "name": "op" + str(self.sequence), "args": arguments}
        job, = [obj for obj in self.render(release, values) if obj["kind"] == "Job"]
        name = job["metadata"]["name"]
        self.apply(job)
        try:
            deadline = time.monotonic() + 180
            while True:
                status = json.loads(self.kube("get", "job", name, "-o", "json").stdout).get("status", {})
                if status.get("succeeded") or status.get("failed"): break
                if time.monotonic() >= deadline: raise AssertionError("offline native operation did not terminate")
                time.sleep(0.2)
            output = self.kube("logs", f"job/{name}").stdout
            self.case.assertNotIn(b"administrator_secret=", output)
            if not status.get("succeeded"):
                raise AssertionError("native offline operation refused: " + output.decode(errors="replace")[:2048])
            return output
        finally:
            self.kube("delete", "job", name, "--wait=true", "--timeout=90s", timeout=100)
            self.kube("wait", "--for=delete", "pod", "-l", f"job-name={name}", "--timeout=90s", timeout=100)

    def prepare(self, configuration):
        self.scale(0)
        environment = dict(os.environ, POSITRON_TEST_COMPOSE_FIXTURE_ROOT=str(self.fixture),
                           POSITRON_TEST_COMPOSE_CURRENT_BINARY=os.environ["POSITRON_TEST_HELM_CURRENT_BINARY"])
        helper = Path(os.environ["POSITRON_TEST_HELM_FIXTURE_HELPER"]).resolve()
        command = ["docker", "run", "--rm", "-i", "--user", f"{os.getuid()}:{os.getgid()}", "--network", "none", "-v", f"{self.root}:{self.root}",
                   "-v", f"{helper.parent}:{helper.parent}:ro", "-v", f"{Path(environment['POSITRON_TEST_COMPOSE_CURRENT_BINARY']).parent}:{Path(environment['POSITRON_TEST_COMPOSE_CURRENT_BINARY']).parent}:ro"]
        for key in ["POSITRON_TEST_COMPOSE_FIXTURE_ROOT", "POSITRON_TEST_COMPOSE_CURRENT_BINARY", "POSITRON_TEST_UPGRADE_BINARY", "POSITRON_TEST_SOURCE_COMMIT", "POSITRON_TEST_CANDIDATE_COMMIT"]:
            command += ["-e", key + "=" + environment[key]]
        candidate = Path(environment["POSITRON_TEST_UPGRADE_BINARY"]).resolve()
        command += ["-v", f"{candidate.parent}:{candidate.parent}:ro", os.environ["POSITRON_TEST_HELM_FIXTURE_BUILDER"], str(helper), "--ignored", "--exact", "prepare_compose_lifecycle_inputs"]
        subprocess.run(command, input=self.query_key.encode(), check=True, capture_output=True, timeout=120)
        section = (self.fixture / "positron.toml").read_text().split("[release.installation]", 1)[1].replace(str(self.fixture), INPUTS)
        self.config = configuration + "\n[release.installation]" + section
        self.recipient = (self.fixture / "export/recipient").read_text()
        self.candidate_digest = (self.fixture / "export/candidate-digest").read_text()
        self.apply({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": self.inputs_claim},
                    "spec": {"accessModes": ["ReadWriteOnce"], "volumeMode": "Filesystem", "storageClassName": self.values["storageClass"],
                             "resources": {"requests": {"storage": "1Gi"}}}})
        self.install({"inputs/export/" + path.name: path.read_bytes() for path in (self.fixture / "export").iterdir()}, initialize=True)
        self.apply({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "native-positron"}, "data": {"positron.toml": self.config}})
        self.values["configuration"] = self.config
        self.values["operationInputsClaim"] = self.inputs_claim
        # OnDelete makes this change intentional; source is already fully stopped.
        values_file = self.root / "configured-values.json"
        values_file.write_text(json.dumps(self.values))
        subprocess.run([*self.helm, "upgrade", "native", str(self.chart), "-f", str(values_file), "--set", "replicas=0"], check=True, capture_output=True)
        self.scale(1)

    def install(self, files, *, initialize=False):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            directories = {"backups/private", "backups/private/repository", "inputs/export"} if initialize else set()
            for name in sorted(directories, key=lambda value: (len(Path(value).parts), value)):
                member = tarfile.TarInfo(name)
                member.type, member.mode, member.uid, member.gid = tarfile.DIRTYPE, 0o700, 65532, 65532
                archive.addfile(member)
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.uid, member.gid = len(data), 0o600, 65532, 65532
                archive.addfile(member, io.BytesIO(data))
        if initialize:
            extract = 'cd "$1"; test ! -e backups/private; test ! -L backups/private; test ! -e inputs/export; test ! -L inputs/export; tar -xf -; chmod -- 00700 backups/private backups/private/repository inputs/export'
        else:
            extract = 'cd "$1"; for path in backups/private backups/private/repository inputs/export; do test "$(find "$path" -prune -type d -perm 0700 -user "$(id -u)" -print)" = "$path"; done; tar -xf -'
        name = "native-input-provision"
        security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532,
                                "fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "provision", "image": data_lifecycle.ADMIN_IMAGE, "command": ["sh", "-ec", extract, "provision", "/work"],
                            "stdin": True, "stdinOnce": True, "securityContext": security,
                            "volumeMounts": [{"name": "inputs", "mountPath": "/work/inputs"}, {"name": "backups", "mountPath": "/work/backups"}]}],
            "volumes": [{"name": "inputs", "persistentVolumeClaim": {"claimName": self.inputs_claim}},
                        {"name": "backups", "persistentVolumeClaim": {"claimName": self.backup_claim}}]}}
        self.apply(pod)
        try:
            self.kube("wait", "--for=condition=Ready", "pod/" + name, "--timeout=180s", timeout=190)
            self.kube("attach", "-i", name, data=payload.getvalue(), timeout=120)
            self.kube("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/" + name, "--timeout=60s", timeout=70)
            status = json.loads(self.kube("get", "pod", name, "-o", "json").stdout)
            self.case.assertEqual(status["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"], 0)
        finally:
            self.kube("delete", "pod", name, "--wait=true", "--timeout=90s", timeout=100)

    def restore(self, expected):
        self.scale(0)
        release = "restored"
        values = dict(self.values, replicas=0, operationInputsClaim=self.inputs_claim, backupClaim=self.backup_claim)
        path = self.root / "restore-values.json"
        path.write_text(json.dumps(values))
        subprocess.run([*self.helm, "install", release, str(self.chart), "-f", str(path)], check=True, capture_output=True)
        try:
            source = [json.loads(self.kube("get", "pvc", "native-positron-" + suffix, "-o", "json").stdout) for suffix in ["data", "secrets"]]
            target = [json.loads(self.kube("get", "pvc", "restored-positron-" + suffix, "-o", "json").stdout) for suffix in ["data", "secrets"]]
            self.case.assertEqual(len({claim["metadata"]["uid"] for claim in source + target}), 4)
            # Fresh target claims bind on the first offline Pod; verify PV identities below.
            args = ["backup", "restore", "start", "--output", "json", "--config", CONFIG,
                    "--locator", BACKUPS + "/repository", "--repository-id", REPOSITORY,
                    "--snapshot-id", self.snapshot, "--expected-manifest-checksum", self.checksum,
                    "--idempotency-key", str(uuid.uuid4()), "--bundle", BACKUPS + "/recovery.age",
                    "--identity-file", INPUTS + "/export/recovery.identity"]
            for flag, key in [("--instance", "instance"), ("--root-key-id", "root_key_id"), ("--root-created-at", "root_created_at"), ("--root-fingerprint", "root_fingerprint"), ("--integrity-public-key", "integrity_public_key"), ("--integrity-fingerprint", "integrity_fingerprint")]:
                args += [flag, self.pin[key]]
            operation = json.loads(self.offline(*args, compose=release))["operation"]["id"]
            target = [json.loads(self.kube("get", "pvc", "restored-positron-" + suffix, "-o", "json").stdout) for suffix in ["data", "secrets"]]
            self.case.assertEqual(len({claim["spec"]["volumeName"] for claim in source + target}), 4)
            args[2] = "wait"
            deadline = time.monotonic() + 300
            while True:
                result = json.loads(self.offline(*args, "--operation-id", operation, "--wait-seconds", "30", compose=release))
                if result["operation"]["status"] == "succeeded": break
                self.case.assertIn(result["operation"]["status"], ["pending", "running"])
                if time.monotonic() >= deadline: raise AssertionError("native Restore did not complete")
            self.kube("scale", "statefulset/restored-positron", "--replicas=1")
            self.kube("wait", "--for=create", "pod/restored-positron-0", "--timeout=90s", timeout=100)
            self.kube("wait", "--for=condition=Ready", "pod/restored-positron-0", "--timeout=180s", timeout=190)
            self.case.assertEqual(self.query("restored-positron-0", stage="restore"), expected)
        finally:
            subprocess.run([*self.helm, "uninstall", release], check=True, capture_output=True)
            self.kube("wait", "--for=delete", "pod/restored-positron-0", "--timeout=180s", timeout=190)
        self.scale(1)
        self.case.assertEqual(self.query(stage="post_restore"), expected)

    def upgrade(self, expected):
        status = fields(self.online("repository", "status"))
        accepted = fields(self.online("upgrade", "start", "--candidate-manifest", self.candidate_digest,
            "--repository-id", REPOSITORY, "--retention-seconds", "3600", "--expected-generation", status["catalog_generation"], "--idempotency-key", str(uuid.uuid4())))
        operation = accepted["operation_id"]
        # Stop reconciliation immediately; native Upgrade itself supplies Drain.
        self.kube("scale", "statefulset/native-positron", "--replicas=0")
        self.kube("wait", "--for=delete", "pod/" + self.pod, "--timeout=180s", timeout=190)
        deadline = time.monotonic() + 300
        while True:
            state = fields(self.offline("upgrade", "offline", "advance", "--config", CONFIG, "--operation-id", operation, "--seconds", "30"))
            if state["stage"] == "Some(Publishing)": break
            self.case.assertEqual(state["status"], "Running")
            if time.monotonic() >= deadline: raise AssertionError("native Upgrade did not finish its verified snapshot")
        self.offline("upgrade", "offline", "publish", "--config", CONFIG, "--operation-id", operation)
        export = self.fixture / "export"
        self.install({"inputs/export/current.manifest": (export / "candidate.manifest").read_bytes(),
                      "inputs/export/current.inventory.json": (export / "inventory.json").read_bytes()})
        self.values["image"] = os.environ["POSITRON_TEST_HELM_CANDIDATE_IMAGE"]
        path = self.root / "upgrade-values.json"
        path.write_text(json.dumps(dict(self.values, replicas=0)))
        subprocess.run([*self.helm, "upgrade", "native", str(self.chart), "-f", str(path)], check=True, capture_output=True)
        self.scale(1)
        self.case.assertEqual(self.query(stage="upgrade"), expected)
