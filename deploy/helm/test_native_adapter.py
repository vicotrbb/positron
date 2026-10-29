"""The Kubernetes subprocess seam preserves native CLI outcomes for existing consumers."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from native_lifecycle import NativeLifecycle
from test_kubernetes import assert_retained_claims, owned_storage_class, inspect_private_modes, reload_projected_identity


class NativeAdapter(unittest.TestCase):
    def test_local_path_drain_accepts_null_empty_endpoints_and_recovers_the_pending_pod(self):
        import json
        from test_kubernetes import drain_operand
        original = {"metadata": {"namespace": "isolated", "uid": "old-pod"}, "spec": {"nodeName": "positron-120-fixture-worker"}, "status": {"podIP": "10.244.1.5"}}
        pending = {"metadata": {"uid": "new-pod"}, "spec": {}, "status": {"phase": "Pending", "conditions": [{"type": "PodScheduled", "status": "False", "reason": "Unschedulable"}]}}
        recovered = {"metadata": {"uid": "new-pod"}, "spec": {"nodeName": "positron-120-fixture-worker"}, "status": {"podIP": "10.244.1.6", "conditions": [{"type": "Ready", "status": "True"}]}}
        class Lifecycle:
            pod = "native-positron-0"
            cordoned = True
            def kube(self, *args, **kwargs):
                if args[0] == "uncordon": self.cordoned = False
                body = {"items": [{"endpoints": None}]} if args[:2] == ("get", "endpointslices") else pending if self.cordoned else recovered
                return subprocess.CompletedProcess([], 0, json.dumps(body).encode(), b"")
            def query_on_node(self, node, address, *args, **kwargs):
                if address == "10.244.1.5": raise subprocess.CalledProcessError(1, ["positron", "query"])
                return "retained-digest"
        lifecycle = Lifecycle()
        self.assertEqual(drain_operand(self, lifecycle, original, "image", "ca", "retained-digest"), recovered)
        self.assertFalse(lifecycle.cordoned)

    def test_drain_failure_uncordons_the_exact_worker_before_returning(self):
        import json
        from test_kubernetes import drain_operand
        requests = []
        state = {"metadata": {"namespace": "isolated", "uid": "same-pod"}, "spec": {"nodeName": "positron-120-fixture-worker"},
                 "status": {"podIP": "10.244.1.5", "conditions": [{"type": "Ready", "status": "True"}]}}
        class Lifecycle:
            pod = "native-positron-0"
            def kube(self, *args, **kwargs):
                requests.append(args)
                if args[0] == "drain": raise RuntimeError("drain refused")
                return subprocess.CompletedProcess([], 0, json.dumps(state).encode(), b"")
        with self.assertRaisesRegex(RuntimeError, "drain refused"):
            drain_operand(self, Lifecycle(), state, "image", "ca", "digest")
        self.assertIn(("uncordon", "positron-120-fixture-worker"), requests)
        drain, = [args for args in requests if args[0] == "drain"]
        self.assertIn("--pod-selector=positron-interruption=isolated", drain)
        self.assertNotIn("--disable-eviction", drain)
        self.assertNotIn("--force", drain)

    def test_policy_eviction_binds_the_observed_uid_and_preserves_pdb_refusal(self):
        import json
        from test_kubernetes import evict_operand
        original = {"metadata": {"namespace": "isolated", "uid": "old-pod"}}
        replacement = {"metadata": {"uid": "new-pod"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
        for rejected in [True, False]:
            requests = []
            class Lifecycle:
                pod = "native-positron-0"
                def kube(self, *args, **kwargs):
                    requests.append((args, kwargs))
                    if args[0] == "create":
                        if rejected: raise RuntimeError("disruption budget refused")
                        return subprocess.CompletedProcess([], 0, b"", b"")
                    return subprocess.CompletedProcess([], 0, json.dumps(replacement).encode(), b"")
            if rejected:
                with self.assertRaisesRegex(RuntimeError, "disruption budget refused"): evict_operand(self, Lifecycle(), original)
                self.assertEqual(len(requests), 1)
            else:
                self.assertEqual(evict_operand(self, Lifecycle(), original), replacement)
            args, options = requests[0]
            self.assertIn("/api/v1/namespaces/isolated/pods/native-positron-0/eviction", args)
            body = json.loads(options["data"])
            self.assertEqual(body["apiVersion"], "policy/v1")
            self.assertEqual(body["deleteOptions"]["preconditions"]["uid"], "old-pod")
            self.assertNotIn("--force", args)

    def test_api_outage_resumes_only_the_verified_api_process_when_direct_query_fails(self):
        import json
        from unittest import mock
        from test_kubernetes import api_outage
        commands = []
        def run(arguments, **kwargs):
            commands.append(arguments)
            body = b""
            if "ps" in arguments: body = json.dumps({"containers": [{"id": "api-container"}]}).encode()
            elif "inspect" in arguments: body = json.dumps({"info": {"pid": 1234}}).encode()
            elif "cat" in arguments: body = b"kube-apiserver\n"
            return subprocess.CompletedProcess(arguments, 0, body, b"")
        class Lifecycle:
            pod = "native-positron-0"
            def kube(self, *args, **kwargs):
                if "-o" in args: return subprocess.CompletedProcess([], 0, json.dumps(state).encode(), b"")
                return subprocess.CompletedProcess([], 1, b"", b"unavailable")
            def query_on_node(self, *args, **kwargs): raise RuntimeError("direct query failed")
        state = {"metadata": {"uid": "same-pod"}, "spec": {"nodeName": "positron-120-fixture-worker"}, "status": {"podIP": "10.244.1.5", "conditions": [{"type": "Ready", "status": "True"}]}}
        with mock.patch("test_kubernetes.subprocess.run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "direct query failed"):
                api_outage(self, Lifecycle(), "positron-120-fixture-control-plane", state, "image", "ca", "digest")
        self.assertEqual([args[-2:] for args in commands if "kill" in args], [["-STOP", "1234"], ["-CONT", "1234"]])
        self.assertTrue(all(args[:3] == ["docker", "exec", "positron-120-fixture-control-plane"] for args in commands))

    def test_provisioning_preserves_exact_private_modes_under_setgid_mount_roots(self):
        import json
        import stat
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mounts = root / "mounts"
            mounts.mkdir()
            for name in ["inputs", "backups"]:
                (mounts / name).mkdir(mode=0o2777)
                (mounts / name).chmod(0o2777)
            before = [(path.stat().st_ino, stat.S_IMODE(path.stat().st_mode)) for path in [mounts / "inputs", mounts / "backups"]]
            applied = []
            def kube(*args, **kwargs):
                if args[0] == "attach":
                    command = applied[-1]["spec"]["containers"][0]["command"]
                    result = subprocess.run([str(mounts) if part == "/work" else part for part in command], input=kwargs["data"], capture_output=True, check=True)
                    return result
                if args[:2] == ("get", "pod"):
                    return subprocess.CompletedProcess([], 0, json.dumps({"status": {"containerStatuses": [{"state": {"terminated": {"exitCode": 0}}}]}}).encode(), b"")
                return subprocess.CompletedProcess([], 0, b"", b"")
            lifecycle = NativeLifecycle(self, root, kube, applied.append, None, "pod", [], None, {}, b"administrator_secret=fixed-admin query_secret=fixed-query")
            lifecycle.install({"inputs/export/static": b"fixture"}, initialize=True)
            for name in ["backups/private", "backups/private/repository", "inputs/export"]:
                self.assertEqual(stat.S_IMODE((mounts / name).stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((mounts / "inputs/export/static").stat().st_mode), 0o600)
            private = [(path.stat().st_ino, path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)) for path in [mounts / name for name in ["backups/private", "backups/private/repository", "inputs/export"]]]
            lifecycle.install({"inputs/export/static": b"replacement"})
            self.assertEqual((mounts / "inputs/export/static").read_bytes(), b"replacement")
            self.assertEqual(private, [(path.stat().st_ino, path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)) for path in [mounts / name for name in ["backups/private", "backups/private/repository", "inputs/export"]]])
            (mounts / "backups/private").chmod(0o2700)
            with self.assertRaises(subprocess.CalledProcessError):
                lifecycle.install({"inputs/export/static": b"refused"})
            self.assertEqual((mounts / "inputs/export/static").read_bytes(), b"replacement")
            self.assertEqual(stat.S_IMODE((mounts / "backups/private").stat().st_mode), 0o2700)
            self.assertEqual(before, [(path.stat().st_ino, stat.S_IMODE(path.stat().st_mode)) for path in [mounts / "inputs", mounts / "backups"]])
            broken = root / "broken"
            broken.mkdir()
            for name in ["inputs", "backups"]: (broken / name).mkdir()
            command = applied[0]["spec"]["containers"][0]["command"]
            failure = subprocess.run([str(broken) if part == "/work" else part for part in command], input=b"invalid tar", capture_output=True)
            self.assertNotEqual(failure.returncode, 0)
            self.assertFalse((broken / "backups/private").exists())
            self.assertFalse((broken / "inputs/export").exists())

    def test_direct_query_transport_preserves_tls_credential_and_original_budget_without_kubernetes(self):
        import json
        calls = []
        def forbidden(*args, **kwargs): raise AssertionError("Kubernetes API unavailable")
        def transport(action, *args, **kwargs):
            calls.append((action, args, kwargs))
            return json.dumps({"events": [{"record": {"message": "compose-retained"}}, {"terminal": {"state": "complete", "stats": {"records": "1", "resultDigest": "a" * 64}}}]}).encode()
        with tempfile.TemporaryDirectory() as directory:
            lifecycle = NativeLifecycle(self, Path(directory), forbidden, None, None, "pod", [], None, {}, b"administrator_secret=fixed-admin query_secret=fixed-query")
            self.assertEqual(lifecycle.query(compose=transport, stage="wire"), "a" * 64)
        self.assertEqual(len(calls), 1)
        action, arguments, options = calls[0]
        self.assertEqual(action, "exec")
        self.assertIn("--server-name", arguments)
        self.assertIn("localhost", arguments)
        self.assertIn("--trust-file", arguments)
        self.assertIn("--credential-stdin", arguments)
        self.assertNotIn("--allow-plaintext", arguments)
        self.assertNotIn("fixed-query", arguments)
        self.assertNotIn("fixed-admin", arguments)
        self.assertEqual(options["input"], b"fixed-query")
        self.assertGreater(options["timeout"], 0)
        self.assertLessEqual(options["timeout"], 35)

    def test_owned_node_query_uses_only_public_mounts_and_stdin_credentials(self):
        import json
        import stat
        import hashlib
        import os
        from unittest import mock
        response = json.dumps({"events": [{"record": {"message": "compose-retained"}}, {"terminal": {"state": "complete", "stats": {"records": "1", "resultDigest": "b" * 64}}}]}).encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lifecycle = NativeLifecycle(self, root, lambda *a, **k: self.fail("API used for direct query"), None, None, "pod", [], None, {}, b"administrator_secret=fixed-admin query_secret=fixed-query")
            (lifecycle.fixture / "export").mkdir()
            (lifecycle.fixture / "export/query.json").write_text("{}")
            ca = root / "ca.pem"
            ca.write_text("public test CA")
            host_id = "sha256:" + "c" * 64
            manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": host_id, "mediaType": "application/vnd.oci.image.config.v1+json", "size": 123}}).encode()
            index = root / "runtime-index.json"
            index.write_bytes(manifest)
            node_image = "ghcr.io/vicotrbb/positron@sha256:" + hashlib.sha256(manifest).hexdigest()
            def docker(arguments, **options):
                if arguments[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(arguments, 0, json.dumps([host_id, "linux", "arm64"]).encode(), b"")
                if arguments[:2] == ["docker", "run"] and host_id not in arguments:
                    raise subprocess.CalledProcessError(125, arguments, stderr=b"No such image: node manifest")
                return subprocess.CompletedProcess(arguments, 0, response, b"")
            with mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": host_id, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run", side_effect=docker) as run:
                self.assertEqual(lifecycle.query_on_node("positron-120-fixture-worker", "10.244.0.7", node_image, ca, stage="wire"), "b" * 64)
            invocation, = [call for call in run.call_args_list if call.args[0][:2] == ["docker", "run"]]
            command = invocation.args[0]
            options = invocation.kwargs
            self.assertEqual(command[:3], ["docker", "run", "--rm"])
            self.assertIn("--pull=never", command)
            self.assertIn("container:positron-120-fixture-worker", command)
            self.assertIn("10.244.0.7:8080", command)
            self.assertIn("localhost", command)
            image_position = command.index(host_id)
            self.assertEqual(command[image_position + 1], "query", "the OCI entrypoint already selects the native executable")
            self.assertNotIn("fixed-query", " ".join(command))
            self.assertNotIn("fixed-admin", " ".join(command))
            self.assertEqual(options["input"], b"fixed-query")
            self.assertGreater(options["timeout"],0)
            self.assertLessEqual(options["timeout"],35)
            self.assertEqual(run.call_count,3)
            for index, argument in enumerate(command):
                if argument == "-v":
                    source, destination, mode = command[index+1].split(":")
                    self.assertEqual(mode,"ro")
                    self.assertIn(Path(source).name,["ca.pem","query.json"])
                    self.assertEqual(stat.S_IMODE(Path(source).stat().st_mode),0o444)
            self.assertEqual(stat.S_IMODE(lifecycle.fixture.stat().st_mode),0o700)
            def refused(arguments, **options):
                if arguments[:2] == ["docker", "run"]:
                    raise subprocess.CalledProcessError(125, arguments, stderr=b"No such image: fixed-query fixed-admin /private/path")
                return subprocess.CompletedProcess(arguments, 0, b"", b"")
            with mock.patch("native_lifecycle.checked_query_image", return_value=host_id), mock.patch("native_lifecycle.subprocess.run", side_effect=refused) as run:
                with self.assertRaisesRegex(RuntimeError, "docker_exit=125, reason=image_unavailable") as failure:
                    lifecycle.query_on_node("positron-120-fixture-worker", "10.244.0.7", node_image, ca, stage="wire")
                self.assertNotIn("fixed-query", str(failure.exception))
                self.assertNotIn("fixed-admin", str(failure.exception))
                self.assertNotIn("/private/path", str(failure.exception))
                self.assertEqual(run.call_count, 2, "failed start still cleans only its owned client")
            for elapsed in [30, 36]:
                clock = [100.0]
                def inspected(*args, **options):
                    clock[0] += elapsed
                    return host_id
                with self.subTest(inspection_seconds=elapsed), mock.patch("native_lifecycle.time.monotonic", side_effect=lambda: clock[0]), mock.patch("native_lifecycle.checked_query_image", side_effect=inspected), mock.patch("native_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 0, response, b"")) as run:
                    if elapsed < 35:
                        self.assertEqual(lifecycle.query_on_node("positron-120-fixture-worker", "10.244.0.7", node_image, ca, stage="wire"), "b" * 64)
                        self.assertLessEqual(run.call_args_list[0].kwargs["timeout"], 5)
                    else:
                        with self.assertRaises(TimeoutError):
                            lifecycle.query_on_node("positron-120-fixture-worker", "10.244.0.7", node_image, ca, stage="wire")
                        run.assert_not_called()

    def test_query_image_binding_follows_the_retained_index_to_its_actual_manifest(self):
        import hashlib
        import json
        import os
        from unittest import mock
        from native_lifecycle import checked_query_image
        fixtures = Path(__file__).with_name("fixtures")
        encoded = (fixtures / "runtime-index.json").read_bytes()
        manifest = (fixtures / "runtime-manifest.json").read_bytes()
        manifest_id = "sha256:" + hashlib.sha256(manifest).hexdigest()
        config_id = json.loads(manifest)["config"]["digest"]
        node_image = "ghcr.io/vicotrbb/positron@sha256:" + hashlib.sha256(encoded).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index = root / "runtime-image-index.json"
            index.write_bytes(encoded)
            (root / ("query-manifest-" + manifest_id.removeprefix("sha256:") + ".json")).write_bytes(manifest)
            for host_id in [config_id, manifest_id]:
                with self.subTest(host_id=host_id), mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": host_id, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps([host_id, "linux", "arm64"]).encode(), b"")):
                    self.assertEqual(checked_query_image(node_image, timeout=5), host_id)
            root_id = node_image.split("@", 1)[1]
            with mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": root_id, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "does not match"):
                    checked_query_image(node_image, timeout=5)
                run.assert_not_called()
            bad_indexes = []
            for change in ["size", "media", "platform", "ambiguous"]:
                value = json.loads(encoded)
                selected = value["manifests"][0]
                if change == "size": selected["size"] += 1
                elif change == "media": selected["mediaType"] = "application/vnd.docker.distribution.manifest.v2+json"
                elif change == "platform": selected["platform"] = {"os": "linux", "architecture": "amd64"}
                else: value["manifests"].append(dict(selected))
                bad_indexes.append(value)
            for value in bad_indexes:
                data = json.dumps(value).encode()
                index.write_bytes(data)
                node = "ghcr.io/vicotrbb/positron@sha256:" + hashlib.sha256(data).hexdigest()
                with self.subTest(index=value), mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": config_id, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run") as run:
                    with self.assertRaises(ValueError): checked_query_image(node, timeout=5)
                    run.assert_not_called()
            index.write_bytes(encoded)
            child = root / ("query-manifest-" + manifest_id.removeprefix("sha256:") + ".json")
            child.write_bytes(manifest + b" ")
            with mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": config_id, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run") as run:
                with self.assertRaisesRegex(ValueError, "binding changed"):
                    checked_query_image(node_image, timeout=5)
                run.assert_not_called()

    def test_query_image_binding_accepts_both_docker_stores_and_refuses_substitution(self):
        import hashlib
        import json
        import os
        from unittest import mock
        from native_lifecycle import checked_query_image
        config_id = "sha256:" + "c" * 64
        encoded = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": config_id, "mediaType": "application/vnd.oci.image.config.v1+json", "size": 123}}).encode()
        manifest_id = "sha256:" + hashlib.sha256(encoded).hexdigest()
        node_image = "ghcr.io/vicotrbb/positron@" + manifest_id
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / "runtime-index.json"
            index.write_bytes(encoded)
            for host_id in [config_id, manifest_id]:
                with self.subTest(store_id=host_id), mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": host_id, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps([host_id, "linux", "arm64"]).encode(), b"")) as run:
                    self.assertEqual(checked_query_image(node_image, timeout=5), host_id)
                    self.assertEqual(run.call_args.args[0][-1], host_id)
                    self.assertEqual(run.call_args.kwargs["timeout"], 5)
            for node, host, data in [
                (manifest_id, config_id, encoded),
                (node_image, "mutable:latest", encoded),
                (node_image, "sha256:" + "d" * 64, encoded),
                (node_image, config_id, encoded + b" "),
                (node_image, config_id, b" " * 1_048_577),
            ]:
                index.write_bytes(data)
                with self.subTest(node=node, host=host), mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": host, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run") as run:
                    with self.assertRaises(ValueError): checked_query_image(node, timeout=5)
                    run.assert_not_called()
            index.write_bytes(encoded)
            with mock.patch.dict(os.environ, {"POSITRON_TEST_HELM_QUERY_IMAGE": config_id, "POSITRON_TEST_HELM_INDEX_FILE": str(index), "POSITRON_TEST_HELM_ARCHITECTURE": "arm64"}), mock.patch("native_lifecycle.subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(["different-id", "linux", "arm64"]).encode(), b"")):
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    checked_query_image(node_image, timeout=5)

    def test_native_fixture_helper_uses_the_callers_numeric_identity_and_keeps_exports_private(self):
        import os
        import stat
        from unittest import mock
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            def run(command, **options):
                if command[0] == "docker":
                    calls.append((command,options))
                    fixture = root / "fixture"
                    (fixture / "positron.toml").write_text('[release.installation]\nchannel="fixture"\n')
                    export = fixture / "export"
                    export.mkdir(mode=0o700)
                    for name in ["recipient","candidate-digest"]:
                        (export / name).write_text("fixed-public-value")
                        (export / name).chmod(0o600)
                return subprocess.CompletedProcess(command,0,b"",b"")
            lifecycle = NativeLifecycle(self, root, lambda *a, **k: subprocess.CompletedProcess([],0,b"",b""), lambda value: None, lambda count: None, "pod", [], None, {"storageClass":"standard"}, b"administrator_secret=fixed-admin query_secret=fixed-query")
            environment = {"POSITRON_TEST_HELM_FIXTURE_HELPER":"/checked/helper","POSITRON_TEST_HELM_CURRENT_BINARY":"/checked/current","POSITRON_TEST_UPGRADE_BINARY":"/checked/candidate","POSITRON_TEST_SOURCE_COMMIT":"a"*40,"POSITRON_TEST_CANDIDATE_COMMIT":"b"*40,"POSITRON_TEST_HELM_FIXTURE_BUILDER":"checked-builder"}
            with mock.patch.dict(os.environ,environment), mock.patch("native_lifecycle.subprocess.run",side_effect=run), mock.patch.object(lifecycle,"install"):
                lifecycle.prepare("schema_version=1")
            command,options = calls[0]
            self.assertIn("--user",command)
            self.assertEqual(command[command.index("--user")+1],f"{os.getuid()}:{os.getgid()}")
            self.assertEqual(options["input"],b"fixed-query")
            self.assertNotIn("fixed-query"," ".join(command))
            self.assertEqual(stat.S_IMODE((root / "fixture/export").stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((root / "fixture/export/recipient").stat().st_mode),0o600)

    def test_explicit_owned_kind_and_k3d_targets_keep_the_selected_storage_class(self):
        for context in ["kind-positron-120-123", "k3d-positron-120-k3s-123"]:
            self.assertEqual(owned_storage_class(context, "qualified-class", context), "qualified-class")
        for context in ["", "default", "kind-production", "k3d-production", "kind-positron-120-"]:
            with self.assertRaises(ValueError): owned_storage_class(context, "qualified-class", context)
        with self.assertRaises(ValueError): owned_storage_class("kind-positron-120-123", "", "kind-positron-120-123")
        for expected in ["", "kind-positron-120-other"]:
            with self.assertRaises(ValueError): owned_storage_class("kind-positron-120-123", "qualified-class", expected)

    def test_private_inspection_refuses_live_owner_before_mounting_any_claim(self):
        for replicas in [1, 0]:
            applied = []
            def kube(*args, **kwargs):
                if args[:2] == ("get", "statefulset"): value = {"spec": {"replicas": replicas}}
                elif args[:2] == ("get", "pods"): value = {"items": [{"metadata": {"uid": "live-owner"}}]}
                else: raise AssertionError("unexpected operation before owner is stopped")
                import json
                return subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b"")
            with self.assertRaisesRegex(AssertionError, "owner"):
                inspect_private_modes(self, kube, applied.append, "native-positron")
            self.assertEqual(applied, [])

    def test_projection_that_arrives_after_a_request_still_reloads_before_the_original_deadline(self):
        calls = []
        def kube(*args, **kwargs):
            calls.append(args)
            self.assertEqual(args[:2], ("exec", "-i"))
            self.assertIn("--credential-stdin", args)
            self.assertEqual(kwargs["data"], b"reload-test-administrator")
            self.assertNotIn("reload-test-administrator", args)
            return subprocess.CompletedProcess([], 0, b"status=reload_requested\n", b"")
        def identity(_timeout): return b"new" if len(calls) >= 2 else b"old"
        reload_projected_identity(kube, "native-positron-0", identity, b"new", b"reload-test-administrator", timeout=2)
        self.assertGreaterEqual(len(calls), 2)

    def test_invalid_projection_requires_a_fresh_native_listener_rejection(self):
        requests = []
        def kube(*args, **kwargs):
            if args[0] == "logs":
                body = b'{"event":"configuration_reload_rejected","category":"listener_unavailable"}\n' if len(requests) >= 2 else b""
            else:
                requests.append(args)
                body = b"status=reload_requested\n"
            return subprocess.CompletedProcess([], 0, body, b"")
        reload_projected_identity(kube, "native-positron-0", lambda _timeout: b"retained", b"retained", b"reload-test-administrator", timeout=2, rejection_baseline=0)
        self.assertEqual(len(requests), 2)
        def unchanged(*args, **kwargs): return subprocess.CompletedProcess([], 0, b"" if args[0] == "logs" else b"status=reload_requested\n", b"")
        with self.assertRaises(AssertionError): reload_projected_identity(unchanged, "native-positron-0", lambda _timeout: b"retained", b"retained", b"reload-test-administrator", timeout=0.01, rejection_baseline=0)
        def old_event(*args, **kwargs):
            body = b'{"event":"configuration_reload_rejected","category":"listener_unavailable"}\n' if args[0] == "logs" else b"status=reload_requested\n"
            return subprocess.CompletedProcess([], 0, body, b"")
        with self.assertRaises(AssertionError): reload_projected_identity(old_event, "native-positron-0", lambda _timeout: b"retained", b"retained", b"reload-test-administrator", timeout=0.01, rejection_baseline=1)

    def test_retained_claims_allow_only_exact_fresh_target_names_and_preserve_every_original_uid(self):
        before = {"native-data": "source-data-id", "native-secrets": "source-key-id"}
        after = dict(before, **{"restored-data": "fresh-data-id", "restored-secrets": "fresh-key-id"})
        assert_retained_claims(self, before, after, ["restored-data", "restored-secrets"])
        for changed in [dict(after, unexpected="other-id"), dict(after, **{"native-data": "wrong-id"}),
                        {key: value for key, value in after.items() if key != "native-secrets"},
                        dict(after, **{"restored-data": "source-data-id"})]:
            with self.assertRaises(AssertionError):
                assert_retained_claims(self, before, changed, ["restored-data", "restored-secrets"])

    def test_native_exit_two_remains_resumable_without_reflecting_stdin_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def kube(*args, **kwargs):
                calls.append((args, kwargs))
                return subprocess.CompletedProcess([], 2, b"operation_id=accepted-operation\n", b"positron: operation outcome remains unknown; inspect the same operation ID before retrying\ncommand terminated with exit code 2\n")
            lifecycle = NativeLifecycle(self, Path(directory), kube, None, None, "native-positron-0", [], None, {}, b"administrator_secret=test-admin query_secret=test-query")
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                lifecycle.online("backup", "wait", "--operation-id", "accepted-operation", "--wait-seconds", "30")
            self.assertEqual(failure.exception.returncode, 2)
            self.assertEqual(failure.exception.stdout, b"operation_id=accepted-operation\n")
            self.assertEqual(failure.exception.stderr, b"positron: operation outcome remains unknown; inspect the same operation ID before retrying\n")
            self.assertNotIn("test-admin", str(failure.exception))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1]["data"], b"test-admin")

    def test_native_success_and_nonresumable_refusal_are_preserved(self):
        for code, output, error in [(0, b"status=succeeded\n", b""), (3, b"", b"positron: native permission denied\n")]:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                lifecycle = NativeLifecycle(self, Path(directory), lambda *args, **kwargs: subprocess.CompletedProcess([], code, output, error), None, None, "pod", [], None, {}, b"administrator_secret=test-admin query_secret=test-query")
                if code == 0:
                    self.assertEqual(lifecycle.online("repository", "status"), b"status=succeeded\n")
                else:
                    with self.assertRaises(subprocess.CalledProcessError) as failure:
                        lifecycle.online("repository", "status")
                    self.assertEqual(failure.exception.stderr, b"positron: native permission denied\n")
                    self.assertEqual(failure.exception.returncode, 3)


if __name__ == "__main__": unittest.main()
