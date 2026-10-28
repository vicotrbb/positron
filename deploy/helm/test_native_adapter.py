"""The Kubernetes subprocess seam preserves native CLI outcomes for existing consumers."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from native_lifecycle import NativeLifecycle
from test_kubernetes import assert_retained_claims, owned_storage_class, inspect_private_modes, reload_projected_identity


class NativeAdapter(unittest.TestCase):
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
            return subprocess.CompletedProcess([], 0, b"status=reload_requested\n", b"")
        def identity(_timeout): return b"new" if len(calls) >= 2 else b"old"
        reload_projected_identity(kube, "native-positron-0", identity, b"new", timeout=2)
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
        reload_projected_identity(kube, "native-positron-0", lambda _timeout: b"retained", b"retained", timeout=2, rejection_baseline=0)
        self.assertEqual(len(requests), 2)
        def unchanged(*args, **kwargs): return subprocess.CompletedProcess([], 0, b"" if args[0] == "logs" else b"status=reload_requested\n", b"")
        with self.assertRaises(AssertionError): reload_projected_identity(unchanged, "native-positron-0", lambda _timeout: b"retained", b"retained", timeout=0.01, rejection_baseline=0)
        def old_event(*args, **kwargs):
            body = b'{"event":"configuration_reload_rejected","category":"listener_unavailable"}\n' if args[0] == "logs" else b"status=reload_requested\n"
            return subprocess.CompletedProcess([], 0, body, b"")
        with self.assertRaises(AssertionError): reload_projected_identity(old_event, "native-positron-0", lambda _timeout: b"retained", b"retained", timeout=0.01, rejection_baseline=1)

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
