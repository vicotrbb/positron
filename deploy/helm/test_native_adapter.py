"""The Kubernetes subprocess seam preserves native CLI outcomes for existing consumers."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from native_lifecycle import NativeLifecycle
from test_kubernetes import assert_retained_claims


class NativeAdapter(unittest.TestCase):
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
