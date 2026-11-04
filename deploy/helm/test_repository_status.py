"""Read-only repository inspection honors only exact native capacity refusals."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from native_lifecycle import NativeLifecycle

CAPACITY = b"positron: capacity unavailable; retry the same idempotent request\n"


class RepositoryStatus(unittest.TestCase):
    def test_capacity_status_reuses_request_credential_and_remaining_timeout(self):
        clock, calls = [0.0], []
        def kube(*args, **kwargs):
            calls.append((args, kwargs))
            clock[0] += 0.25
            return subprocess.CompletedProcess([], 2, b"", CAPACITY) if len(calls) == 1 else subprocess.CompletedProcess([], 0, b"catalog_generation=7\n", b"")
        with tempfile.TemporaryDirectory() as directory, patch("native_lifecycle.time.monotonic", side_effect=lambda: clock[0]), patch("native_lifecycle.time.sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            lifecycle = NativeLifecycle(self, Path(directory), kube, None, None, "pod", [], None, {}, b"administrator_secret=test-admin query_secret=test-query")
            self.assertEqual(lifecycle.online("repository", "status", timeout=3), b"catalog_generation=7\n")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], calls[1][0])
        self.assertEqual([options["data"] for _, options in calls], [b"test-admin", b"test-admin"])
        self.assertEqual([options["timeout"] for _, options in calls], [3, 1.75])
        self.assertEqual(clock[0], 1.5)

    def test_repeated_capacity_cannot_reset_or_outlive_the_original_window(self):
        for oversleep in [False, True]:
            clock, calls = [0.0], []
            def kube(*args, **kwargs):
                calls.append((args, kwargs))
                return subprocess.CompletedProcess([], 2, b"", CAPACITY)
            with self.subTest(oversleep=oversleep), tempfile.TemporaryDirectory() as directory, patch("native_lifecycle.time.monotonic", side_effect=lambda: clock[0]), patch("native_lifecycle.time.sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds + (3 if oversleep else 0))):
                lifecycle = NativeLifecycle(self, Path(directory), kube, None, None, "pod", [], None, {}, b"administrator_secret=test-admin query_secret=test-query")
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    lifecycle.online("repository", "status", timeout=2.5)
                self.assertEqual(caught.exception.returncode, 2)
                self.assertEqual(caught.exception.stdout, b"")
                self.assertEqual(caught.exception.stderr, CAPACITY)
                self.assertEqual([options["timeout"] for _, options in calls], [2.5] if oversleep else [2.5, 1.5, 0.5])
                self.assertEqual(clock[0], 4 if oversleep else 2)

    def test_only_empty_exact_capacity_status_is_reconciled(self):
        cases = [("repository", "init", 2, b"", CAPACITY), ("repository", "cancel", 2, b"", CAPACITY),
                 ("repository", "lookup", 2, b"", CAPACITY), ("backup", "status", 2, b"", CAPACITY),
                 ("repository", "status", 1, b"", CAPACITY), ("repository", "status", 2, b"partial", CAPACITY),
                 ("repository", "status", 2, b"", CAPACITY + b"untrusted trailer\n"),
                 ("repository", "status", 2, b"", b"positron: system administration authentication rejected\n"),
                 ("repository", "status", 2, b"", b"positron: stale resource generation; inspect current state before retrying\n"),
                 ("repository", "status", 2, b"", b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n")]
        for family, action, code, output, error in cases:
            calls = []
            def kube(*args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess([], code, output, error)
            with self.subTest(family=family, action=action, code=code, output=output, error=error), tempfile.TemporaryDirectory() as directory:
                lifecycle = NativeLifecycle(self, Path(directory), kube, None, None, "pod", [], None, {}, b"administrator_secret=test-admin query_secret=test-query")
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    lifecycle.online(family, action, timeout=0.1)
                self.assertEqual((caught.exception.returncode, caught.exception.stdout, caught.exception.stderr), (code, output, error))
                self.assertEqual(len(calls), 1)
        failure = subprocess.TimeoutExpired(["positron", "repository"], 1)
        with tempfile.TemporaryDirectory() as directory:
            def kube(*args, **kwargs): raise failure
            lifecycle = NativeLifecycle(self, Path(directory), kube, None, None, "pod", [], None, {}, b"administrator_secret=test-admin query_secret=test-query")
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                lifecycle.online("repository", "status")
            self.assertIs(caught.exception, failure)
