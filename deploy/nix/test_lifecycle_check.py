"""Closed diagnostics for the existing bounded offline upgrade journey."""
import contextlib
import io
import json
import pathlib
import runpy
import subprocess
import sys
import types
import unittest
from unittest import mock


class SnapshotObservation(unittest.TestCase):
    operation = "0123456789abcdef0123456789abcdef"

    def invoke(self, receipt=None, failure=None, stderr=None, stop_after_advance=False):
        self.clock = 0
        self.commands = []
        output = io.StringIO()

        def read(path, *args, **kwargs):
            if str(path).endswith("positron-claim"):
                return "administrator_secret=protected-secret"
            return json.dumps({"upgrade": self.operation})

        def execute(command, **options):
            self.commands.append((command, options))
            if stop_after_advance and len(self.commands) > 1:
                raise RuntimeError("after publication boundary")
            self.clock += 65
            if failure is not None:
                raise failure
            text = receipt or (f"operation_id={self.operation} status=Running "
                               "stage=Some(Snapshot) revision=4 rollback_available=false")
            return types.SimpleNamespace(returncode=2 if stderr else 0,
                                         stdout=text if isinstance(text, bytes) else text.encode(),
                                         stderr=stderr or b"")

        path = pathlib.Path(__file__).with_name("lifecycle-check.py")
        with mock.patch.object(pathlib.Path, "read_text", read), \
                mock.patch.object(sys, "argv", [str(path), "publish-upgrade"]), \
                mock.patch("time.monotonic", side_effect=lambda: self.clock), \
                mock.patch("subprocess.run", side_effect=execute), \
                contextlib.redirect_stdout(output):
            with self.assertRaises(RuntimeError) as raised:
                runpy.run_path(str(path))
        self.error = str(raised.exception)
        self.output = output.getvalue()
        return [json.loads(line) for line in self.output.splitlines()]

    def test_each_advance_and_original_deadline_emit_only_closed_public_facts(self):
        records = self.invoke()
        self.assertEqual([item["outcome"] for item in records],
                         ["advanced", "advanced", "advanced", "deadline"])
        self.assertEqual([item["elapsed_ms"] for item in records], [65000, 130000, 195000, 195000])
        for record in records:
            self.assertEqual(record["operation_id"], self.operation)
            self.assertEqual(record["status"], "Running")
            self.assertEqual(record["stage"], "Some(Snapshot)")
            self.assertEqual(record["revision"], 4)
            self.assertIs(record["rollback_available"], False)
            self.assertEqual(record["error"], "none")
        self.assertEqual(self.error, "authenticated upgrade snapshot did not complete")
        self.assertEqual(len(self.commands), 3)
        for command, options in self.commands:
            self.assertEqual(command[-2:], ["--seconds", "60"])
            self.assertEqual(options["timeout"], 180)
        self.assertNotIn("protected", self.output)

    def test_untrusted_receipt_fields_are_not_printed(self):
        records = self.invoke("operation_id=protected-secret status=protected-secret "
                              "stage=Some(protected-secret) revision=protected-secret "
                              "rollback_available=protected-secret extra=protected-secret "
                              "snapshot=protected-secret snapshot_kind=protected-secret "
                              "snapshot_phase=protected-secret snapshot_status=protected-secret "
                              "snapshot_revision=protected-secret snapshot_checkpoint_sequence=protected-secret "
                              "snapshot_checkpoint_sha256=protected-secret snapshot_progress_percent=101")
        self.assertEqual(len(records), 4)
        for record in records:
            self.assertFalse(set(record) & {"operation_id", "status", "stage", "revision", "rollback_available", "snapshot", "snapshot_kind", "snapshot_phase", "snapshot_status", "snapshot_revision", "snapshot_checkpoint_sequence", "snapshot_checkpoint_sha256", "snapshot_progress_percent"})
        self.assertNotIn("protected", self.output)

    def test_child_progress_keeps_only_closed_fields_and_checkpoint_digest(self):
        receipt = (f"operation_id={self.operation} status=Running stage=Some(Snapshot) revision=4 "
                   "snapshot=present snapshot_kind=BackupSnapshot snapshot_phase=BackupTransfer "
                   "snapshot_status=Running snapshot_revision=7 snapshot_progress_percent=40 "
                   "snapshot_checkpoint_sequence=3 snapshot_checkpoint_sha256=" + "ab" * 32 +
                   " verification=absent snapshot_payload=protected-secret")
        for record in self.invoke(receipt):
            self.assertEqual(record["snapshot_revision"], 7)
            self.assertEqual(record["snapshot_checkpoint_sequence"], 3)
            self.assertEqual(record["snapshot_checkpoint_sha256"], "ab" * 32)
            self.assertEqual(record["verification"], "absent")
        self.assertNotIn("protected", self.output)

    def test_command_timeout_is_closed_and_does_not_retry(self):
        records = self.invoke(failure=subprocess.TimeoutExpired(["protected-secret"], 180))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["outcome"], "failed")
        self.assertEqual(records[0]["error"], "command_timeout")
        self.assertEqual(len(self.commands), 1)
        self.assertNotIn("protected", self.output + self.error)

    def test_known_and_unknown_command_errors_never_print_receipts_or_stderr(self):
        cases = [(b"positron: upgrade remains resumable; inspect and retry after trusted time or capacity recovers", "resumable"),
                 (b"positron: upgrade recovery state or exclusive volume ownership unavailable", "unsafe_state"),
                 (b"protected-secret", "other")]
        for stderr, category in cases:
            with self.subTest(category=category):
                records = self.invoke(receipt="protected-secret", stderr=stderr)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["error"], category)
                self.assertEqual(records[0]["outcome"], "failed")
                self.assertEqual(len(self.commands), 1)
                self.assertNotIn("protected", self.output + self.error)

    def test_invalid_receipt_encoding_is_closed(self):
        records = self.invoke(receipt=b"\xffprotected-secret")
        self.assertEqual(records[0]["error"], "invalid_receipt")
        self.assertEqual(len(self.commands), 1)
        self.assertNotIn("protected", self.output + self.error)

    def test_publishing_still_leaves_the_loop_before_restore_reference(self):
        records = self.invoke(receipt=f"operation_id={self.operation} status=Running "
                              "stage=Some(Publishing) revision=5 rollback_available=true",
                              stop_after_advance=True)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["stage"], "Some(Publishing)")
        self.assertIs(records[0]["rollback_available"], True)
        self.assertEqual(self.error, "after publication boundary")
        self.assertIn("restore-reference", self.commands[1][0])
