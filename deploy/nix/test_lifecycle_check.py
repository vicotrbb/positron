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

    def invoke(self, receipt=None, failure=None, stderr=None, stop_after_advance=False,
               publishing_after=None):
        self.clock = 0
        self.commands = []
        output = io.StringIO()

        def read(path, *args, **kwargs):
            if str(path).endswith("positron-claim"):
                return "administrator_secret=protected-secret"
            return json.dumps({"upgrade": self.operation})

        def execute(command, **options):
            self.commands.append((command, options))
            if stop_after_advance and len(self.commands) > (publishing_after or 1):
                raise RuntimeError("after publication boundary")
            self.clock += 65
            if failure is not None:
                raise failure
            text = receipt or (f"operation_id={self.operation} status=Running "
                               "stage=Some(Snapshot) revision=4 rollback_available=false")
            if publishing_after:
                text += (f" snapshot=present snapshot_kind=BackupSnapshot snapshot_checkpoint_sequence={len(self.commands) * 50}"
                         " verification=present verification_kind=BackupVerification"
                         f" verification_checkpoint_sequence={max(0, len(self.commands) - 2)}")
            if publishing_after == len(self.commands):
                text = (f"operation_id={self.operation} status=Running "
                        "stage=Some(Publishing) revision=5 rollback_available=false")
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

    def test_progressive_snapshot_and_verification_can_publish_after_three_minutes(self):
        records = self.invoke(publishing_after=4, stop_after_advance=True)
        self.assertEqual([record["outcome"] for record in records], ["advanced"] * 4)
        self.assertEqual([record["snapshot_checkpoint_sequence"] for record in records[:3]], [50, 100, 150])
        self.assertEqual(records[2]["verification_checkpoint_sequence"], 1)
        self.assertEqual(records[-1]["stage"], "Some(Publishing)")
        self.assertEqual(records[-1]["elapsed_ms"], 260000)
        self.assertEqual(self.error, "after publication boundary")
        self.assertEqual(len(self.commands), 5)
        for command, options in self.commands[:4]:
            self.assertEqual(command[-2:], ["--seconds", "60"])
            self.assertEqual(options["timeout"], 180)

    def test_stalled_snapshot_fails_at_the_finite_journey_deadline_with_closed_facts(self):
        records = self.invoke()
        self.assertEqual([item["outcome"] for item in records],
                         ["advanced"] * 10 + ["deadline"])
        self.assertEqual([item["elapsed_ms"] for item in records], [65000 * turn for turn in range(1, 11)] + [650000])
        for record in records:
            self.assertEqual(record["operation_id"], self.operation)
            self.assertEqual(record["status"], "Running")
            self.assertEqual(record["stage"], "Some(Snapshot)")
            self.assertEqual(record["revision"], 4)
            self.assertIs(record["rollback_available"], False)
            self.assertEqual(record["error"], "none")
        self.assertEqual(self.error, "authenticated upgrade snapshot did not complete")
        self.assertEqual(len(self.commands), 10)
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
        self.assertEqual(len(records), 11)
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


class SourceExitObservation(unittest.TestCase):
    operation = "0123456789abcdef0123456789abcdef"

    def invoke(self, receipt=None, returncode=0, failure=None, stop_code=0):
        self.commands = []
        output = io.StringIO()

        def read(path, *args, **kwargs):
            return ("administrator_secret=protected-secret" if path.name == "positron-claim"
                    else json.dumps({"upgrade": self.operation}))

        def execute(command, **options):
            self.commands.append((command, options))
            if len(self.commands) == 1:
                return types.SimpleNamespace(returncode=stop_code, stdout=b"protected-secret", stderr=b"protected-secret")
            if failure:
                raise failure
            return types.SimpleNamespace(returncode=returncode,
                stdout=receipt if receipt is not None else (f"operation_id={self.operation} status=Running "
                    "stage=Some(Draining) revision=3 rollback_available=false").encode(),
                stderr=b"positron: upgrade recovery state or exclusive volume ownership unavailable")

        path = pathlib.Path(__file__).with_name("lifecycle-check.py")
        with mock.patch.object(pathlib.Path, "read_text", read), \
                mock.patch.object(sys, "argv", [str(path), "source-exit-diagnostics"]), \
                mock.patch("subprocess.run", side_effect=execute), contextlib.redirect_stdout(output):
            runpy.run_path(str(path))
        self.output = output.getvalue()
        self.assertNotIn("protected", self.output)
        self.assertNotIn(self.operation, self.output)
        return json.loads(self.output)

    def test_failed_source_exit_observes_existing_offline_status_without_identifiers(self):
        self.assertEqual(self.invoke(), {"event": "upgrade_source_exit", "outcome": "observed",
            "status": "Running", "stage": "Some(Draining)", "revision": 3})
        self.assertEqual(self.commands[0][0], ["systemctl", "stop", "positron"])
        command, options = self.commands[1]
        self.assertEqual(command, ["runuser", "-u", "positron", "--", "positron", "upgrade", "offline", "status",
            "--config", "/var/lib/positron-release/positron.toml", "--operation-id", self.operation])
        self.assertEqual([options["timeout"] for _, options in self.commands], [10, 20])
        self.assertEqual(options["input"], None)

    def test_untrusted_refused_and_timed_out_observations_remain_closed(self):
        cases = [{"receipt": b"protected-secret"}, {"receipt": b"x" * 4097},
            {"receipt": (f"operation_id={self.operation} status=protected-secret stage=Some(Draining) revision=3").encode()},
            {"receipt": (f"operation_id={self.operation} status=Running stage=Some(protected-secret) revision=3").encode()},
            {"receipt": (f"operation_id={self.operation} status=Running stage=Some(Draining) revision=18446744073709551616").encode()},
            {"receipt": b"operation_id=protected-secret status=Running stage=Some(Draining) revision=3"},
            {"failure": subprocess.TimeoutExpired("protected-secret", 20)}, {"stop_code": 1}]
        for case in cases:
            with self.subTest(kind="unsafe observation"):
                self.assertEqual(self.invoke(**case), {"event": "upgrade_source_exit", "outcome": "unavailable"})
        self.assertEqual(self.invoke(returncode=2), {"event": "upgrade_source_exit", "outcome": "refused", "reason": "unsafe_state"})


class SourceExitDriverObservation(unittest.TestCase):
    def invoke(self, failed=True, collector_code=0, collector_error=False):
        import textwrap
        calls = []
        original = RuntimeError("original source exit assertion")
        script = pathlib.Path(__file__).with_name("test.nix").read_text().split("  testScript = ''\n", 1)[1].rsplit("  '';", 1)[0]
        output = io.StringIO()

        class Machine:
            def succeed(self, command):
                return ""

            def fail(self, command):
                return ""

            def wait_for_unit(self, unit):
                pass

            def wait_until_succeeds(self, command, **options):
                if command == "test $(systemctl show -p ActiveState --value positron) = inactive":
                    if options:
                        raise AssertionError("original wait deadline changed")
                    if failed:
                        raise original

            def execute(self, command):
                calls.append(command)
                if collector_error:
                    raise OSError("protected-secret")
                return collector_code, ('{"event":"upgrade_source_exit","outcome":"unavailable"}\n'
                                        if collector_code == 0 else "protected-secret")

        caught = None
        with contextlib.redirect_stdout(output):
            try:
                exec(compile(textwrap.dedent(script), "test.nix:testScript", "exec"),
                     {"machine": Machine(), "start_all": lambda: None})
            except Exception as error:
                caught = error
        self.assertIs(caught, original if failed else None)
        self.assertNotIn("protected", output.getvalue())
        return calls, output.getvalue()

    def test_original_source_exit_failure_collects_once_and_is_preserved(self):
        calls, output = self.invoke()
        self.assertEqual(calls, ["timeout --kill-after=1s 34s python /etc/positron-lifecycle-check.py source-exit-diagnostics"])
        self.assertEqual(json.loads(output), {"event": "upgrade_source_exit", "outcome": "unavailable"})

    def test_success_and_collector_failures_preserve_the_driver_outcome(self):
        self.assertEqual(self.invoke(failed=False)[0], [])
        for options in [{"collector_code": 137}, {"collector_error": True}]:
            calls, output = self.invoke(**options)
            self.assertEqual(len(calls), 1)
            self.assertEqual(json.loads(output), {"event": "upgrade_source_exit", "outcome": "unavailable"})


class UpgradedStatus(unittest.TestCase):
    capacity = b"positron: capacity unavailable; retry the same idempotent request"

    def invoke(self, responses, elapsed=None):
        self.clock = 0
        self.commands = []
        state = {"upgrade": "0123456789abcdef0123456789abcdef", "target_manifest": "manifest",
                 "source_hash": "source", "target_hash": "target"}

        def read(path, *args, **kwargs):
            if str(path).endswith("positron-claim"):
                return "administrator_secret=protected-secret"
            return json.dumps({"version": "candidate"} if str(path).endswith("inputs.json") else state)

        def execute(command, **options):
            self.commands.append((command, options))
            self.clock += (elapsed or [0] * len(responses))[len(self.commands) - 1]
            error = responses[len(self.commands) - 1]
            if isinstance(error, Exception):
                raise error
            return types.SimpleNamespace(returncode=2 if error else 0, stderr=error,
                stdout=b"status=succeeded target_version=candidate target_manifest=manifest source_artifact=source target_artifact=target")

        path = pathlib.Path(__file__).with_name("lifecycle-check.py")
        with mock.patch.object(pathlib.Path, "read_text", read), \
                mock.patch.object(sys, "argv", [str(path), "upgraded"]), \
                mock.patch("time.monotonic", side_effect=lambda: self.clock), \
                mock.patch("time.sleep", side_effect=lambda seconds: setattr(self, "clock", self.clock + seconds)), \
                mock.patch("subprocess.run", side_effect=execute):
            runpy.run_path(str(path))

    def test_capacity_refusal_retries_identical_status_with_remaining_deadline(self):
        self.invoke([self.capacity, b""], [3, 1])
        self.assertEqual(self.commands[0][0], self.commands[1][0])
        self.assertEqual(self.commands[0][1]["timeout"], 60)
        self.assertAlmostEqual(self.commands[1][1]["timeout"], 56.9)
        self.assertEqual(self.commands[0][1]["input"], b"protected-secret")

    def test_late_success_or_capacity_refusal_exhausts_original_deadline(self):
        for response in [self.capacity, b""]:
            with self.subTest(response=response):
                with self.assertRaisesRegex(RuntimeError, "attestation did not complete"):
                    self.invoke([response], [60])
                self.assertEqual(len(self.commands), 1)

    def test_other_and_noncanonical_failures_are_not_retried(self):
        for response in [b"protected-secret", self.capacity + b" extra",
                         b"positron: administration unavailable; inspect or retry the same operation"]:
            with self.subTest(response=response):
                with self.assertRaises(RuntimeError) as failure:
                    self.invoke([response])
                self.assertEqual(len(self.commands), 1)
                self.assertNotIn("protected-secret", str(failure.exception))


    def test_status_timeout_fails_closed_without_retry(self):
        with self.assertRaisesRegex(RuntimeError, "target startup attestation did not complete") as failure:
            self.invoke([subprocess.TimeoutExpired(["protected-secret"], 60,
                         output=b"protected-secret", stderr=b"protected-secret")])
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.commands[0][1]["timeout"], 60)
        self.assertNotIn("protected-secret", str(failure.exception))
