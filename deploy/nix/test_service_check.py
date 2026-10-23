"""Regressions for the VM's bounded public ingest acknowledgment flow."""
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
import urllib.error


class IngestAcknowledgment(unittest.TestCase):
    def run_ingest(self, respond):
        self.clock = 0
        self.requests = []

        def request(value, timeout):
            self.requests.append((value.data, timeout))
            return respond(timeout)

        def sleep(seconds):
            self.clock += seconds

        with mock.patch.object(pathlib.Path, "read_text", return_value="ingest_secret=test-only\n"), \
                mock.patch.object(sys, "argv", ["service-check.py", "ingest"]), \
                mock.patch("time.monotonic", side_effect=lambda: self.clock), \
                mock.patch("time.sleep", side_effect=sleep), \
                mock.patch("urllib.request.urlopen", side_effect=request):
            runpy.run_path(str(pathlib.Path(__file__).with_name("service-check.py")))

    @staticmethod
    def accepted():
        return contextlib.nullcontext(types.SimpleNamespace(status=200))

    @staticmethod
    def rejected(code=429, message="OTLP Logs ingest capacity is unavailable", retry="1"):
        return urllib.error.HTTPError("http://localhost/v1/logs", code, "refused",
                                      {"Retry-After": retry},
                                      io.BytesIO(json.dumps({"code": 14, "message": message}).encode()))

    def test_waits_for_ack_inside_existing_thirty_second_budget(self):
        def response(timeout):
            if timeout < 6:
                raise TimeoutError("response arrives after six seconds")
            self.clock += 6
            return self.accepted()
        self.run_ingest(response)
        self.assertEqual(len(self.requests), 1)
        self.assertLessEqual(self.requests[0][1], 30)

    def test_timeout_and_ambiguous_response_never_replay(self):
        for failure in [TimeoutError("unknown acknowledgment"), self.rejected(503)]:
            with self.subTest(failure=type(failure).__name__):
                def response(_):
                    raise failure
                with self.assertRaises((TimeoutError, RuntimeError)):
                    self.run_ingest(response)
                self.assertEqual(len(self.requests), 1)

    def test_only_exact_capacity_refusal_retries_identical_bytes(self):
        def response(_):
            if len(self.requests) == 1:
                raise self.rejected()
            return self.accepted()
        self.run_ingest(response)
        self.assertEqual([item[1] for item in self.requests], [30, 29])
        self.assertEqual(self.requests[0][0], self.requests[1][0])
        for failure in [self.rejected(message="different refusal"), self.rejected(retry="2")]:
            with self.subTest(failure=failure.headers):
                def response(_):
                    raise failure
                with self.assertRaises(RuntimeError):
                    self.run_ingest(response)
                self.assertEqual(len(self.requests), 1)

    def test_backoff_cannot_start_an_attempt_after_the_original_deadline(self):
        def response(_):
            if len(self.requests) > 1:
                return self.accepted()
            self.clock = 29.5
            raise self.rejected()
        with self.assertRaises(RuntimeError):
            self.run_ingest(response)
        self.assertEqual(len(self.requests), 1)


class QueryCompletion(unittest.TestCase):
    @staticmethod
    def response(state):
        # Mock the captured CLI output shape, not the API's response validator.
        return {"events": [
            {"batch": {"rows": [{"cells": [{"nativeValue": {"textValue": "nix-retained-117"}}]}]}},
            {"terminal": {"state": state}},
        ]}

    def run_query(self, output):
        result = types.SimpleNamespace(returncode=0, stdout=output, stderr=b"")
        with mock.patch.object(pathlib.Path, "read_text", return_value="query_secret=test-only\n"), \
                mock.patch.object(pathlib.Path, "write_text"), \
                mock.patch.object(sys, "argv", ["service-check.py", "query"]), \
                mock.patch("subprocess.run", return_value=result) as execute:
            try:
                runpy.run_path(str(pathlib.Path(__file__).with_name("service-check.py")))
            finally:
                self.assertEqual(execute.call_count, 1)

    def test_accepts_complete_and_refuses_incomplete_with_the_same_retained_record(self):
        self.run_query(json.dumps(self.response("complete")).encode())
        with self.assertRaisesRegex(AssertionError, "query did not complete"):
            self.run_query(json.dumps(self.response("incomplete")).encode())

    def test_missing_unknown_or_malformed_terminal_fails_closed(self):
        missing = self.response("complete")
        del missing["events"][-1]["terminal"]
        responses = [json.dumps(missing).encode(),
                     json.dumps(self.response("future")).encode(),
                     b'{"events": [{"marker": "nix-retained-117", "state": "complete"}']
        for output in responses:
            with self.subTest(output_kind="invalid response"):
                with self.assertRaises((AssertionError, KeyError, json.JSONDecodeError)):
                    self.run_query(output)


class BackupOutcomeKnowledge(unittest.TestCase):
    def run_backup(self, responses):
        self.commands = []
        self.saved = []

        def execute(command, **options):
            self.commands.append(command)
            self.assertNotIn("test-only", command)
            action = command[1:3]
            if action == ["repository", "status"]:
                output = "catalog_generation=1"
            elif action == ["repository", "init"]:
                output = "operation_id=repository"
            elif action == ["repository", "wait"]:
                output = "operation_id=repository status=succeeded"
            elif action == ["backup", "create"]:
                output = "operation_id=snapshot"
            elif action == ["backup", "wait"]:
                response = responses.pop(0)
                if isinstance(response, BaseException):
                    raise response
                return response
            else:
                raise AssertionError("unexpected lifecycle command")
            return types.SimpleNamespace(returncode=0, stdout=output.encode(), stderr=b"")

        def read(path):
            return "administrator_secret=test-only" if path.name == "positron-claim" else "{}"

        def write(path, document):
            self.saved.append(json.loads(document))

        with mock.patch.object(pathlib.Path, "read_text", autospec=True, side_effect=read), \
                mock.patch.object(pathlib.Path, "write_text", autospec=True, side_effect=write), \
                mock.patch.object(sys, "argv", ["lifecycle-check.py", "backup"]), \
                mock.patch("subprocess.run", side_effect=execute):
            runpy.run_path(str(pathlib.Path(__file__).with_name("lifecycle-check.py")))

    @staticmethod
    def outcome(status, operation="snapshot", checksum="", unknown=False):
        output = f"operation_id={operation} status={status} manifest_checksum={checksum}"
        return types.SimpleNamespace(returncode=int(unknown), stdout=output.encode(), stderr=(
            b"positron: operation outcome remains unknown; inspect the same operation ID before retrying"
            if unknown else b""))

    def test_pending_knowledge_window_continues_same_backup_until_success(self):
        self.run_backup([self.outcome("running", unknown=True),
                         self.outcome("succeeded", checksum="verified")])
        creates = [command for command in self.commands if command[1:3] == ["backup", "create"]]
        waits = [command for command in self.commands if command[1:3] == ["backup", "wait"]]
        self.assertEqual(len(creates), 1)
        self.assertEqual(len(waits), 2)
        self.assertEqual(waits[0], waits[1])
        self.assertEqual(waits[0][-4:], ["--operation-id", "snapshot", "--wait-seconds", "60"])
        self.assertEqual(self.saved[-1], {"snapshot": "snapshot", "checksum": "verified"})

    def test_mismatched_terminal_or_transport_outcomes_never_repeat_admission(self):
        unavailable = types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"HTTP 503")
        failures = [self.outcome("running", operation="other", unknown=True),
                    self.outcome("succeeded", operation="other", checksum="verified"),
                    self.outcome("failed"), self.outcome("succeeded"), unavailable,
                    subprocess.TimeoutExpired("positron backup wait", 180)]
        for response in failures:
            with self.subTest(response=response):
                with self.assertRaises((RuntimeError, AssertionError, subprocess.TimeoutExpired)):
                    self.run_backup([response])
                self.assertEqual(sum(command[1:3] == ["backup", "create"]
                                     for command in self.commands), 1)
                self.assertEqual(sum(command[1:3] == ["backup", "wait"]
                                     for command in self.commands), 1)
                self.assertEqual(self.saved, [])


class QueryOwnerDiagnostics(unittest.TestCase):
    entry = b"positron-query-owner-probe stage=entry elapsed_us=0 pid=123"
    returned = b"positron-query-owner-probe stage=return elapsed_us=5001000 pid=123 entry_written=true"

    def run_query(self, queries, journal):
        commands = []
        output = io.StringIO()
        clock = [0]

        def execute(command, **options):
            commands.append((command, options))
            if command[0] == "positron":
                return queries.pop(0)
            self.assertEqual(command[0], "journalctl")
            if isinstance(journal, BaseException):
                raise journal
            return journal

        def sleep(seconds):
            clock[0] += seconds

        failure = None
        with mock.patch.object(pathlib.Path, "read_text", return_value="query_secret=test-only\n"), \
                mock.patch.object(pathlib.Path, "write_text"), \
                mock.patch.object(sys, "argv", ["service-check.py", "query"]), \
                mock.patch("subprocess.run", side_effect=execute), \
                mock.patch("time.monotonic", side_effect=lambda: clock[0]), \
                mock.patch("time.sleep", side_effect=sleep), contextlib.redirect_stderr(output):
            try:
                runpy.run_path(str(pathlib.Path(__file__).with_name("service-check.py")))
            except RuntimeError as error:
                failure = str(error)
        return failure, output.getvalue(), commands

    @staticmethod
    def result(code=2, stdout=b"", stderr=b"positron: query transport or response unavailable"):
        return types.SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    def test_forwards_only_two_closed_records_and_preserves_original_failure(self):
        failure, output, commands = self.run_query([self.result()],
            self.result(0, self.entry + b"\n" + self.returned + b"\n"))
        self.assertEqual(output.splitlines(), [self.entry.decode(), self.returned.decode()])
        self.assertEqual(failure, "public query failed: code=transport returncode=2 attempt=1 elapsed_ms=0")
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][1]["timeout"], 10)
        self.assertEqual(commands[1][1]["timeout"], 3)
        self.assertIn("--lines=2", commands[1][0])

    def test_excess_unknown_and_raw_canary_records_never_escape(self):
        for records in [self.entry + b"\n" + self.returned + b"\n" + self.entry,
                        b"secret-canary", self.entry + b" secret-canary", b""]:
            with self.subTest(kind="untrusted journal output"):
                failure, output, _ = self.run_query([self.result()], self.result(0, records))
                self.assertNotIn("secret-canary", output)
                self.assertEqual(output, "positron-query-owner-probe collection=unavailable\n")
                self.assertIn("code=transport", failure)

    def test_timeout_oserror_and_journal_failure_remain_unavailable(self):
        for journal in [subprocess.TimeoutExpired("journalctl", 3), OSError("secret-canary"),
                        self.result(1, self.entry, b"secret-canary")]:
            with self.subTest(kind=type(journal).__name__):
                failure, output, _ = self.run_query([self.result()], journal)
                self.assertNotIn("secret-canary", output)
                self.assertEqual(output, "positron-query-owner-probe collection=unavailable\n")
                self.assertIn("code=transport", failure)

    def test_capacity_retries_identical_query_and_success_never_collects(self):
        complete = self.result(0, json.dumps(QueryCompletion.response("complete")).encode(), b"")
        failure, output, commands = self.run_query([
            self.result(stderr=b"positron: query capacity unavailable; retry after backoff"), complete],
            OSError("journal must not run"))
        self.assertIsNone(failure)
        self.assertEqual(output, "")
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0], commands[1])
