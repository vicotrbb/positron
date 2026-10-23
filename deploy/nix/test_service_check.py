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
    returned = b"positron-query-owner-probe stage=return elapsed_us=9001000 pid=123 entry_written=true"

    def run_query(self, queries, chunks, query_elapsed=0):
        commands = []
        output = io.StringIO()
        clock = [0]
        child = mock.MagicMock()
        child.__enter__.return_value = child
        child.poll.return_value = None
        child.wait.return_value = -9

        def execute(command, **options):
            commands.append((command, options))
            clock[0] += query_elapsed
            return queries.pop(0)

        def spawn(command, **options):
            commands.append((command, options))
            if isinstance(chunks, BaseException):
                raise chunks
            return child

        def ready(readers, _writes, _errors, remaining):
            self.assertGreater(remaining, 0)
            self.assertLessEqual(remaining, 30)
            if not chunks:
                clock[0] += remaining
                return [], [], []
            clock[0] += 1
            return readers, [], []

        def read(_descriptor, count):
            self.assertLessEqual(count, 512)
            chunk = chunks.pop(0)
            if isinstance(chunk, BaseException):
                raise chunk
            self.assertLessEqual(len(chunk), count)
            return chunk

        failure = None
        with mock.patch.object(pathlib.Path, "read_text", return_value="query_secret=test-only\n"), \
                mock.patch.object(pathlib.Path, "write_text"), \
                mock.patch.object(sys, "argv", ["service-check.py", "query"]), \
                mock.patch("subprocess.run", side_effect=execute), \
                mock.patch("subprocess.Popen", side_effect=spawn), \
                mock.patch("select.select", side_effect=ready), \
                mock.patch("os.read", side_effect=read), \
                mock.patch("time.monotonic", side_effect=lambda: clock[0]), \
                mock.patch("time.sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                contextlib.redirect_stderr(output):
            try:
                runpy.run_path(str(pathlib.Path(__file__).with_name("service-check.py")))
            except RuntimeError as error:
                failure = str(error)
        if len(commands) > 1 and commands[-1][0][0] == "journalctl" and not isinstance(chunks, BaseException):
            child.kill.assert_called_once()
            child.wait.assert_called_once()
        return failure, output.getvalue(), commands

    @staticmethod
    def result(code=2, stdout=b"", stderr=b"positron: query transport or response unavailable"):
        return types.SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    def test_late_return_keeps_original_failure_elapsed_and_original_window(self):
        failure, output, commands = self.run_query([self.result()],
            [self.entry + b"\n", self.returned + b"\n"], query_elapsed=6)
        self.assertEqual(output.splitlines(), [self.entry.decode(), self.returned.decode()])
        self.assertEqual(failure, "public query failed: code=transport returncode=2 attempt=1 elapsed_ms=6000")
        self.assertEqual(commands[0][1]["timeout"], 10)
        self.assertIn("--follow", commands[1][0])
        self.assertIn("--lines=2", commands[1][0])
        self.assertEqual(commands[1][1]["stderr"], subprocess.DEVNULL)

    def test_excess_unknown_partial_and_overflow_never_escape(self):
        for records in [self.entry + b"\n" + self.returned + b"\n" + self.entry + b"\n",
                        b"secret-canary\n", self.entry, b"secret-canary".ljust(512, b"x")]:
            with self.subTest(kind="untrusted journal output"):
                failure, output, _ = self.run_query([self.result()], [records])
                self.assertNotIn("secret-canary", output)
                self.assertEqual(output, "positron-query-owner-probe collection=unavailable\n")
                self.assertIn("code=transport", failure)

    def test_entry_only_timeout_is_explicitly_incomplete(self):
        failure, output, _ = self.run_query([self.result()], [self.entry + b"\n"])
        self.assertEqual(output.splitlines(), [self.entry.decode(), "positron-query-owner-probe collection=incomplete"])
        self.assertIn("code=transport", failure)

    def test_no_records_or_spawn_error_remain_unavailable(self):
        for chunks in [[], OSError("secret-canary")]:
            with self.subTest(kind=type(chunks).__name__):
                failure, output, _ = self.run_query([self.result()], chunks)
                self.assertNotIn("secret-canary", output)
                self.assertEqual(output, "positron-query-owner-probe collection=unavailable\n")
                self.assertIn("code=transport", failure)

    def test_read_error_reaps_acquired_child_and_preserves_original_failure(self):
        failure, output, _ = self.run_query([self.result()], [OSError("secret-canary")])
        self.assertNotIn("secret-canary", output)
        self.assertEqual(output, "positron-query-owner-probe collection=unavailable\n")
        self.assertEqual(failure, "public query failed: code=transport returncode=2 attempt=1 elapsed_ms=0")

    def test_expired_original_window_never_starts_collector(self):
        failure, output, commands = self.run_query([self.result()], [], query_elapsed=30)
        self.assertEqual(len(commands), 1)
        self.assertEqual(output, "positron-query-owner-probe collection=unavailable\n")
        self.assertIn("elapsed_ms=30000", failure)

    def test_capacity_retries_identical_query_and_success_never_collects(self):
        complete = self.result(0, json.dumps(QueryCompletion.response("complete")).encode(), b"")
        failure, output, commands = self.run_query([
            self.result(stderr=b"positron: query capacity unavailable; retry after backoff"), complete],
            OSError("journal must not run"))
        self.assertIsNone(failure)
        self.assertEqual(output, "")
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0], commands[1])
