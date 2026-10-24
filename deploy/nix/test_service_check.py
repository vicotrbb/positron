"""Regressions for the VM's bounded public ingest acknowledgment flow."""
import ast
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


class QueryDeadline(unittest.TestCase):
    def run_query(self, responses, validation_elapsed=0):
        self.clock = 0
        self.commands = []
        decode = json.loads

        def validate(value):
            self.clock += validation_elapsed
            return decode(value)

        def execute(command, **options):
            self.commands.append((command, options))
            elapsed, result = responses.pop(0)
            self.clock += elapsed
            return result

        def sleep(seconds):
            self.clock += seconds

        with mock.patch.object(pathlib.Path, "read_text", return_value="query_secret=test-only\n"), \
                mock.patch.object(pathlib.Path, "write_text"), \
                mock.patch.object(sys, "argv", ["service-check.py", "query"]), \
                mock.patch("subprocess.run", side_effect=execute), \
                mock.patch("json.loads", side_effect=validate), \
                mock.patch("time.monotonic", side_effect=lambda: self.clock), \
                mock.patch("time.sleep", side_effect=sleep):
            runpy.run_path(str(pathlib.Path(__file__).with_name("service-check.py")))

    @staticmethod
    def complete():
        return types.SimpleNamespace(returncode=0,
            stdout=json.dumps(QueryCompletion.response("complete")).encode(), stderr=b"")

    @staticmethod
    def refused(message=b"positron: query capacity unavailable; retry after backoff"):
        return types.SimpleNamespace(returncode=2, stdout=b"", stderr=message)

    def test_capacity_retry_uses_only_remaining_original_thirty_seconds(self):
        self.run_query([(20, self.refused()), (1, self.complete())])
        self.assertEqual([options["timeout"] for _, options in self.commands], [30, 9])
        self.assertEqual(self.commands[0][0], self.commands[1][0])
        self.assertEqual(self.commands[0][1]["input"], self.commands[1][1]["input"])

    def test_complete_response_after_original_deadline_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "query deadline elapsed"):
            self.run_query([(31, self.complete())])
        self.assertEqual(len(self.commands), 1)

    def test_local_validation_crossing_original_deadline_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "query deadline elapsed"):
            self.run_query([(0, self.complete())], validation_elapsed=31)
        self.assertEqual(len(self.commands), 1)

    def test_capacity_backoff_cannot_begin_an_attempt_after_original_deadline(self):
        with self.assertRaises(RuntimeError):
            self.run_query([(29.5, self.refused()), (0, self.complete())])
        self.assertEqual(len(self.commands), 1)

    def test_transport_failure_never_retries(self):
        with self.assertRaisesRegex(RuntimeError, "code=transport"):
            self.run_query([(1, self.refused(b"positron: query transport or response unavailable"))])
        self.assertEqual(len(self.commands), 1)


class BackupOutcomeKnowledge(unittest.TestCase):
    def run_backup(self, responses, repository_receipt=None):
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
                output = repository_receipt or "operation_id=repository status=succeeded repository_id=11111111-1111-4111-8111-111111111111"
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


    def test_repository_wait_must_preserve_operation_and_repository_identity(self):
        for receipt in [
                "operation_id=other status=succeeded repository_id=11111111-1111-4111-8111-111111111111",
                "operation_id=repository status=succeeded repository_id=99999999-9999-4999-8999-999999999999"]:
            with self.assertRaises(AssertionError):
                self.run_backup([], repository_receipt=receipt)
            self.assertFalse(any(command[1:3] == ["backup", "create"] for command in self.commands))


class RepositoryAdmissionReconciliation(unittest.TestCase):
    operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    key = "22222222-2222-4222-8222-222222222222"
    unknown = b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n"

    def response(self, status="running", identifier=None, code=0, error=b""):
        return types.SimpleNamespace(returncode=code, stderr=error,
            stdout=f"operation_id={identifier or self.operation_id} status={status}\n".encode())

    def invoke(self, responses, kind="repository", action="init", advances=None, validation_elapsed=0):
        self.calls = []
        self.clock = 0
        self.generations = []

        def execute(command, **options):
            self.calls.append((command[:], options.copy()))
            if advances:
                self.clock += advances[len(self.calls) - 1]
            response = responses[len(self.calls) - 1]
            if isinstance(response, Exception):
                raise response
            return response

        def generation():
            self.generations.append(True)
            return str(len(self.generations) + 6)

        path = pathlib.Path(__file__).with_name("lifecycle-check.py")
        source = ast.parse(path.read_text(), filename=str(path))
        # Load the actual helper without invoking an unrelated VM lifecycle action.
        source.body = [node for node in source.body if not isinstance(node, ast.If)]
        owner = {"__file__": str(path)}
        with mock.patch.object(pathlib.Path, "read_text", return_value="administrator_secret=protected-canary\n"):
            exec(compile(source, str(path), "exec"), owner)
        owner["admit"].__globals__["generation"] = generation
        original_fields = owner["fields"]

        def validate(text):
            self.clock += validation_elapsed
            return original_fields(text)

        owner["admit"].__globals__["fields"] = validate
        with mock.patch("time.monotonic", side_effect=lambda: self.clock), \
                mock.patch("subprocess.run", side_effect=execute):
            return owner["admit"](kind, action, ["--locator", "/protected-locator", "--repository-id",
                "11111111-1111-4111-8111-111111111111", "--idempotency-key", self.key])

    def test_lost_acknowledgment_inspects_then_replays_exact_original_binding(self):
        receipt = self.invoke([self.response(code=2, error=self.unknown), self.response(), self.response()])
        self.assertEqual(receipt["operation_id"], self.operation_id)
        self.assertEqual(self.calls[0], self.calls[2])
        self.assertEqual(self.calls[1][0][1:3], ["repository", "lookup"])
        self.assertEqual(self.calls[1][0][-2:], ["--idempotency-key", self.key])
        self.assertEqual(len(self.generations), 1)

    def test_nonpositive_or_invalid_lookup_never_replays(self):
        for lookup in [self.response(code=2, error=self.unknown),
                       self.response(code=2, error=b"positron: repository operation unavailable"),
                       self.response(status="failed"),
                       self.response(status="cancelled"), self.response(identifier="malformed"),
                       types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")]:
            with self.subTest(state="unresolved"):
                with self.assertRaises(RuntimeError) as failure:
                    self.invoke([self.response(code=2, error=self.unknown), lookup])
                self.assertEqual(len(self.calls), 2)
                self.assertNotIn("protected", str(failure.exception))

    def test_conflicting_replay_or_changed_operation_is_refused(self):
        for replay in [self.response(code=2, error=b"idempotency conflict"),
                       self.response(identifier="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")]:
            with self.assertRaises(RuntimeError):
                self.invoke([self.response(code=2, error=self.unknown), self.response(), replay])
            self.assertEqual(len(self.calls), 3)

    def test_original_deadline_bounds_lookup_replay_and_late_success(self):
        for elapsed, expected_calls in [([59, 1], 2), ([50, 5, 5], 3)]:
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                self.invoke([self.response(code=2, error=self.unknown), self.response(), self.response()],
                            advances=elapsed)
            self.assertEqual(len(self.calls), expected_calls)
            self.assertEqual(self.calls[1][1]["timeout"], 60 - elapsed[0])

    def test_normal_admission_and_other_unknown_operations_do_not_reconcile(self):
        self.invoke([self.response()])
        self.assertEqual(len(self.calls), 1)
        with self.assertRaises(RuntimeError):
            self.invoke([self.response(code=2, error=self.unknown)], kind="backup", action="create")
        self.assertEqual(len(self.calls), 1)

    def test_receipt_validation_cannot_accept_after_original_deadline(self):
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            self.invoke([self.response()], validation_elapsed=60)
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            self.invoke([self.response(code=2, error=self.unknown), self.response()],
                        validation_elapsed=60)
        self.assertEqual(len(self.calls), 2)

    def test_lookup_timeout_stays_unknown_without_replay_or_sensitive_error(self):
        with self.assertRaisesRegex(RuntimeError, "outcome unknown") as failure:
            self.invoke([self.response(code=2, error=self.unknown),
                         subprocess.TimeoutExpired(["protected-locator"], 1)])
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn("protected", str(failure.exception))
