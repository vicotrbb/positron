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
                mock.patch.object(pathlib.Path, "write_text") as write, \
                mock.patch.object(sys, "argv", ["service-check.py", "query"]), \
                mock.patch("subprocess.run", return_value=result) as execute:
            try:
                runpy.run_path(str(pathlib.Path(__file__).with_name("service-check.py")))
            finally:
                self.assertEqual(execute.call_count, 1)
        return write.call_args.args[0]

    def test_accepts_complete_and_refuses_incomplete_with_the_same_retained_record(self):
        self.run_query(json.dumps(self.response("complete")).encode())
        with self.assertRaisesRegex(AssertionError, "query did not complete"):
            self.run_query(json.dumps(self.response("incomplete")).encode())

    def test_missing_marker_reports_only_closed_query_facts(self):
        response = {"events": [{"header": {"identity": "protected-canary"}},
            {"terminal": {"state": "incomplete", "reason": "budget_exhausted",
                "continuationCursor": "protected-canary", "stats": {
                    "records": "0", "cpuWorkUnits": "15", "resultDigest": "protected-canary"}}}]}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(
                AssertionError, "acknowledged record missing or duplicated"):
            self.run_query(json.dumps(response).encode())
        self.assertEqual(json.loads(output.getvalue()), {
            "event": "query_marker_failure", "marker_count": 0, "outcome": "observed",
            "event_kinds": ["header", "terminal"], "terminal_state": "incomplete",
            "terminal_reason": "budget_exhausted", "stats": {"records": 0, "cpuWorkUnits": 15}})

    def test_marker_diagnostic_rejects_untrusted_or_unbounded_responses(self):
        responses = [b"protected-canary", b"x" * 65537,
            b'{"events":[]}', b'{"events":[{"protected-canary":{}}]}']
        for terminal in [None, {"state": "protected-canary"},
                {"state": "incomplete", "reason": "protected-canary"},
                {"state": "complete", "stats": []},
                {"state": "complete", "stats": {"records": "protected-canary"}},
                {"state": "complete", "stats": {"records": "18446744073709551616"}},
                {"state": "complete", "stats": {"records": True}}]:
            responses.append(json.dumps({"events": [{"terminal": terminal}]}).encode())
        responses.append(json.dumps({"events": [{"header": {}}] * 33}).encode())
        for response in responses:
            output = io.StringIO()
            with self.subTest(kind="untrusted response"), contextlib.redirect_stdout(output), \
                    self.assertRaisesRegex(AssertionError, "acknowledged record missing or duplicated"):
                self.run_query(response)
            self.assertEqual(json.loads(output.getvalue()), {
                "event": "query_marker_failure", "marker_count": 0, "outcome": "unavailable"})

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
            if isinstance(result, BaseException): raise result
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

    @staticmethod
    def wall_exhausted(limiter="wall_seconds"):
        return types.SimpleNamespace(returncode=0, stderr=b"", stdout=json.dumps({"events": [
            {"header": {}}, {"terminal": {"state": "incomplete", "reason": "budget_exhausted",
                "stats": {"wallSeconds": "5", "limitingBudget": limiter}}}]}).encode())

    def test_wall_exhaustion_discards_partial_output_and_repeats_identical_query(self):
        self.run_query([(17.75, self.wall_exhausted()), (1, self.complete())])
        self.assertEqual([options["timeout"] for _, options in self.commands], [30, 11.25])
        self.assertEqual(self.commands[0][0], self.commands[1][0])
        self.assertEqual(self.commands[0][1]["input"], self.commands[1][1]["input"])

    def test_query_timeout_retains_last_closed_outcome_and_original_budget(self):
        output = io.StringIO()
        timeout = subprocess.TimeoutExpired(["protected-canary"], 1,
            output=b"protected-canary", stderr=b"protected-canary")
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "public query command timed out") as caught:
            self.run_query([(20, self.wall_exhausted()), (7, self.refused()), (1, timeout)])
        self.assertEqual(json.loads(output.getvalue()), {"event": "query_timeout",
            "attempt": 3, "elapsed_ms": 30000, "remaining_ms": 0,
            "last_terminal_state": "incomplete", "last_terminal_reason": "budget_exhausted",
            "last_limiting_budget": "wall_seconds", "last_rejection": "capacity_unavailable"})
        self.assertEqual([options["timeout"] for _, options in self.commands], [30, 9, 1])
        self.assertNotIn("protected-canary", str(caught.exception) + output.getvalue())

    def test_query_timeout_without_prior_terminal_has_no_raw_failure_data(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "public query command timed out"):
            self.run_query([(30, subprocess.TimeoutExpired(["protected-canary"], 30,
                output=b"protected-canary", stderr=b"protected-canary"))])
        self.assertEqual(json.loads(output.getvalue()), {"event": "query_timeout",
            "attempt": 1, "elapsed_ms": 30000, "remaining_ms": 0,
            "last_terminal_state": "unavailable", "last_terminal_reason": "unavailable",
            "last_limiting_budget": "unavailable", "last_rejection": "none"})
        self.assertEqual(len(self.commands), 1)

    def test_wall_exhaustion_is_bounded_to_three_executions(self):
        with self.assertRaisesRegex(RuntimeError, "query wall allowance exhausted"):
            self.run_query([(1, self.wall_exhausted())] * 3 + [(0, self.complete())])
        self.assertEqual(len(self.commands), 3)

    def test_capacity_refusals_do_not_consume_query_execution_attempts(self):
        self.run_query([(0, self.refused())] * 4 + [(0, self.wall_exhausted()),
            (0, self.wall_exhausted()), (0, self.complete())])
        self.assertEqual(len(self.commands), 7)

    def test_wall_retry_cannot_begin_after_original_deadline(self):
        with self.assertRaisesRegex(RuntimeError, "query deadline elapsed"):
            self.run_query([(29.5, self.wall_exhausted()), (0, self.complete())])
        self.assertEqual(len(self.commands), 1)

    def test_missing_unknown_or_other_limiting_budget_never_retries(self):
        for limiter in [None, "cpu_work_units", "protected-canary", 5]:
            with self.subTest(limiter=limiter), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(AssertionError):
                self.run_query([(0, self.wall_exhausted(limiter)), (0, self.complete())])
            self.assertEqual(len(self.commands), 1)

    def test_complete_empty_or_duplicate_is_never_retried(self):
        empty = {"events": [{"header": {}}, {"terminal": {"state": "complete"}}]}
        duplicate = QueryCompletion.response("complete")
        duplicate["events"].insert(0, duplicate["events"][0])
        for response in [empty, duplicate]:
            result = types.SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b"")
            with self.subTest(response=response), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaisesRegex(AssertionError, "acknowledged record missing or duplicated"):
                self.run_query([(0, result), (0, self.complete())])
            self.assertEqual(len(self.commands), 1)

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
    operation_id = bytes(range(16)).hex()
    key = "22222222-2222-4222-8222-222222222222"
    unknown = b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n"

    def response(self, status="running", identifier=None, code=0, error=b""):
        return types.SimpleNamespace(returncode=code, stderr=error,
            stdout=f"operation_id={identifier or self.operation_id} status={status}\n".encode())

    def invoke(self, responses, kind="repository", action="init", advances=None, validation_elapsed=0,
               real_generation=False):
        self.calls = []
        self.clock = 0
        self.generations = []

        def execute(command, **options):
            if not real_generation and command[1:3] == ["repository", "status"]:
                return types.SimpleNamespace(returncode=0, stderr=b"",
                    stdout=("catalog_generation=" + generation()).encode())
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
        original_fields = owner["fields"]

        def validate(text):
            if not text.startswith("catalog_generation="):
                self.clock += validation_elapsed
            return original_fields(text)

        owner["admit"].__globals__["fields"] = validate
        with mock.patch("time.monotonic", side_effect=lambda: self.clock), \
                mock.patch("subprocess.run", side_effect=execute):
            return owner["admit"](kind, action, ["--locator", "/protected-locator", "--repository-id",
                "11111111-1111-4111-8111-111111111111", "--idempotency-key", self.key])

    def test_status_capacity_refusal_retries_before_admitting_with_fresh_generation(self):
        cases = [("repository", "init", b"positron: capacity unavailable; retry the same idempotent request"),
                 ("backup", "create", b"positron: administration unavailable; inspect or retry the same operation"),
                 ("upgrade", "start", b"positron: stale resource generation; inspect current state before retrying")]
        status = types.SimpleNamespace(returncode=0, stdout=b"catalog_generation=7\n", stderr=b"")
        for kind, action, error in cases:
            with self.subTest(kind=kind), mock.patch("time.sleep") as sleep:
                receipt = self.invoke([self.response(code=2, error=error), status, self.response()],
                                      kind=kind, action=action, real_generation=True)
            self.assertEqual(receipt["operation_id"], self.operation_id)
            self.assertEqual([call[0][1:3] for call in self.calls],
                             [["repository", "status"], ["repository", "status"], [kind, action]])
            self.assertEqual(self.calls[-1][0][-2:], ["--expected-generation", "7"])
            self.assertTrue(all(call[1]["timeout"] <= 60 for call in self.calls))
            sleep.assert_called_once_with(0.1)

    def test_status_retry_and_success_share_the_original_admission_deadline(self):
        capacity = self.response(code=2, error=b"positron: capacity unavailable; retry the same idempotent request")
        status = types.SimpleNamespace(returncode=0, stdout=b"catalog_generation=7", stderr=b"")
        with mock.patch("time.sleep"):
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                self.invoke([capacity, status], advances=[59, 1], real_generation=True)
        self.assertEqual([call[0][1:3] for call in self.calls], [["repository", "status"]] * 2)
        self.assertEqual([call[1]["timeout"] for call in self.calls], [60, 1])

    def test_status_fatal_and_unknown_refusals_never_attempt_admission_or_lookup(self):
        for error, category in [(self.unknown, "transport_unknown"),
                (b"positron: system administration authentication rejected", "authentication_rejected"),
                (b"protected-canary /protected-locator capacity unavailable", "other")]:
            with self.subTest(category=category), self.assertRaisesRegex(RuntimeError, "code=" + category) as failure:
                self.invoke([self.response(code=2, error=error)], real_generation=True)
            self.assertEqual(len(self.calls), 1)
            self.assertNotIn("protected", str(failure.exception))

    def test_status_timeout_or_invalid_generation_never_attempts_admission(self):
        for response in [subprocess.TimeoutExpired(["protected-canary"], 60)] + [
                types.SimpleNamespace(returncode=0, stdout=receipt, stderr=b"")
                for receipt in [b"", b"catalog_generation=protected-canary", b"catalog_generation=-1",
                                b"catalog_generation=18446744073709551616", b"catalog_generation=\xff"]]:
            with self.subTest(receipt="invalid"), self.assertRaises(RuntimeError) as failure:
                self.invoke([response], real_generation=True)
            self.assertEqual(len(self.calls), 1)
            self.assertNotIn("protected", str(failure.exception))

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
                       self.response(identifier="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]:
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

    def test_noncanonical_operation_ids_never_permit_replay(self):
        for identifier in ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "A" * 32,
                           "0" * 32, "f" * 31, "g" * 32, "1" * 33]:
            with self.subTest(format="noncanonical"):
                with self.assertRaisesRegex(RuntimeError, "invalid receipt"):
                    self.invoke([self.response(code=2, error=self.unknown),
                                 self.response(identifier=identifier)])
                self.assertEqual(len(self.calls), 2)

    def test_lookup_failures_report_only_exact_closed_canonical_classes(self):
        failures = [
            (b"positron: invalid repository request", "invalid_request"),
            (b"positron: system administration authentication rejected", "authentication_rejected"),
            (b"positron: repository operation unavailable", "operation_unavailable"),
            (b"positron: stale resource generation; inspect current state before retrying", "stale_generation"),
            (b"positron: operation precondition failed; inspect current state before retrying", "precondition_failed"),
            (b"positron: idempotency key conflicts with an accepted request", "idempotency_conflict"),
            (b"positron: administration unavailable; inspect or retry the same operation", "administration_unavailable"),
            (b"positron: capacity unavailable; retry the same idempotent request", "capacity_unavailable"),
            (self.unknown, "transport_unknown"),
            (b"protected-canary /protected-locator", "other"),
        ]
        for error, category in failures:
            with self.subTest(category=category):
                with self.assertRaises(RuntimeError) as failure:
                    self.invoke([self.response(code=2, error=self.unknown),
                                 self.response(code=2, error=error)])
                self.assertEqual(str(failure.exception),
                                 "repository admission reconciliation refused: code=" + category)
                self.assertEqual(len(self.calls), 2)


class RestartReadinessObservation(unittest.TestCase):
    """Run the actual VM test script with its machine boundary mocked."""

    @staticmethod
    def status():
        return {"phase": "serving", "integrity_degraded": False,
                "maintenance": {"clock_uncertain": True},
                "doctor": {"required_families": {"storage": {
                    "disk_pressure": "healthy", "usable_disk_bytes": 123456}}},
                "unrelated": "protected-canary"}

    def invoke(self, response=None, failure=True, collector_error=False, systemd_output=None, collector_result=None, ingest_failure=False):
        import textwrap
        self.observations = []
        self.commands = []
        self.http = []
        self.reads = []
        self.systemd = []
        self.waits = []
        original = RuntimeError("original readiness assertion")
        owner = self

        class Machine:
            restarted = False

            def succeed(self, command):
                owner.commands.append(command)
                if ingest_failure and command == "python /etc/positron-service-check.py ingest":
                    raise original
                if command == "systemctl restart positron":
                    self.restarted = True
                return ""

            def fail(self, command):
                return ""

            def wait_for_unit(self, unit):
                return None

            def wait_until_succeeds(self, command, **options):
                owner.waits.append((command, options.copy()))
                if self.restarted and failure:
                    raise original
                return ""

            def execute(self, command, **options):
                owner.observations.append((command, options.copy()))
                if collector_error:
                    raise OSError("protected-canary")
                if collector_result is not None:
                    return collector_result
                owner.assertEqual(command,
                    "timeout --kill-after=1s 14s python /etc/positron-service-check.py readiness-diagnostics")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    runpy.run_path(str(pathlib.Path(__file__).with_name("service-check.py")))
                return 0, output.getvalue()

        def request(value, timeout):
            self.http.append((value, timeout))
            if isinstance(response, BaseException):
                raise response
            encoded = json.dumps(self.status()).encode() if response is None else response
            class Response(io.BytesIO):
                status = 200

                def read(inner, size=-1):
                    result = super().read(size)
                    owner.reads.append((size, len(result)))
                    return result

            stream = Response(encoded)
            return contextlib.closing(stream)

        def systemd(command, **options):
            self.systemd.append((command, options))
            return types.SimpleNamespace(returncode=0, stdout=systemd_output if systemd_output is not None else (
                b"ActiveState=active\nSubState=running\nMainPID=123\n"
                b"ExecMainStatus=0\nNRestarts=0\n"), stderr=b"protected-canary")

        directory = pathlib.Path(__file__).parent
        source = (directory / "test.nix").read_text()
        script = textwrap.dedent(source.split("  testScript = ''\n", 1)[1].rsplit("  '';", 1)[0])
        output = io.StringIO()
        caught = None
        with mock.patch.object(pathlib.Path, "read_text", return_value=(
                "administrator_secret=protected-canary\ningest_secret=protected-ingest\n"
                "query_secret=protected-query\n")), \
                mock.patch.object(sys, "argv", ["service-check.py", "readiness-diagnostics"]), \
                mock.patch("urllib.request.urlopen", side_effect=request), \
                mock.patch("subprocess.run", side_effect=systemd), \
                contextlib.redirect_stdout(output):
            try:
                exec(compile(script, "test.nix:testScript", "exec"),
                     {"machine": Machine(), "start_all": lambda: None})
            except BaseException as error:
                caught = error
        self.output = output.getvalue()
        if failure:
            self.assertIs(caught, original)
        elif caught is not None:
            raise caught
        return self.output

    def observed(self):
        self.assertEqual(len(self.observations), 1,
                         "readiness failure must collect one bounded observation before cleanup")
        self.assertEqual(self.observations[0][1], {})
        self.assertEqual(len(self.http), 1)
        request, timeout = self.http[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:4310/status")
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 5)
        self.assertNotIn("protected", request.full_url)
        self.assertNotIn("protected", self.output)
        self.assertTrue(all(0 < size <= 65537 for size, _ in self.reads),
                        "status reads must specify a bounded size including one sentinel")
        self.assertLessEqual(sum(count for _, count in self.reads), 65537)
        self.assertTrue(all(not options for _, options in self.waits),
                        "preserve the driver's original readiness timeout")

    def test_ingest_failure_observes_once_without_replay_or_replacing_the_failure(self):
        self.invoke(ingest_failure=True)
        self.observed()
        self.assertEqual(self.commands.count("python /etc/positron-service-check.py ingest"), 1)
        self.assertNotIn("protected", self.output)

    def test_failure_observes_closed_clock_and_resource_facts_before_same_exception(self):
        output = self.invoke()
        self.observed()
        records = [json.loads(line) for line in output.splitlines()]
        status = next(record for record in records if record.get("event") == "readiness_status")
        self.assertEqual(status, {"event": "readiness_status", "outcome": "observed",
            "phase": "serving", "integrity_degraded": False, "clock_uncertain": True,
            "disk_pressure": "healthy", "usable_disk_bytes": 123456})
        self.assertTrue(self.reads)
        self.assertIn({"event": "readiness_systemd", "outcome": "observed",
            "ActiveState": "active", "SubState": "running", "MainPID": 123,
            "ExecMainStatus": 0, "NRestarts": 0}, records)
        self.assertEqual(len(self.systemd), 1)
        command, options = self.systemd[0]
        self.assertEqual(command, ["systemctl", "show", "positron", "--property="
            "ActiveState,SubState,MainPID,ExecMainStatus,NRestarts"])
        self.assertGreater(options["timeout"], 0)
        self.assertLessEqual(options["timeout"], 3)

    def test_systemd_untrusted_values_are_not_rendered(self):
        for value in [b"ActiveState=protected-canary\n", b"x" * 4097,
                      b"ActiveState=active\nSubState=running\nMainPID=protected-canary\n",
                      b"ActiveState=active\nSubState=running\nMainPID=123\n"
                      b"ExecMainStatus=0\nNRestarts=0\nExtra=protected-canary\n"]:
            with self.subTest(kind="invalid systemd observation"):
                self.invoke(systemd_output=value)
                self.observed()
                records = [json.loads(line) for line in self.output.splitlines()]
                self.assertIn({"event": "readiness_systemd", "outcome": "unavailable"}, records)

    def test_success_path_never_observes_or_changes_lifecycle(self):
        self.invoke(failure=False)
        self.assertEqual(self.observations, [])
        self.assertEqual(self.http, [])
        self.assertEqual(self.systemd, [])

    def test_collector_error_cannot_replace_original_readiness_failure(self):
        self.invoke(collector_error=True)
        self.assertEqual(len(self.observations), 1)
        self.assertNotIn("protected", self.output)

    def test_collector_kill_result_never_leaks_output_or_replaces_original_failure(self):
        self.invoke(collector_result=(137, "protected-canary"))
        self.assertEqual(len(self.observations), 1)
        self.assertNotIn("protected", self.output)
        self.assertIn('"outcome":"unavailable"', self.output)

    def test_invalid_or_oversized_status_never_prints_untrusted_fields(self):
        for response in [b"protected-canary", b"x" * 65537,
                         json.dumps({"phase": "protected-canary"}).encode(),
                         json.dumps({**self.status(), "integrity_degraded": "protected-canary"}).encode()]:
            with self.subTest(kind="invalid status"):
                self.invoke(response=response)
                self.observed()
                self.assertIn('"outcome": "unavailable"', self.output)

    def test_auth_refusal_and_timeout_are_distinct_and_never_retried(self):
        cases = [(urllib.error.HTTPError("http://localhost/status", 401, "protected-canary", {},
                    io.BytesIO(b"protected-canary")), "authentication_rejected"),
                 (urllib.error.HTTPError("http://localhost/status", 503, "protected-canary", {},
                    io.BytesIO(b"protected-canary")), "refused"),
                 (TimeoutError("protected-canary"), "timeout")]
        for response, expected in cases:
            with self.subTest(outcome=expected):
                self.invoke(response=response)
                self.observed()
                self.assertIn('"outcome": "' + expected + '"', self.output)


class UpgradeAdmissionObservation(unittest.TestCase):
    def test_upgrade_timeout_preserves_bounded_last_admission_facts(self):
        owner = RepositoryAdmissionReconciliation()
        errors = [b"positron: stale resource generation; inspect current state before retrying",
                  b"positron: administration unavailable; inspect or retry the same operation",
                  b"positron: capacity unavailable; retry the same idempotent request"]
        output = io.StringIO()
        with contextlib.redirect_stderr(output), mock.patch("time.sleep"), \
                self.assertRaisesRegex(RuntimeError, "admission outcome unknown at deadline"):
            owner.invoke([*[owner.response(code=2, error=error) for error in errors],
                          subprocess.TimeoutExpired(["protected-canary"], 30,
                              output=b"protected-canary", stderr=b"protected-canary")],
                         kind="upgrade", action="start", advances=[10, 10, 10, 30])
        self.assertTrue(output.getvalue(), "timed-out admission must retain closed last-attempt facts")
        self.assertEqual(json.loads(output.getvalue()), {
            "event": "lifecycle_admission_failed", "attempt": 4, "phase": "upgrade_start",
            "last_rejection": "capacity_unavailable", "elapsed_ms": 60000, "remaining_ms": 0})
        self.assertEqual([options["timeout"] for _, options in owner.calls], [60, 50, 40, 30])
        self.assertEqual(len(owner.generations), 4)
        self.assertNotIn("protected", output.getvalue())

    def test_upgrade_repository_status_timeout_is_distinguished_without_output(self):
        owner = RepositoryAdmissionReconciliation()
        output = io.StringIO()
        with contextlib.redirect_stderr(output), self.assertRaisesRegex(RuntimeError, "outcome unknown"):
            owner.invoke([subprocess.TimeoutExpired(["protected-canary"], 60,
                              stderr=b"protected-canary")], kind="upgrade", action="start",
                         real_generation=True, advances=[60])
        self.assertEqual(json.loads(output.getvalue()), {
            "event": "lifecycle_admission_failed", "attempt": 1, "phase": "repository_status",
            "last_rejection": "none", "elapsed_ms": 60000, "remaining_ms": 0})
        self.assertEqual(len(owner.calls), 1)
        self.assertNotIn("protected", output.getvalue())

    def test_upgrade_unknown_fatal_preserves_the_original_decision_and_closed_class(self):
        owner = RepositoryAdmissionReconciliation()
        with self.assertRaisesRegex(RuntimeError, "code=transport_unknown"):
            owner.invoke([owner.response(code=2, error=owner.unknown)], kind="upgrade", action="start")
        self.assertEqual(len(owner.calls), 1)


    def test_upgrade_fatal_whitelist_does_not_render_unknown_input(self):
        cases = [(b"positron: invalid upgrade request", "invalid_request"),
            (b"positron: system administration authentication rejected", "authentication_rejected"),
            (b"positron: upgrade operation unavailable", "operation_unavailable"),
            (b"positron: upgrade precondition failed; inspect current state before retrying", "precondition_failed"),
            (b"positron: idempotency key conflicts with an accepted request", "idempotency_conflict"),
            (b"protected-secret-canary", "other")]
        for error, category in cases:
            owner = RepositoryAdmissionReconciliation()
            with self.subTest(category=category), self.assertRaises(RuntimeError) as raised:
                owner.invoke([owner.response(code=2, error=error)], kind="upgrade", action="start")
            self.assertEqual(str(raised.exception), "native service refused lifecycle admission: code=" + category)
            self.assertNotIn("protected-secret-canary", str(raised.exception))
            self.assertEqual(len(owner.calls), 1)


    def test_upgrade_success_and_existing_capacity_retry_keep_their_original_binding(self):
        owner = RepositoryAdmissionReconciliation()
        capacity = b"positron: capacity unavailable; retry the same idempotent request"
        with mock.patch("time.sleep") as sleep:
            receipt = owner.invoke([owner.response(code=2, error=capacity), owner.response()],
                kind="upgrade", action="start")
        self.assertEqual(receipt["operation_id"], owner.operation_id)
        self.assertEqual(len(owner.calls), 2)
        # Existing admission refreshes generation between canonical refusals.
        self.assertEqual(owner.calls[0][0][:-1], owner.calls[1][0][:-1])
        self.assertEqual(owner.calls[0][1], owner.calls[1][1])
        sleep.assert_called_once_with(0.1)
