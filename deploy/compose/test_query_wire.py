"""Consume a response emitted and validated by the canonical Rust API encoder."""
import sys
import contextlib
import io
import json
import base64
import unittest
from data_lifecycle import DataLifecycle

payload = sys.stdin.buffer.read(65537)
assert len(payload) <= 65536
case = unittest.TestCase()
# The replaceable boundary is external Compose CLI stdout, not a protocol codec.
def compose(*args, **kwargs):
    return payload
lifecycle = DataLifecycle(case, None, "wire-fixture", compose, None,
                          b"administrator_secret=fixture-admin query_secret=fixture-query")
if sys.argv[1] == "complete-one":
    case.assertEqual(lifecycle.query(stage="wire"), base64.b64encode(bytes([7]) * 32).decode())
else:
    output = io.StringIO()
    with contextlib.redirect_stderr(output), case.assertRaises(AssertionError):
        lifecycle.query(stage="wire")
    case.assertTrue(output.getvalue(), "strict query failure must retain closed terminal context")
    summary = json.loads(output.getvalue())
    case.assertEqual(summary, {"event": "compose_query_failed", "stage": "wire", "terminal_count": 1,
        "state": "incomplete" if sys.argv[1] == "incomplete-zero" else "complete",
        "records": 0, "digest_present": True, "matching_rows": 0,
        "reason": "budget_exhausted" if sys.argv[1] == "incomplete-zero" else "none",
        "limiting_budget": "wall_seconds" if sys.argv[1] == "incomplete-zero" else "none"})
    for secret in ["fixture-admin", "fixture-query", "wire-secret-canary"]:
        case.assertNotIn(secret, output.getvalue())
