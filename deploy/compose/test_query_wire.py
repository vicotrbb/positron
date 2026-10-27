"""Consume a response emitted and validated by the canonical Rust API encoder."""
import sys
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
case.assertEqual(lifecycle.query(), base64.b64encode(bytes([7]) * 32).decode())
