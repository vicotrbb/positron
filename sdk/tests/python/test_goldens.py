"""Canonical cross-language fixtures exercise the installed public Python API."""
import json
import pathlib
import unittest
from positron_sdk import decode, decode_query, query_error

ROOT = pathlib.Path(__file__).resolve().parents[2] / 'python/positron_sdk/api'

class GoldenTests(unittest.TestCase):
    def test_canonical_contract(self):
        fixture = json.loads((ROOT / 'query-golden-fixtures.json').read_text())
        for case in fixture['representations']:
            with self.subTest(case=case['id']):
                if case['accepted']:
                    self.assertEqual(decode(case['type'], case['input']), case['canonical'])
                else:
                    with self.assertRaises(ValueError):
                        decode(case['type'], case['input'])
        for case in fixture['responses']:
            with self.subTest(case=case['id']):
                if case['accepted']:
                    decode_query(json.dumps(case['input']), case.get('mode', 'execute'))
                else:
                    with self.assertRaises(ValueError):
                        decode_query(json.dumps(case['input']), case.get('mode', 'execute'))
        for case in fixture['errors']:
            with self.subTest(case=case['id']):
                error = query_error(case['status'], json.dumps(case['input']), case.get('cancellation', False))
                self.assertEqual((error.failure, error.retry_class, error.completion_state),
                                 (case['failure'], case['retryClass'], case['completionState']))

if __name__ == '__main__':
    unittest.main()
