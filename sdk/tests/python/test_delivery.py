"""Caller-visible delivery state never advances on invalid output."""
import copy
import json
import pathlib
import unittest
from positron_sdk import BatchTracker, WireError, terminal_status

FIXTURE = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'python/positron_sdk/api/query-golden-fixtures.json').read_text())
def response(identity):
    return copy.deepcopy(next(case['input'] for case in FIXTURE['responses'] if case['id'] == identity))

class DeliveryTests(unittest.TestCase):
    def test_replay_changed_content_and_final_status(self):
        tracker = BatchTracker()
        first = response('one-batch-complete')
        self.assertEqual(len(tracker.filter(first)), 1)
        self.assertEqual(tracker.filter(first), [])
        changed = copy.deepcopy(first)
        changed['events'][1]['batch']['rows'][0]['cells'][0]['nativeValue']['textValue'] = 'changed'
        with self.assertRaises(WireError):
            tracker.filter(changed)
        self.assertEqual(tracker.filter(first), [])
        self.assertEqual(terminal_status(first['events'][-1]['terminal']), {'kind': 'complete'})

    def test_tail_explicit_receipt_and_atomic_gap_refusal(self):
        tracker = BatchTracker('tail')
        self.assertIsNone(tracker.acknowledgement())
        first = response('tail-single-incomplete')
        self.assertEqual(len(tracker.filter(first)), 1)
        self.assertEqual(tracker.filter(first), [])
        self.assertEqual(tracker.acknowledgement(), {'sequence': '0', 'digest': first['events'][1]['batch']['digest']})
        next_page = response('tail-next-incomplete')
        gap = copy.deepcopy(next_page)
        gap['events'][1]['batch']['sequence'] = '4'
        with self.assertRaises(WireError):
            tracker.filter(gap)
        self.assertEqual(len(tracker.filter(next_page)), 1)
        with self.assertRaises(WireError):
            tracker.filter(first)

    def test_schema_change_and_false_completion_are_refused(self):
        first = response('tail-single-incomplete')
        tracker = BatchTracker('tail')
        tracker.filter(first)
        changed = response('tail-next-incomplete')
        changed['events'][0]['header']['columns'][0]['name'] = 'other'
        with self.assertRaises(WireError):
            tracker.filter(changed)
        false = copy.deepcopy(first['events'][-1]['terminal'])
        false['state'] = 'complete'
        with self.assertRaises(WireError):
            terminal_status(false)
