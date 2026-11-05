"""Public Tail requests preserve the optional uint32 historical row count."""
import http.server
import json
import pathlib
import threading
import unittest
from positron_sdk import PositronClient, WireError

FIXTURE = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'python/positron_sdk/api/query-golden-fixtures.json').read_text())

class TailRequestTests(unittest.TestCase):
    def test_historical_row_count_is_a_bounded_optional_integer(self):
        response = next(case['input'] for case in FIXTURE['responses'] if case['id'] == 'tail-single-incomplete')
        query = dict(pipeline='pipeline:v1 logs | range query_time 0 100 | project commit_position | limit all', budget=response['events'][0]['header']['effectiveBudget'])
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append((self.path, body))
                value = dict(api_major=1, schema_digest='a' * 64, capability=5, availability=1, refusal=None) if self.path.endswith('capabilities:negotiate') else response
                payload = json.dumps(value).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *_):
                pass
        with http.server.HTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                client = PositronClient(f'http://127.0.0.1:{server.server_port}', allow_plaintext=True)
                for tail in ({'query': query}, {'query': query, 'historicalRows': 1}, {'query': query, 'historicalRows': 128}):
                    with self.subTest(tail=tail):
                        self.assertEqual(client.log_query_session({'tail': tail, 'batchLimit': 1}), response)
                        self.assertEqual(requests[-1], ('/v1/logs:session', {'tail': tail, 'batchLimit': 1}))
                before = len(requests)
                for value in (0, -1, 129, 4294967295, 4294967296, True, False, 1.5, '1'):
                    with self.subTest(value=value), self.assertRaises(WireError):
                        client.log_query_session({'tail': {'query': query, 'historicalRows': value}, 'batchLimit': 1})
                self.assertEqual(len(requests), before)
                with self.assertRaises(WireError):
                    client.log_query_session({'tail': {'query': query, 'historicalRows': 1, 'cursor': 'YQ=='}, 'batchLimit': 1})
                self.assertEqual(len(requests), before)
            finally:
                server.shutdown()
                thread.join()
