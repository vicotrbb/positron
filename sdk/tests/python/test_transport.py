"""Public client transport refuses unsafe input and exposes ambiguous loss."""
import http.server
import json
import socketserver
import ssl
import threading
import time
import unittest
from positron_sdk import PositronClient, ClientError, QueryError, WireError, decode, encode

class Server(socketserver.TCPServer):
    allow_reuse_address = True

class TransportTests(unittest.TestCase):
    def invoke(self, status, body, call, *, delay=0):
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, self.rfile.read(int(self.headers['Content-Length']))))
                if delay:
                    time.sleep(delay)
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_):
                pass
        with Server(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                result = call(f'http://127.0.0.1:{server.server_address[1]}')
            finally:
                server.shutdown()
                thread.join()
        return result, requests

    def test_endpoint_and_header_refusal_never_echoes_secret(self):
        for endpoint in ('http://localhost', 'https://user:secret@localhost', 'https://localhost/path', 'https://localhost/?secret', 'file:///tmp/key'):
            with self.subTest(endpoint=endpoint), self.assertRaises(WireError) as caught:
                PositronClient(endpoint)
            self.assertNotIn('secret', str(caught.exception))
        client = PositronClient('http://127.0.0.1:1', allow_plaintext=True)
        for bearer in ('secret\r\nheader', 'secret '):
            with self.assertRaises(WireError) as caught:
                client.capability_negotiate({'api_major': 1}, bearer=bearer)
            self.assertNotIn('secret', str(caught.exception))
        for timeout in (0, 31, float('nan'), float('inf')):
            with self.assertRaises(WireError):
                client.capability_negotiate({'api_major': 1}, timeout=timeout)

    def test_http_round_trip_preserves_old_and_new_v1_capability(self):
        for schema in ('a' * 64, 'b' * 64):
            value = dict(api_major=1, schema_digest=schema, capability=1, availability=1, refusal=None)
            result, requests = self.invoke(200, json.dumps(value).encode(), lambda endpoint: PositronClient(endpoint, allow_plaintext=True).capability_negotiate({'api_major': 1}))
            self.assertEqual(result, value)
            self.assertEqual(len(requests), 1)

    def test_new_features_are_refused_before_sending_invalid_semantics(self):
        value = dict(api_major=1, schema_digest='a' * 64, capability=4, availability=3, refusal=None)
        def call(endpoint):
            with self.assertRaises(QueryError) as caught:
                PositronClient(endpoint, allow_plaintext=True).log_query_session({'resume': 'YQ==', 'batchLimit': 1})
            self.assertEqual(caught.exception.failure, 'UnsupportedFeature')
            self.assertEqual(caught.exception.completion_state, 'COMPLETION_STATE_REJECTED')
        _, requests = self.invoke(200, json.dumps(value).encode(), call)
        self.assertEqual(len(requests), 1)
        self.assertTrue(requests[0][0].endswith('capabilities:negotiate'))

    def test_malformed_or_oversized_response_and_timeout_are_ambiguous(self):
        for body in (b'not-json', b'{}' * 3000, b'{"api_major":1,"api_major":1}'):
            def call(endpoint):
                with self.assertRaises(ClientError) as caught:
                    PositronClient(endpoint, allow_plaintext=True).capability_negotiate({'api_major': 1})
                self.assertEqual(caught.exception.completion_state, 'COMPLETION_STATE_AMBIGUOUS')
                self.assertEqual(caught.exception.retry_class, 'RETRY_CLASS_NEVER')
            _, requests = self.invoke(200, body, call)
            self.assertEqual(len(requests), 1)
        def call(endpoint):
            with self.assertRaises(ClientError):
                PositronClient(endpoint, allow_plaintext=True).capability_negotiate({'api_major': 1}, timeout=.02)
        _, requests = self.invoke(200, b'{}', call, delay=.05)
        self.assertEqual(len(requests), 1)

    def test_redirects_are_never_followed(self):
        def call(endpoint):
            with self.assertRaises(ClientError):
                PositronClient(endpoint, allow_plaintext=True).capability_negotiate({'api_major': 1})
        _, requests = self.invoke(302, b'{}', call)
        self.assertEqual(len(requests), 1)

    def test_exact_integer_and_oneof_boundaries(self):
        value = {'unsignedInteger': '18446744073709551615'}
        self.assertEqual(decode('LogQueryCell', encode('LogQueryCell', value)), value)
        for text in ('{"unsignedInteger":"18446744073709551616"}', '{"unsignedInteger":"1","missing":{}}', '{"unsignedInteger":"1","unsigned_integer":"2"}'):
            with self.assertRaises(WireError):
                decode('LogQueryCell', text)

    def test_tls_peer_verification_is_required(self):
        import os
        import pathlib
        from unittest.mock import patch
        fixtures = pathlib.Path(__file__).resolve().parents[3] / 'crates/positron-runtime/tests/native_transport/fixtures'
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                body = json.dumps(dict(api_major=1, schema_digest='a' * 64, capability=1, availability=1, refusal=None)).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_):
                pass
        with Server(('127.0.0.1', 0), Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(fixtures / 'api-test-cert.pem', fixtures / 'api-test-key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            endpoint = f'https://localhost:{server.server_address[1]}'
            try:
                with self.assertRaises(ClientError):
                    PositronClient(endpoint).capability_negotiate({'api_major': 1})
                with patch.dict(os.environ, SSL_CERT_FILE=str(fixtures / 'api-test-cert.pem')):
                    self.assertEqual(PositronClient(endpoint).capability_negotiate({'api_major': 1})['api_major'], 1)
            finally:
                server.shutdown()
                thread.join()

    def test_deadline_bounds_slow_response_headers(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(8192)
                pieces = [b'HTTP/1.1 200 OK\r\nX-Delay: '] + [b'a'] * 20 + [b'\r\nContent-Length: 2\r\n\r\n{}']
                try:
                    for piece in pieces:
                        self.request.sendall(piece)
                        time.sleep(.01)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        with Server(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                started = time.monotonic()
                with self.assertRaises(ClientError):
                    PositronClient(f'http://127.0.0.1:{server.server_address[1]}', allow_plaintext=True).capability_negotiate({'api_major': 1}, timeout=.05)
                self.assertLess(time.monotonic() - started, .15)
            finally:
                server.shutdown()
                thread.join()

    def test_deadline_bounds_stalled_name_resolution(self):
        import socket
        from unittest.mock import patch
        original = socket.getaddrinfo
        def stalled(host, port, *args, **kwargs):
            time.sleep(.2)
            return original('127.0.0.1', port, *args, **kwargs)
        with patch('socket.getaddrinfo', stalled):
            started = time.monotonic()
            with self.assertRaises(ClientError):
                PositronClient('http://resolver.test.invalid:1', allow_plaintext=True).capability_negotiate({'api_major': 1}, timeout=.02)
            self.assertLess(time.monotonic() - started, .1)

    def test_stalled_resolvers_are_bounded_and_eventually_release_resources(self):
        import socket
        from unittest.mock import patch
        release = threading.Event()
        workers = []
        original = socket.getaddrinfo
        def stalled(host, port, *args, **kwargs):
            workers.append(threading.current_thread())
            release.wait(2)
            return original('127.0.0.1', port, *args, **kwargs)
        try:
            with patch('socket.getaddrinfo', stalled):
                for _ in range(24):
                    started = time.monotonic()
                    with self.assertRaises(ClientError):
                        PositronClient('http://resolver.test.invalid:1', allow_plaintext=True).capability_negotiate({'api_major': 1}, timeout=.01)
                    self.assertLess(time.monotonic() - started, .1)
                self.assertLessEqual(len(workers), 16)
        finally:
            release.set()
            for worker in workers:
                worker.join(1)
                self.assertFalse(worker.is_alive())
        # A subsequent request can connect normally after the resolver recovers.
        value = dict(api_major=1, schema_digest='a' * 64, capability=1, availability=1, refusal=None)
        result, requests = self.invoke(200, json.dumps(value).encode(), lambda endpoint: PositronClient(endpoint, allow_plaintext=True).capability_negotiate({'api_major': 1}))
        self.assertEqual(result, value)
        self.assertEqual(len(requests), 1)

    def test_slow_body_deadline_closes_socket_and_timer_resources(self):
        closed = threading.Event()
        requests = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(8192)
                requests.append(self.request)
                if len(requests) > 1:
                    body = json.dumps(dict(api_major=1, schema_digest='a' * 64, capability=1, availability=1, refusal=None)).encode()
                    self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
                    return
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n')
                try:
                    for _ in range(100):
                        self.request.sendall(b'x')
                        time.sleep(.01)
                except (BrokenPipeError, ConnectionResetError):
                    closed.set()
        before = set(threading.enumerate())
        with Server(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                client = PositronClient(f'http://127.0.0.1:{server.server_address[1]}', allow_plaintext=True)
                started = time.monotonic()
                with self.assertRaises(ClientError):
                    client.capability_negotiate({'api_major': 1}, timeout=.05)
                self.assertLess(time.monotonic() - started, .15)
                self.assertTrue(closed.wait(1))
                self.assertEqual(client.capability_negotiate({'api_major': 1})['api_major'], 1)
                self.assertEqual(len(requests), 2)
                self.assertIsNot(requests[0], requests[1])
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(set(threading.enumerate()), before)
