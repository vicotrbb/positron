"""The actual native readiness CLI verifies the Compose TLS fixture's roles."""
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from tls_fixture import material


class ReadinessTLS(unittest.TestCase):
    def test_native_probe_refuses_ca_as_server_and_accepts_its_signed_server_leaf(self):
        binary = os.environ.get("POSITRON_TEST_NATIVE_BINARY", str(Path(__file__).resolve().parents[2] / "target/debug/positron"))
        with tempfile.TemporaryDirectory(prefix="positron-ready-tls-") as directory:
            root = Path(directory)
            # This is the original failing Compose profile, with the same DNS SAN.
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(root / "bad-key.pem"), "-out", str(root / "bad.pem")], check=True, capture_output=True)
            material(root)
            for certificate, key, trust, expected in [("bad.pem", "bad-key.pem", "bad.pem", False), ("server.pem", "server-key.pem", "ca.pem", True)]:
                seen = []
                class Peer(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        seen.append((self.path, self.headers.get("Authorization")))
                        self.send_response(200)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                    def log_message(self, *args): pass
                server = http.server.HTTPServer(("127.0.0.1", 0), Peer)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / certificate, root / key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    args = [binary, "doctor", "--ready", "--endpoint", f"127.0.0.1:{server.server_address[1]}", "--server-name", "localhost", "--trust-file", str(root / trust)]
                    result = subprocess.run(args, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode == 0, expected, (result.stdout, result.stderr))
                    if expected:
                        self.assertEqual(result.stdout, b"status=ready\n")
                        self.assertEqual(seen, [("/health/ready", None)])
                        args[args.index("localhost")] = "wrong.invalid"
                        rejected = subprocess.run(args, capture_output=True, timeout=10)
                        self.assertEqual(rejected.returncode, 3)
                        self.assertIn(b"DOCTOR_ONLINE_INSPECTION_UNAVAILABLE", rejected.stdout)
                        self.assertEqual(seen, [("/health/ready", None)])
                    else:
                        self.assertIn(b"DOCTOR_ONLINE_INSPECTION_UNAVAILABLE", result.stdout)
                        self.assertEqual(seen, [])
                finally:
                    server.shutdown()
                    server.server_close()
                    worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
