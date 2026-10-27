"""Private test CA and a distinct server-only localhost certificate."""
import subprocess


def material(directory):
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Positron Compose test CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(directory / "ca-key.pem"), "-out", str(directory / "ca.pem"))
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
            "-keyout", str(directory / "server-key.pem"), "-out", str(directory / "server.csr"))
    extensions = directory / "server.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    openssl("x509", "-req", "-in", str(directory / "server.csr"), "-CA", str(directory / "ca.pem"),
            "-CAkey", str(directory / "ca-key.pem"), "-CAcreateserial", "-days", "1", "-sha256",
            "-extfile", str(extensions), "-out", str(directory / "server.pem"))
