"""Public telemetry outcomes for the NixOS VM. Credentials never enter argv or logs."""
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

claim = dict(line.split("=", 1) for line in pathlib.Path("/root/positron-claim").read_text().splitlines())
marker = "nix-retained-117"
deadline = time.monotonic() + 30
if sys.argv[1] == "ingest":
    body = json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": [
        {"timeUnixNano": "42", "body": {"stringValue": marker}}
    ]}]}]}).encode()
    while True:
        request = urllib.request.Request("http://127.0.0.1:4313/v1/logs", body,
            {"Authorization": "Bearer " + claim["ingest_secret"], "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 200
                break
        except urllib.error.HTTPError as error:
            if error.code != 429 or time.monotonic() >= deadline:
                raise RuntimeError("ingest did not acknowledge telemetry") from None
            time.sleep(1)
else:
    query = pathlib.Path("/root/positron-query.json")
    query.write_text(json.dumps({"pipeline": "logs | range query_time 0 100 | limit 16", "budget": {
        "scannedBytes": "1048576", "decodedRecords": "16", "outputRows": "16",
        "outputBytes": "16384", "memoryBytes": "1048576", "cpuWorkUnits": "15",
        "wallSeconds": "5", "maximumTimeRangeNanoseconds": "100"}}))
    while True:
        result = subprocess.run(["positron", "query", "--endpoint", "127.0.0.1:4311",
            "--credential-stdin", "--allow-plaintext", "--request", str(query)],
            input=claim["query_secret"].encode(), capture_output=True, timeout=10)
        if result.returncode == 0:
            assert marker.encode() in result.stdout, "acknowledged record missing"
            assert b"complete" in result.stdout, "query did not complete"
            break
        if time.monotonic() >= deadline or b"capacity unavailable" not in result.stderr:
            raise RuntimeError("public query failed")
        time.sleep(1)
