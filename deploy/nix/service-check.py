"""Public telemetry outcomes for the NixOS VM. Credentials never enter argv or logs."""
import json
import pathlib
import os
import re
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
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("ingest acknowledgment deadline elapsed")
        request = urllib.request.Request("http://127.0.0.1:4313/v1/logs", body,
            {"Authorization": "Bearer " + claim["ingest_secret"], "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=remaining) as response:
                assert response.status == 200
                if time.monotonic() > deadline:
                    raise RuntimeError("ingest acknowledgment deadline elapsed")
                break
        except urllib.error.HTTPError as error:
            with error:
                try:
                    rejection = json.loads(error.read(4096))
                except ValueError:
                    rejection = None
                retryable = (error.code == 429 and error.headers.get("Retry-After") == "1"
                    and rejection == {"code": 14, "message": "OTLP Logs ingest capacity is unavailable"})
            if not retryable or time.monotonic() + 1 >= deadline:
                raise RuntimeError("ingest did not acknowledge telemetry") from None
            time.sleep(1)
else:
    query = pathlib.Path("/root/positron-query.json")
    query.write_text(json.dumps({"pipeline": "logs | range query_time 0 100 | limit 16", "budget": {
        "scannedBytes": "1048576", "decodedRecords": "16", "outputRows": "16",
        "outputBytes": "16384", "memoryBytes": "1048576", "cpuWorkUnits": "15",
        "wallSeconds": "5", "maximumTimeRangeNanoseconds": "100"}}))
    attempt = 0
    while True:
        attempt += 1
        result = subprocess.run(["positron", "query", "--endpoint", "127.0.0.1:4311",
            "--credential-stdin", "--allow-plaintext", "--request", str(query)],
            input=claim["query_secret"].encode(), capture_output=True, timeout=10,
            env={**os.environ, "POSITRON_117_QUERY_PROBE": "1"})
        if result.returncode == 0:
            assert result.stdout.count(marker.encode()) == 1, "acknowledged record missing or duplicated"
            response = json.loads(result.stdout)
            assert response["events"][-1]["terminal"]["state"] == "complete", "query did not complete"
            break
        if time.monotonic() >= deadline or b"capacity unavailable" not in result.stderr:
            probe_lines = [line for line in result.stderr.splitlines()
                if re.fullmatch(rb"positron-query-probe stage=(send|read) timeout=(true|false|unknown)", line)]
            if len(probe_lines) == 1:
                print(probe_lines[0].decode("ascii"), file=sys.stderr)
            elif len(probe_lines) > 1:
                print("positron-query-probe incomplete=multiple", file=sys.stderr)
            classification_stderr = b"\n".join(line for line in result.stderr.splitlines()
                if line not in probe_lines)
            failure = {
                b"positron: invalid bounded query request": "invalid_request",
                b"positron: query authentication rejected": "authentication_rejected",
                b"positron: query capacity unavailable; retry after backoff": "capacity_unavailable",
                b"positron: query unavailable; inspect instance readiness": "query_unavailable",
                b"positron: query transport or response unavailable": "transport",
            }.get(classification_stderr.strip(), "other")
            elapsed_ms = int((time.monotonic() - (deadline - 30)) * 1000)
            raise RuntimeError(f"public query failed: code={failure} returncode={result.returncode} "
                f"attempt={attempt} elapsed_ms={elapsed_ms}")
        time.sleep(1)
