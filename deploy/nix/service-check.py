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
if sys.argv[1] == "readiness-diagnostics":
    # Failure-only projection of existing public facts; never print raw responses.
    observation = {"event": "readiness_status", "outcome": "unavailable"}
    request = urllib.request.Request("http://127.0.0.1:4310/status", headers={
        "Authorization": "Bearer " + claim["administrator_secret"]})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read(65537)
        if len(body) > 65536:
            raise ValueError("status exceeds observation bound")
        status = json.loads(body)
        phase = status["phase"]
        integrity = status["integrity_degraded"]
        uncertain = status["maintenance"]["clock_uncertain"]
        storage = status["doctor"]["required_families"]["storage"]
        pressure = storage["disk_pressure"]
        usable = storage["usable_disk_bytes"]
        if (phase not in {"starting", "recovering", "serving", "draining", "fenced", "stopping", "stopped"}
                or type(integrity) is not bool or type(uncertain) is not bool
                or pressure not in {"healthy", "soft", "hard"}
                or type(usable) is not int or not 0 <= usable <= 18446744073709551615):
            raise ValueError("status contains unsupported observation fields")
        observation.update(outcome="observed", phase=phase, integrity_degraded=integrity,
                           clock_uncertain=uncertain, disk_pressure=pressure, usable_disk_bytes=usable)
    except urllib.error.HTTPError as error:
        observation["outcome"] = "authentication_rejected" if error.code in {401, 403} else "refused"
        error.close()
    except TimeoutError:
        observation["outcome"] = "timeout"
    except urllib.error.URLError as error:
        observation["outcome"] = "timeout" if isinstance(error.reason, TimeoutError) else "unavailable"
    except (ValueError, KeyError, TypeError, OSError):
        pass
    print(json.dumps(observation))

    observation = {"event": "readiness_systemd", "outcome": "unavailable"}
    try:
        result = subprocess.run(["systemctl", "show", "positron", "--property="
            "ActiveState,SubState,MainPID,ExecMainStatus,NRestarts"],
            capture_output=True, timeout=3)
        if result.returncode or len(result.stdout) > 4096:
            raise ValueError("systemd observation unavailable")
        lines = result.stdout.decode("ascii").splitlines()
        values = dict(line.split("=", 1) for line in lines)
        if (len(lines) != 5 or set(values) != {"ActiveState", "SubState", "MainPID", "ExecMainStatus", "NRestarts"}
                or values["ActiveState"] not in {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}
                or values["SubState"] not in {"running", "dead", "failed", "exited", "start", "start-pre", "start-post", "stop", "stop-sigterm", "stop-sigkill", "stop-post", "auto-restart", "reload", "reload-signal", "reload-notify"}):
            raise ValueError("systemd contains unsupported observation fields")
        for field in ["MainPID", "ExecMainStatus", "NRestarts"]:
            if not values[field].isascii() or not values[field].isdigit() or len(values[field]) > 20:
                raise ValueError("systemd observation is not numeric")
            values[field] = int(values[field])
            if values[field] > 18446744073709551615:
                raise ValueError("systemd observation is out of range")
        observation.update(outcome="observed", **values)
    except (ValueError, TypeError, OSError, subprocess.TimeoutExpired):
        pass
    print(json.dumps(observation))
elif sys.argv[1] == "ingest":
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
    executions = 0
    last_terminal = {"last_terminal_state": "unavailable", "last_terminal_reason": "unavailable",
        "last_limiting_budget": "unavailable"}
    last_rejection = "none"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("query deadline elapsed")
        attempt += 1
        try:
            result = subprocess.run(["positron", "query", "--endpoint", "127.0.0.1:4311",
                "--credential-stdin", "--allow-plaintext", "--request", str(query)],
                input=claim["query_secret"].encode(), capture_output=True, timeout=remaining)
        except subprocess.TimeoutExpired:
            now = time.monotonic()
            print(json.dumps({"event": "query_timeout", "attempt": attempt,
                "elapsed_ms": max(0, int((now - (deadline - 30)) * 1000)),
                "remaining_ms": max(0, int((deadline - now) * 1000)),
                **last_terminal, "last_rejection": last_rejection}))
            raise RuntimeError("public query command timed out") from None
        if result.returncode == 0:
            executions += 1
            if time.monotonic() >= deadline:
                raise RuntimeError("query deadline elapsed")
            wall_exhausted = False
            try:
                if len(result.stdout) > 65536:
                    raise ValueError("query observation exceeds bound")
                events = json.loads(result.stdout)["events"]
                if (not isinstance(events, list) or not 1 <= len(events) <= 32
                        or any(not isinstance(event, dict) or len(event) != 1
                            or next(iter(event)) not in {"header", "batch", "terminal"}
                            or not isinstance(next(iter(event.values())), dict) for event in events)
                        or sum("terminal" in event for event in events) != 1):
                    raise ValueError("unsupported events")
                terminal = events[-1]["terminal"]
                stats = terminal["stats"]
                wall_exhausted = (terminal["state"] == "incomplete"
                    and terminal.get("reason") == "budget_exhausted"
                    and isinstance(stats, dict) and stats.get("limitingBudget") == "wall_seconds"
                    and stats.get("wallSeconds") == "5"
                    and all(isinstance(value, str) and value.isascii() and value.isdigit()
                        and len(value) <= 20 and int(value) <= 18446744073709551615
                        for field, value in stats.items() if field in {
                            "records", "scannedBytes", "decodedRecords", "outputRows", "outputBytes",
                            "memoryPeakBytes", "cpuWorkUnits", "wallSeconds", "lastSequence",
                            "resumeCount", "repeatedBatchCount"}))
            except (ValueError, KeyError, TypeError, RecursionError):
                pass
            if wall_exhausted:
                last_terminal = {"last_terminal_state": "incomplete",
                    "last_terminal_reason": "budget_exhausted", "last_limiting_budget": "wall_seconds"}
                if executions >= 3:
                    raise RuntimeError("query wall allowance exhausted")
                if time.monotonic() + 1 >= deadline:
                    raise RuntimeError("query deadline elapsed")
                # A fresh read has no mutation or cumulative-cursor authority.
                # Discard this incomplete result; require one complete answer.
                time.sleep(1)
                continue
            if result.stdout.count(marker.encode()) != 1:
                observation = {"event": "query_marker_failure",
                    "marker_count": result.stdout.count(marker.encode()), "outcome": "unavailable"}
                try:
                    if len(result.stdout) > 65536:
                        raise ValueError("query observation exceeds bound")
                    events = json.loads(result.stdout)["events"]
                    if not isinstance(events, list) or not 1 <= len(events) <= 32:
                        raise ValueError("unsupported events")
                    kinds = []
                    for event in events:
                        if not isinstance(event, dict) or len(event) != 1:
                            raise ValueError("unsupported event")
                        kind = next(iter(event))
                        if kind not in {"header", "batch", "terminal"}:
                            raise ValueError("unsupported event kind")
                        kinds.append(kind)
                    terminal = events[-1]["terminal"]
                    state, reason = terminal["state"], terminal.get("reason", "")
                    if state not in {"complete", "incomplete"} or reason not in {
                            "", "unauthorized", "idempotency_conflict", "invalid_budget", "budget_exhausted",
                            "invalid_cursor", "snapshot_expired", "authorization_changed", "cancelled",
                            "resource_admission_refused", "resource_exhausted", "unsupported_query",
                            "store_unavailable", "incomplete_data", "malformed_persistent_data", "internal"}:
                        raise ValueError("unsupported terminal")
                    stats = {}
                    source = terminal.get("stats", {})
                    if not isinstance(source, dict):
                        raise ValueError("unsupported statistics")
                    for field in ("records", "scannedBytes", "decodedRecords", "outputBytes",
                                  "memoryPeakBytes", "cpuWorkUnits", "wallSeconds", "lastSequence",
                                  "resumeCount", "repeatedBatchCount"):
                        if field in source:
                            value = source[field]
                            if (not isinstance(value, str) or not value.isascii()
                                    or not value.isdigit() or len(value) > 20
                                    or int(value) > 18446744073709551615):
                                raise ValueError("unsupported statistic")
                            stats[field] = int(value)
                    if "limitingBudget" in source:
                        limiter = source["limitingBudget"]
                        if limiter not in {"scanned_bytes", "decoded_records", "output_rows",
                                "output_bytes", "memory_bytes", "cpu_work_units", "wall_seconds",
                                "maximum_time_range_nanoseconds"}:
                            raise ValueError("unsupported limiting budget")
                        stats["limitingBudget"] = limiter
                    observation.update(outcome="observed", event_kinds=kinds,
                        terminal_state=state, terminal_reason=reason, stats=stats)
                except (ValueError, KeyError, TypeError, RecursionError):
                    pass
                print(json.dumps(observation))
            assert result.stdout.count(marker.encode()) == 1, "acknowledged record missing or duplicated"
            response = json.loads(result.stdout)
            assert response["events"][-1]["terminal"]["state"] == "complete", "query did not complete"
            if time.monotonic() >= deadline:
                raise RuntimeError("query deadline elapsed")
            break
        last_rejection = {
            b"positron: invalid bounded query request": "invalid_request",
            b"positron: query authentication rejected": "authentication_rejected",
            b"positron: query capacity unavailable; retry after backoff": "capacity_unavailable",
            b"positron: query unavailable; inspect instance readiness": "query_unavailable",
            b"positron: query transport or response unavailable": "transport",
        }.get(result.stderr.strip(), "other")
        if time.monotonic() + 1 >= deadline or b"capacity unavailable" not in result.stderr:
            elapsed_ms = int((time.monotonic() - (deadline - 30)) * 1000)
            raise RuntimeError(f"public query failed: code={last_rejection} returncode={result.returncode} "
                f"attempt={attempt} elapsed_ms={elapsed_ms}")
        time.sleep(1)
