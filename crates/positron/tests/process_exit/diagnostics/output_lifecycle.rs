//! Real native lifecycle owns and reaps the optional output child.
#![cfg(unix)]
use super::output_helper::full_pipe;
use super::*;
use std::{os::unix::process::ExitStatusExt, process::Child, time::Instant};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct OutputChild(Child);
impl std::ops::Deref for OutputChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for OutputChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for OutputChild {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_none()) && self.0.kill().is_ok() {
            let _reaped = self.0.wait();
        }
    }
}
fn children(parent: u32) -> TestResult<Vec<u32>> {
    let output = Command::new("ps").args(["-axo", "pid=,ppid="]).output()?;
    assert!(output.status.success());
    assert!(output.stdout.len() <= 1024 * 1024);
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            (ppid == parent).then_some(pid)
        })
        .collect())
}
fn await_helper(parent: &mut Child) -> TestResult<u32> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(1);
    let mut samples = 0;
    loop {
        let children = children(parent.id())?;
        samples += 1;
        assert!(
            children.len() <= 1,
            "one invocation must own at most one output helper"
        );
        if let Some(pid) = children.first() {
            return Ok(*pid);
        }
        if Instant::now() >= deadline {
            return Err(format!("native output child was not observed: parent_status={:?} elapsed_ms={} ps_samples={samples}", parent.try_wait()?, started.elapsed().as_millis()).into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn await_terminated(pid: u32) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let output = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()?;
        let state = String::from_utf8(output.stdout)?;
        // A dead parent's orphan can briefly await the operating-system reaper.
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("output helper {pid} remains alive: {state}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn terminate(child: &mut Child) -> TestResult {
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(wait_for_child(child)?.code(), Some(0));
    Ok(())
}
fn http(port: u16, path: &str, credential: &str, body: &[u8]) -> TestResult<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let remaining = || -> std::io::Result<Duration> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "output lifecycle HTTP deadline exhausted",
            ))
        } else {
            Ok(remaining)
        }
    };
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()
    ).into_bytes();
    request.extend_from_slice(body);
    loop {
        let mut stream = TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            remaining()?,
        )?;
        let mut pending = request.as_slice();
        while !pending.is_empty() {
            stream.set_write_timeout(Some(remaining()?))?;
            let written = stream.write(pending)?;
            if written == 0 {
                return Err("output lifecycle request write closed".into());
            }
            pending = pending.get(written..).ok_or("request write length")?;
        }
        let mut response = Vec::new();
        loop {
            stream.set_read_timeout(Some(remaining()?))?;
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                return Err("output lifecycle HTTP response truncated".into());
            }
            response.extend_from_slice(buffer.get(..count).ok_or("response read length")?);
            if response.len() > 65_536 {
                return Err("output lifecycle HTTP response exceeded bound".into());
            }
            if let Some(boundary) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let head = std::str::from_utf8(response.get(..boundary).ok_or("HTTP headers")?)?;
                let lengths = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
                    .map(|(_, value)| value.trim().parse::<usize>())
                    .collect::<Result<Vec<_>, _>>()?;
                let [length] = lengths.as_slice() else {
                    return Err("HTTP response content length".into());
                };
                let total = boundary
                    .checked_add(4)
                    .and_then(|head| head.checked_add(*length))
                    .filter(|total| *total <= 65_536)
                    .ok_or("HTTP response length bound")?;
                if response.len() == total {
                    break;
                }
                if response.len() > total {
                    return Err("HTTP response exceeds declared length".into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("output lifecycle HTTP deadline exhausted".into());
        }
        let boundary = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .ok_or("HTTP response boundary")?;
        let payload = response.get(boundary + 4..).ok_or("HTTP response body")?;
        let head = std::str::from_utf8(response.get(..boundary).ok_or("HTTP headers")?)?;
        // Ingest admits no records on this refusal. Query is a fresh read whose
        // complete canonical rejection carries no accepted execution outcome.
        let ingest_capacity = path == "/v1/logs"
            && head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("Retry-After: 1"))
            && serde_json::from_slice::<serde_json::Value>(payload).ok()
                == Some(
                    serde_json::json!({"code": 14, "message": "OTLP Logs ingest capacity is unavailable"}),
                );
        let query_capacity = path == positron_api::log_query::HTTP_PATH
            && head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("Retry-After"))
                .map(|(_, value)| value.trim())
                .eq(["1"])
            && positron_api::log_query::decode_query_rejection(429, payload)
                == positron_api::log_query::LogQueryServiceClientFailure::CapacityUnavailable
            && positron_api::log_query::query_rejection(429, "capacity_unavailable")
                .ok()
                .and_then(|expected| serde_json::from_slice::<serde_json::Value>(&expected).ok())
                .is_some_and(|expected| {
                    serde_json::from_slice::<serde_json::Value>(payload).ok() == Some(expected)
                });
        let retryable =
            response.starts_with(b"HTTP/1.1 429 ") && (ingest_capacity || query_capacity);
        if retryable && deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(1)
        {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        if !response.starts_with(b"HTTP/1.1 200 ") {
            return Err(format!(
                "public {path} failed with {}",
                String::from_utf8_lossy(&response)
            )
            .into());
        }
        return Ok(payload.to_vec());
    }
}

#[test]
fn parent_sigkill_ends_its_output_helper_while_stderr_stays_full() -> TestResult {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    let (_reader, writer) = full_pipe()?;
    let mut parent = OutputChild(
        Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["serve", "--set", "storage.data_directory=relative"])
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()?,
    );
    let helper = await_helper(&mut parent)?;
    std::thread::sleep(Duration::from_millis(50));
    assert!(parent.try_wait()?.is_none());
    parent.kill()?;
    assert_eq!(parent.wait()?.signal(), Some(9));
    await_terminated(helper)?;
    Ok(())
}

#[test]
fn normal_and_saturated_output_reap_before_graceful_marker_and_retain_acknowledged_data()
-> TestResult {
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    for saturated in [false, true] {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-output-drain-{nonce}"));
        let roots = ChildRoots::new(&root)?;
        let paths =
            BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let ports = available_ports()?;
        let config = root.join("positron.toml");
        fs::write(
            &config,
            format!(
                "schema_version=1\n[runtime]\nshutdown_grace_seconds=2\n[listener]\ncontrol_path=\"{}\"\noperations_bind_address=\"127.0.0.1:{}\"\napi_bind_address=\"127.0.0.1:{}\"\notlp_grpc_bind_address=\"127.0.0.1:{}\"\notlp_http_bind_address=\"127.0.0.1:{}\"\nloki_push_bind_address=\"127.0.0.1:{}\"\noperations_transport=\"plaintext\"\napi_transport=\"plaintext\"\notlp_grpc_transport=\"plaintext\"\notlp_http_transport=\"plaintext\"\nloki_push_transport=\"plaintext\"\n[storage]\ndata_directory=\"{}\"\nsecrets_directory=\"{}\"\n[security]\nlocal_key_file=\"{}\"\n",
                std::env::temp_dir()
                    .join(format!("positron-output-{nonce}.sock"))
                    .display(),
                ports[0],
                ports[1],
                ports[2],
                ports[3],
                ports[4],
                roots.data.display(),
                roots.secrets.display(),
                roots.secrets.join("local-root-key.v1").display()
            ),
        )?;
        let (mut reader, writer) = if saturated {
            full_pipe()?
        } else {
            std::io::pipe()?
        };
        let flags = rustix::fs::fcntl_getfl(&writer)? & rustix::fs::OFlags::NONBLOCK;
        let mut child = OutputChild(
            Command::new(env!("CARGO_BIN_EXE_positron"))
                .args(["serve", "--config"])
                .arg(&config)
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer.try_clone()?))
                .spawn()?,
        );
        wait_for_ready(ports[0])?;
        let helper = children(child.id())?.first().copied();
        http(ports[3], "/v1/logs", claim.ingest_secret().ok_or("ingest credential")?, br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"42","body":{"stringValue":"output-helper-retained"}}]}]}]}"#)?;
        terminate(&mut child)?;
        if let Some(helper) = helper {
            await_terminated(helper)?;
        }
        assert_eq!(
            rustix::fs::fcntl_getfl(&writer)? & rustix::fs::OFlags::NONBLOCK,
            flags
        );
        let reopened = InstanceBootstrap::reopen(&paths)?;
        assert!(reopened.graceful_shutdown_record()?.is_some());
        drop(reopened);
        drop(writer);
        if !saturated {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            assert!(!bytes.is_empty());
            for line in bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let value: serde_json::Value = serde_json::from_slice(line)?;
                assert!(value["event"].is_string());
            }
        }
        let mut restarted = OutputChild(
            Command::new(env!("CARGO_BIN_EXE_positron"))
                .args(["serve", "--config"])
                .arg(&config)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        wait_for_ready(ports[0])?;
        let query = http(ports[1], positron_api::log_query::HTTP_PATH, claim.query_secret().ok_or("query credential")?, br#"{"pipeline":"logs | range query_time 0 100 | limit 16","budget":{"scannedBytes":"1048576","decodedRecords":"16","outputRows":"16","outputBytes":"16384","memoryBytes":"1048576","cpuWorkUnits":"15","wallSeconds":"5","maximumTimeRangeNanoseconds":"100"}}"#)?;
        let response = positron_api::log_query::LogQueryResponse::decode(&query)?;
        use positron_api::log_query::log_query_event::Event;
        assert!(response.events.last().and_then(|event| event.event.as_ref()).is_some_and(|event| matches!(event, Event::Terminal(terminal) if terminal.state == "complete" && terminal.stats.as_ref().is_some_and(|stats| stats.records == 1))));
        assert_eq!(
            String::from_utf8(query)?
                .matches("output-helper-retained")
                .count(),
            1
        );
        terminate(&mut restarted)?;
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn accept_http_fixture(listener: &std::net::TcpListener) -> std::io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "fixture connection deadline exhausted",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            },
            Err(error) => return Err(error),
        }
    }
}

fn read_http_fixture_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    for _ in 0..4096 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            return Ok(request);
        }
    }
    Err(std::io::Error::other("fixture headers exceed bound"))
}

#[test]
fn output_lifecycle_retries_only_explicit_ingest_capacity_with_the_same_request() -> TestResult {
    retry_capacity_case(
        "/v1/logs",
        br#"{"code":14,"message":"OTLP Logs ingest capacity is unavailable"}"#,
    )
}

#[test]
fn output_lifecycle_retries_only_explicit_query_capacity_with_the_same_request() -> TestResult {
    let payload = positron_api::log_query::query_rejection(429, "capacity_unavailable")
        .map_err(|_| "query refusal fixture")?;
    retry_capacity_case(positron_api::log_query::HTTP_PATH, &payload)
}

fn retry_capacity_case(path: &str, payload: &[u8]) -> TestResult {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let refusal = format!(
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        std::str::from_utf8(payload)?
    );
    let peer = std::thread::spawn(move || -> std::io::Result<Vec<Vec<u8>>> {
        let mut requests = Vec::new();
        for (index, response) in [
            refusal.as_str(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        ]
        .into_iter()
        .enumerate()
        {
            let context = |stage, error| {
                std::io::Error::other(format!(
                    "capacity peer request={index} stage={stage}: {error}"
                ))
            };
            let mut stream =
                accept_http_fixture(&listener).map_err(|error| context("accept", error))?;
            let mut request = read_http_fixture_headers(&mut stream)
                .map_err(|error| context("headers", error))?;
            let mut body = [0; 4];
            stream
                .read_exact(&mut body)
                .map_err(|error| context("body", error))?;
            request.extend_from_slice(&body);
            requests.push(request);
            stream
                .write_all(response.as_bytes())
                .map_err(|error| context("response", error))?;
        }
        Ok(requests)
    });
    let result = http(port, path, "fixture-credential", b"body");
    let requests = peer.join().map_err(|_| "capacity peer panicked")?;
    let result = result.map_err(|error| {
        format!(
            "capacity client: {error}; peer_failure={:?}",
            requests.as_ref().err()
        )
    })?;
    assert_eq!(result, b"{}");
    let requests = requests?;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert!(
        requests[0]
            .windows(b"Authorization: Bearer fixture-credential".len())
            .any(|bytes| bytes == b"Authorization: Bearer fixture-credential")
    );
    Ok(())
}

#[test]
fn output_lifecycle_does_not_retry_noncanonical_or_cross_protocol_refusals() -> TestResult {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    for (path, retry, message) in [
        ("/v1/logs", "2", "OTLP Logs ingest capacity is unavailable"),
        ("/v1/logs", "1", "other refusal"),
        (
            positron_api::log_query::HTTP_PATH,
            "1",
            "OTLP Logs ingest capacity is unavailable",
        ),
    ] {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let payload = serde_json::json!({"code": 14, "message": message}).to_string();
        let peer = std::thread::spawn(move || -> std::io::Result<()> {
            let mut stream = accept_http_fixture(&listener)?;
            read_http_fixture_headers(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {retry}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )?;
            Ok(())
        });
        let result = http(port, path, "fixture-credential", b"");
        peer.join().map_err(|_| "refusal peer panicked")??;
        assert!(
            result
                .expect_err("noncanonical refusal must fail")
                .to_string()
                .contains("429 Too Many Requests")
        );
    }
    Ok(())
}

#[test]
fn output_lifecycle_query_capacity_metadata_and_retry_header_fail_closed() -> TestResult {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    let canonical = positron_api::log_query::query_rejection(429, "capacity_unavailable")
        .map_err(|_| "query refusal fixture")?;
    let value: serde_json::Value = serde_json::from_slice(&canonical)?;
    let mut cases = Vec::new();
    for field in [
        "code",
        "retryClass",
        "completionState",
        "source",
        "safeDetail",
    ] {
        let mut changed = value.clone();
        changed[field] = serde_json::json!("unknown");
        cases.push((changed.to_string(), "Retry-After: 1\r\n"));
        let mut missing = value.clone();
        assert!(
            missing
                .as_object_mut()
                .ok_or("refusal object")?
                .remove(field)
                .is_some()
        );
        cases.push((missing.to_string(), "Retry-After: 1\r\n"));
    }
    let mut extra = value.clone();
    extra["extra"] = serde_json::json!(true);
    cases.push((extra.to_string(), "Retry-After: 1\r\n"));
    let canonical = std::str::from_utf8(&canonical)?;
    cases.push((
        format!(
            "{{\"code\":\"PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE\",{}",
            canonical.strip_prefix('{').ok_or("refusal object")?
        ),
        "Retry-After: 1\r\n",
    ));
    cases.push((canonical.into(), "Retry-After: 1\r\nRetry-After: 1\r\n"));
    cases.push((canonical.into(), "Retry-After: 2\r\n"));
    for (payload, retry) in cases {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let peer = std::thread::spawn(move || -> std::io::Result<()> {
            let mut stream = accept_http_fixture(&listener)?;
            read_http_fixture_headers(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 429 Too Many Requests\r\n{retry}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )?;
            Ok(())
        });
        let result = http(
            port,
            positron_api::log_query::HTTP_PATH,
            "fixture-credential",
            b"",
        );
        peer.join().map_err(|_| "query refusal peer panicked")??;
        assert!(
            result
                .expect_err("noncanonical query refusal must fail")
                .to_string()
                .contains("429 Too Many Requests")
        );
    }
    Ok(())
}

#[test]
fn output_lifecycle_trickled_response_cannot_restart_the_original_deadline() -> TestResult {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let peer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stream = accept_http_fixture(&listener)?;
        read_http_fixture_headers(&mut stream)?;
        for _ in 0..60 {
            if stream.write_all(b"H").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    });
    let started = Instant::now();
    let result = http(port, "/v1/logs", "fixture-credential", b"");
    let elapsed = started.elapsed();
    peer.join().map_err(|_| "deadline peer panicked")??;
    assert!(result.is_err());
    assert!(elapsed >= Duration::from_secs(4));
    assert!(
        elapsed < Duration::from_millis(5800),
        "deadline restarted: {elapsed:?}"
    );
    Ok(())
}

#[test]
fn output_lifecycle_rejects_a_truncated_declared_response() -> TestResult {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let peer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stream = accept_http_fixture(&listener)?;
        read_http_fixture_headers(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}")?;
        Ok(())
    });
    let result = http(port, "/v1/logs", "fixture-credential", b"");
    peer.join()
        .map_err(|_| "truncated response peer panicked")??;
    assert!(
        result.is_err(),
        "an incomplete declared body cannot succeed"
    );
    Ok(())
}

#[test]
fn output_lifecycle_fixture_fails_without_a_second_connection() -> TestResult {
    #[cfg(target_os = "macos")]
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let first = TcpStream::connect(listener.local_addr()?)?;
    drop(accept_http_fixture(&listener)?);
    drop(first);
    let started = Instant::now();
    let error =
        accept_http_fixture(&listener).expect_err("missing retry must exhaust peer deadline");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(3));
    Ok(())
}
