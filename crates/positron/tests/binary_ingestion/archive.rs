use super::*;

pub(super) fn stop(child: &mut Option<Child>) -> TestResult {
    let process = child.as_mut().ok_or("missing archive process")?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &process.id().to_string()])
            .status()?
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = process.try_wait()? {
            assert!(
                status.success(),
                "archive initialization/inspection must Drain gracefully"
            );
            *child = None;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("archive process Drain deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn query_log(
    binary: &std::path::Path,
    root: &std::path::Path,
    endpoint: std::net::SocketAddr,
    query_secret: &str,
) -> TestResult<Vec<u8>> {
    use positron_api::log_query::*;
    let request = LogQueryRequest {
        pipeline: "logs | range query_time 0 100 | limit 16".into(),
        budget: Some(LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 15,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    let result = query_response(binary, root, endpoint, query_secret, &request)?;
    let bodies = result
        .events
        .iter()
        .filter_map(|event| match event.event.as_ref()? {
            log_query_event::Event::Batch(batch) => Some(
                batch
                    .rows
                    .iter()
                    .flat_map(|row| row.cells.iter())
                    .filter_map(|cell| match cell.value.as_ref()? {
                        log_query_cell::Value::NativeValue(value) => match value.value.as_ref()? {
                            log_query_value::Value::TextValue(text) => Some(text.as_str()),
                            _ => None,
                        },
                        _ => None,
                    }),
            ),
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(bodies, ["binary-otlp"]);
    let Some(log_query_event::Event::Terminal(terminal)) =
        result.events.last().and_then(|event| event.event.as_ref())
    else {
        return Err("missing query terminal".into());
    };
    assert_eq!(terminal.state, "complete");
    let stats = terminal.stats.as_ref().ok_or("missing query statistics")?;
    assert_eq!(stats.records, 1);
    Ok(stats.result_digest.clone())
}

fn query_response(
    binary: &std::path::Path,
    root: &std::path::Path,
    endpoint: std::net::SocketAddr,
    query_secret: &str,
    request: &positron_api::log_query::LogQueryRequest,
) -> TestResult<positron_api::log_query::LogQueryResponse> {
    use positron_api::log_query::LogQueryResponse;
    let path = root.join("query-request.json");
    std::fs::write(&path, request.encode()?)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let output = loop {
        let mut child = Command::new(binary)
            .args([
                "query",
                "--endpoint",
                &endpoint.to_string(),
                "--credential-stdin",
                "--allow-plaintext",
                "--request",
            ])
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("missing query credential pipe")?
            .write_all(query_secret.as_bytes())?;
        let output = collect_query(child, deadline)?;
        if output.status.success() {
            break output;
        }
        let error = String::from_utf8_lossy(&output.stderr);
        if !error.contains("query capacity unavailable; retry after backoff")
            || Instant::now() + Duration::from_secs(1) >= deadline
        {
            return Err(format!("public query refused: {error}").into());
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    Ok(LogQueryResponse::decode(&output.stdout)?)
}

pub(super) fn query_capacity_refusal(
    binary: &std::path::Path,
    root: &std::path::Path,
    endpoint: std::net::SocketAddr,
    credential: &str,
) -> TestResult {
    use positron_api::log_query::*;
    let request = LogQueryRequest::decode(br#"{"pipeline":"logs | range query_time 0 2000 | limit 100","budget":{"scannedBytes":"1048576","decodedRecords":"100","outputRows":"100","outputBytes":"16384","memoryBytes":"1048576","cpuWorkUnits":"16","wallSeconds":"5","maximumTimeRangeNanoseconds":"2000"}}"#)?;
    let response = query_response(binary, root, endpoint, credential, &request)?;
    let Some(log_query_event::Event::Terminal(terminal)) = response
        .events
        .last()
        .and_then(|event| event.event.as_ref())
    else {
        return Err("missing bounded-query terminal".into());
    };
    assert_eq!(
        terminal.state, "incomplete",
        "a capacity-limited scan cannot claim complete"
    );
    assert!(
        terminal
            .stats
            .as_ref()
            .ok_or("query stats")?
            .limiting_budget
            .as_deref()
            .is_some_and(|budget| !budget.is_empty())
    );
    Ok(())
}

pub(super) fn query_refusals(
    root: &std::path::Path,
    endpoint: std::net::SocketAddr,
    query: &str,
    admin: &str,
    ingest: &str,
) -> TestResult {
    use positron_api::log_query::*;
    let body = fs::read(root.join("query-request.json"))?;
    for (case, credential) in ["", admin, ingest].into_iter().enumerate() {
        query_authentication_refusal(endpoint, &body, credential, [query, admin, ingest], case)?;
    }
    let bearer = format!("Bearer {query}");
    let response = request(
        endpoint.port(),
        HTTP_PATH,
        &[("Authorization", &bearer), ("X-Scope-OrgID", "other")],
        &body,
    )?;
    assert!(response.starts_with("HTTP/1.1 401 "));
    let response = request_with_capacity_retry(
        endpoint.port(),
        HTTP_PATH,
        &[("Authorization", &bearer)],
        br#"{"pipeline":"logs","unknown":1}"#,
        Duration::from_secs(5),
    )?;
    assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    let (_, payload) = response
        .split_once("\r\n\r\n")
        .ok_or("missing invalid request body")?;
    assert_eq!(
        decode_query_rejection(400, payload.as_bytes()),
        LogQueryServiceClientFailure::InvalidRequest
    );
    let response = request(
        endpoint.port(),
        HTTP_PATH,
        &[("Authorization", &bearer)],
        &vec![b' '; MAX_REQUEST_BYTES + 1],
    )?;
    assert!(response.starts_with("HTTP/1.1 413 "));
    let (_, payload) = response
        .split_once("\r\n\r\n")
        .ok_or("missing oversized rejection body")?;
    assert_eq!(
        decode_query_rejection(413, payload.as_bytes()),
        LogQueryServiceClientFailure::InvalidRequest
    );
    let mut request = LogQueryRequest::decode(&body)?;
    request
        .budget
        .as_mut()
        .ok_or("missing budget")?
        .output_bytes = 1;
    query_output_bytes_incomplete(endpoint, query, &request)
}

pub(super) fn query_output_bytes_incomplete(
    endpoint: std::net::SocketAddr,
    credential: &str,
    request: &positron_api::log_query::LogQueryRequest,
) -> TestResult {
    use positron_api::log_query::*;
    // This assertion requires an executed budget outcome, not a pre-admission
    // capacity refusal. Keep the same encoded request and original wall budget.
    let body = request.encode()?;
    let bearer = format!("Bearer {credential}");
    let deadline = Instant::now() + Duration::from_secs(5);
    let response = request_with_capacity_retry(
        endpoint.port(),
        HTTP_PATH,
        &[
            ("Authorization", &bearer),
            ("Content-Type", "application/json"),
        ],
        &body,
        Duration::from_secs(5),
    )?;
    if Instant::now() >= deadline {
        return Err("budget query exceeded its original wall budget".into());
    }
    if !response.starts_with("HTTP/1.1 200 ") {
        return Err("budget query did not execute successfully".into());
    }
    let (_, payload) = response
        .split_once("\r\n\r\n")
        .ok_or("missing budget query response body")?;
    let response = LogQueryResponse::decode(payload.as_bytes())?;
    let Some(log_query_event::Event::Terminal(terminal)) = response
        .events
        .last()
        .and_then(|event| event.event.as_ref())
    else {
        return Err("missing incomplete terminal".into());
    };
    assert_eq!(terminal.state, "incomplete");
    assert_eq!(terminal.reason, "budget_exhausted");
    assert_eq!(
        terminal
            .stats
            .as_ref()
            .ok_or("missing incomplete stats")?
            .limiting_budget
            .as_deref(),
        Some("output_bytes")
    );
    Ok(())
}

pub(super) fn query_authentication_refusal(
    endpoint: std::net::SocketAddr,
    body: &[u8],
    credential: &str,
    secrets: [&str; 3],
    case: usize,
) -> TestResult {
    use positron_api::log_query::*;
    let bearer = format!("Bearer {credential}");
    let response = request_with_capacity_retry(
        endpoint.port(),
        HTTP_PATH,
        &[("Authorization", &bearer)],
        body,
        Duration::from_secs(5),
    )?;
    let diagnostic = refusal_diagnostic(&response, secrets);
    if !response.starts_with("HTTP/1.1 401 ") {
        return Err(format!("query authentication case {case}: {diagnostic}").into());
    }
    let (_, payload) = response
        .split_once("\r\n\r\n")
        .ok_or("missing rejection body")?;
    if decode_query_rejection(401, payload.as_bytes())
        != LogQueryServiceClientFailure::AuthenticationRejected
    {
        return Err(
            format!("query authentication case {case} typed rejection: {diagnostic}").into(),
        );
    }
    assert!(!response.contains(secrets[0]));
    Ok(())
}

fn refusal_diagnostic(response: &str, secrets: [&str; 3]) -> String {
    let mut diagnostic = response.to_owned();
    for secret in secrets.into_iter().filter(|secret| !secret.is_empty()) {
        diagnostic = diagnostic.replace(secret, "[REDACTED]");
    }
    diagnostic.chars().take(2048).collect()
}

#[test]
fn query_refusal_diagnostic_redacts_all_claims_before_truncation() {
    let secrets = [
        "query-credential-canary",
        "administrator-credential-canary",
        "ingest-credential-canary",
    ];
    let response = format!(
        "HTTP/1.1 429 Capacity\r\nRetry-After: 1\r\n\r\n{} {} {}",
        secrets[0], secrets[1], secrets[2]
    );
    assert_eq!(
        refusal_diagnostic(&response, secrets),
        "HTTP/1.1 429 Capacity\r\nRetry-After: 1\r\n\r\n[REDACTED] [REDACTED] [REDACTED]"
    );
    for secret in secrets {
        let crossing = format!("{}{secret} outside-bound", "x".repeat(2040));
        assert_eq!(
            refusal_diagnostic(&crossing, secrets),
            format!("{}[REDACTE", "x".repeat(2040))
        );
    }
}

pub(super) fn collect_query(child: Child, deadline: Instant) -> TestResult<std::process::Output> {
    Ok(child_output::wait_before(
        child,
        deadline,
        Duration::from_millis(10),
        "public query exceeded its original wall budget",
    )?)
}
