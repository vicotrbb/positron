use super::*;
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn request() -> api::LogQueryRequest {
    api::LogQueryRequest {
        pipeline:
            r#"pipeline:v1 logs | range query_time 0 100 | project record["absent"] | limit 2"#
                .into(),
        budget: Some(api::LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 16,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    }
}

fn missing_response() -> TestResult<api::LogQueryResponse> {
    use api::*;
    let budget = request().budget.ok_or("fixture budget")?;
    let response = LogQueryResponse {
        events: vec![
            LogQueryEvent {
                event: Some(log_query_event::Event::Header(LogQueryHeader {
                    columns: vec![LogQueryColumn {
                        name: r#"record["absent"]"#.into(),
                        value_type: "attribute_occurrence_set".into(),
                        nullable: true,
                    }],
                    snapshot: Some(LogQuerySnapshot {
                        identity: vec![1; 32],
                        generation: 1,
                        frontier: 0,
                    }),
                    ordering: vec![LogQueryOrdering {
                        column: "query_time".into(),
                        value_type: "query_time".into(),
                        direction: "ascending".into(),
                    }],
                    effective_budget: Some(budget),
                    lease: Some(LogQueryLease {
                        identity: vec![1; 16],
                        expiry_unix_seconds: 1,
                    }),
                    initial_cursor: None,
                })),
            },
            LogQueryEvent {
                event: Some(log_query_event::Event::Batch(LogQueryBatch {
                    sequence: 0,
                    rows: vec![LogQueryRow {
                        cells: vec![LogQueryCell {
                            value: Some(log_query_cell::Value::Missing(LogQueryMissing {})),
                        }],
                        replayed: false,
                    }],
                    prior_digest: vec![0; 32],
                    digest: vec![1; 32],
                })),
            },
            LogQueryEvent {
                event: Some(log_query_event::Event::Terminal(LogQueryTerminal {
                    state: "complete".into(),
                    stats: Some(LogQueryStats {
                        records: 1,
                        last_sequence: Some(0),
                        result_digest: vec![1; 32],
                        cumulative_budget: Some(budget),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            },
        ],
    };
    response.validate()?;
    Ok(response)
}

fn reply(status: u16, body: &[u8], retry: bool) -> Vec<u8> {
    let hint = if retry { "Retry-After: 1\r\n" } else { "" };
    let mut bytes = format!("HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{hint}Connection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

// A bounded loopback peer records the actual body; it owns no client policy.
fn scripted<T>(
    replies: Vec<(Vec<u8>, bool)>,
    run: impl FnOnce(SocketAddr) -> TestResult<T>,
) -> TestResult<(TestResult<T>, Vec<Vec<u8>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&stop);
    let server = std::thread::spawn(move || -> std::io::Result<Vec<Vec<u8>>> {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut requests = Vec::new();
        for (response, trickle) in replies {
            let mut stream = loop {
                if finished.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    return Ok(requests);
                }
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    },
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let count = stream.read(&mut chunk)?;
                if count == 0 {
                    return Ok(requests);
                }
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() > api::MAX_REQUEST_BYTES + 8192 {
                    return Err(std::io::Error::other("fixture request bound"));
                }
                if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                    let header =
                        std::str::from_utf8(&bytes[..end]).map_err(std::io::Error::other)?;
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        })
                        .ok_or_else(|| std::io::Error::other("fixture content length"))?;
                    if bytes.len() >= end + 4 + length {
                        requests.push(bytes[end + 4..end + 4 + length].to_vec());
                        break;
                    }
                }
            }
            if trickle {
                let end = response
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .ok_or_else(|| std::io::Error::other("fixture response head"))?
                    + 4;
                stream.write_all(&response[..end])?;
                for byte in &response[end..] {
                    if finished.load(Ordering::Relaxed) || Instant::now() >= deadline {
                        break;
                    }
                    if let Err(error) = stream.write_all(&[*byte]) {
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ) {
                            break;
                        }
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            } else if !response.is_empty() {
                stream.write_all(&response)?;
            }
        }
        Ok(requests)
    });
    let result = run(endpoint);
    stop.store(true, Ordering::Relaxed);
    let requests = server.join().map_err(|_| "query fixture peer panicked")??;
    Ok((result, requests))
}

#[test]
fn explicit_capacity_then_missing_preserves_the_encoded_query() -> TestResult<()> {
    let request = request();
    let expected = missing_response()?;
    let (result, bodies) = scripted(
        vec![
            (
                reply(
                    429,
                    &api::query_rejection(429, "capacity_unavailable")?,
                    true,
                ),
                false,
            ),
            (reply(200, &expected.encode()?, false), false),
        ],
        |endpoint| execute_query(endpoint, "query-canary", &request),
    )?;
    assert_eq!(result?, expected);
    assert_eq!(bodies, vec![request.encode()?; 2]);
    Ok(())
}

#[test]
fn only_explicit_capacity_is_retried() -> TestResult<()> {
    let request = request();
    let capacity = api::query_rejection(429, "capacity_unavailable")?;
    for first in [
        Vec::new(),
        reply(
            401,
            &api::query_rejection(401, "authentication_rejected")?,
            false,
        ),
        reply(503, &api::query_rejection(503, "query_unavailable")?, false),
        reply(429, br#"{"code":"unknown"}"#, true),
        reply(429, &capacity, false),
        reply(200, b"{}", false),
    ] {
        let (result, bodies) = scripted(
            vec![
                (first, false),
                (reply(200, &missing_response()?.encode()?, false), false),
            ],
            |endpoint| execute_query(endpoint, "query-canary", &request),
        )?;
        let error = result
            .err()
            .ok_or("invalid refusal unexpectedly succeeded")?
            .to_string();
        assert!(
            !error.contains("query-canary"),
            "query error exposed credential"
        );
        assert_eq!(bodies, vec![request.encode()?]);
    }
    Ok(())
}

#[test]
fn capacity_cannot_extend_the_original_absolute_request_budget() -> TestResult<()> {
    let response = reply(
        429,
        &api::query_rejection(429, "capacity_unavailable")?,
        true,
    );
    let request = request();
    let mut elapsed = Duration::ZERO;
    let (result, bodies) = scripted(vec![(response, false); 8], |endpoint| {
        let started = Instant::now();
        let result = execute_query(endpoint, "query-canary", &request);
        elapsed = started.elapsed();
        result
    })?;
    assert_eq!(
        result
            .err()
            .ok_or("capacity unexpectedly succeeded")?
            .to_string(),
        "projection query deadline expired"
    );
    assert!(elapsed < Duration::from_secs(6));
    assert!(!bodies.is_empty() && bodies.len() < 8);
    let expected = request.encode()?;
    assert!(bodies.iter().all(|body| *body == expected));
    Ok(())
}

#[test]
fn trickled_body_cannot_refresh_the_total_deadline() -> TestResult<()> {
    let mut elapsed = Duration::ZERO;
    let (result, bodies) = scripted(
        vec![(reply(200, &missing_response()?.encode()?, false), true)],
        |endpoint| {
            let started = Instant::now();
            let result = execute_query(endpoint, "query-canary", &request());
            elapsed = started.elapsed();
            result
        },
    )?;
    assert!(result.is_err());
    assert!(elapsed < Duration::from_secs(6));
    assert_eq!(bodies.len(), 1);
    Ok(())
}

#[test]
fn response_capture_retains_the_canonical_bound() -> TestResult<()> {
    let (result, bodies) = scripted(
        vec![(
            reply(200, &vec![b'x'; api::MAX_RESPONSE_BYTES + 1], false),
            false,
        )],
        |endpoint| execute_query(endpoint, "query-canary", &request()),
    )?;
    assert_eq!(
        result
            .err()
            .ok_or("oversized response succeeded")?
            .to_string(),
        "projection query response exceeded canonical bound"
    );
    assert_eq!(bodies.len(), 1);
    Ok(())
}

fn generated_capacity_then_terminal(incomplete: bool, expected_refusals: usize) -> TestResult<()> {
    let request = request();
    let mut expected = missing_response()?;
    if incomplete {
        let Some(Event::Terminal(terminal)) = expected
            .events
            .last_mut()
            .and_then(|event| event.event.as_mut())
        else {
            return Err("fixture terminal missing".into());
        };
        terminal.state = "incomplete".into();
        terminal.reason = "budget_exhausted".into();
        terminal
            .stats
            .as_mut()
            .ok_or("fixture stats missing")?
            .limiting_budget = Some("scanned_bytes".into());
    }
    let bytes = expected.encode()?;
    let rejection = reply(
        429,
        &api::query_rejection(429, "capacity_unavailable")?,
        true,
    );
    let mut replies = vec![(rejection, false); expected_refusals];
    replies.push((reply(200, &bytes, false), false));
    let (result, bodies) = scripted(replies, |endpoint| {
        let client =
            api::LogQueryServiceClient::new(api::LogQueryTransport::PlaintextOptOut { endpoint })?;
        super::super::execute_admitted_query(&client, "query-canary", &request)
    })?;
    let (response, capacity_refusals) = result?;
    assert_eq!(response, expected);
    assert_eq!(
        capacity_refusals, expected_refusals as u64,
        "each canonical capacity refusal must be counted exactly"
    );
    assert_eq!(bodies, vec![request.encode()?; expected_refusals + 1]);
    Ok(())
}

#[test]
fn generated_capacity_then_complete_preserves_the_encoded_query() -> TestResult<()> {
    generated_capacity_then_terminal(false, 1)
}

#[test]
fn generated_capacity_then_incomplete_preserves_the_encoded_query() -> TestResult<()> {
    generated_capacity_then_terminal(true, 1)
}

#[test]
fn generated_admission_does_not_retry_auth_unavailable_or_transport() -> TestResult<()> {
    let request = request();
    for first in [
        Vec::new(),
        reply(
            401,
            &api::query_rejection(401, "authentication_rejected")?,
            false,
        ),
        reply(503, &api::query_rejection(503, "query_unavailable")?, false),
        reply(429, br#"{"code":"unknown"}"#, true),
    ] {
        let (result, bodies) = scripted(
            vec![
                (first, false),
                (reply(200, &missing_response()?.encode()?, false), false),
            ],
            |endpoint| {
                let client =
                    api::LogQueryServiceClient::new(api::LogQueryTransport::PlaintextOptOut {
                        endpoint,
                    })?;
                super::super::execute_admitted_query(&client, "query-canary", &request)
            },
        )?;
        let error = result
            .err()
            .ok_or("invalid refusal unexpectedly succeeded")?;
        assert!(
            !error.to_string().contains("query-canary"),
            "query error exposed credential"
        );
        assert_eq!(bodies, vec![request.encode()?]);
    }
    Ok(())
}

#[test]
fn generated_repeated_capacity_expires_admission_without_a_late_attempt() -> TestResult<()> {
    let request = request();
    let capacity = reply(
        429,
        &api::query_rejection(429, "capacity_unavailable")?,
        true,
    );
    let (result, bodies) = scripted(vec![(capacity, false); 8], |endpoint| {
        let client =
            api::LogQueryServiceClient::new(api::LogQueryTransport::PlaintextOptOut { endpoint })?;
        super::super::execute_admitted_query(&client, "query-canary", &request)
    })?;
    assert_eq!(
        result
            .err()
            .ok_or("capacity unexpectedly succeeded")?
            .to_string(),
        "typed query admission window expired"
    );
    assert!(
        !bodies.is_empty() && bodies.len() <= 5,
        "admission replay exceeded its bounded attempt window"
    );
    let expected = request.encode()?;
    assert!(bodies.iter().all(|body| *body == expected));
    Ok(())
}

#[test]
fn generated_repeated_capacity_counts_every_rejected_attempt() -> TestResult<()> {
    generated_capacity_then_terminal(false, 2)
}
