use super::*;

fn scripted_requests(
    responses: &[(u16, serde_json::Value)],
    request: impl FnOnce(std::net::SocketAddr) -> TestResult<String>,
) -> TestResult<(TestResult<String>, Vec<serde_json::Value>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let responses = responses.to_vec();
    let (completed, finished) = std::sync::mpsc::channel::<()>();
    let server = std::thread::spawn(move || -> Result<_, String> {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if matches!(
                            finished.try_recv(),
                            Err(std::sync::mpsc::TryRecvError::Disconnected)
                        ) {
                            return Ok(requests);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => return Err(error.to_string()),
                }
            };
            // Accepted sockets inherit nonblocking mode on macOS.
            stream.set_nonblocking(false).map_err(|e| e.to_string())?;
            // Native maintenance clients allow five seconds for delivery;
            // the fixture must not impose a shorter per-read deadline.
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).map_err(|e| e.to_string())?;
                headers.push(byte[0]);
                if headers.len() > 8192 {
                    return Err("request headers exceeded bound".into());
                }
            }
            let headers = String::from_utf8(headers).map_err(|e| e.to_string())?;
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .ok_or("request content length")?;
            if length > 4096 {
                return Err("request body exceeded bound".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            requests.push(serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
            if status == 0 {
                continue;
            }
            let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).map_err(|e| e.to_string())?;
            stream.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        Ok(requests)
    });
    // The caller already bounds its request; keep this fixture alive through
    // CLI startup and join it even if the caller fails or panics.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| request(endpoint)));
    drop(completed);
    let joined = server.join();
    let result = match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let requests = joined.map_err(|_| "script server panic")??;
    Ok((result, requests))
}
fn scripted_mutation(
    responses: &[(u16, serde_json::Value)],
) -> TestResult<(TestResult<String>, Vec<serde_json::Value>)> {
    scripted_requests(responses, |endpoint| {
        mutate(
            "repository",
            serde_json::json!({
                "action":"init", "idempotency_key":"11111111-1111-4111-8111-111111111111",
                "repository_id":"22222222-2222-4222-8222-222222222222", "locator":"/fixture/repository"
            }),
            endpoint,
            "test-administrator",
        )
    })
}
#[test]
fn scripted_status_server_survives_valid_client_startup_delay() -> TestResult {
    use positron_api::repository::{
        RepositoryRequest, RepositoryServiceClient, RepositoryTransport,
    };
    let (result, requests) = scripted_requests(
        &[(200, serde_json::json!({"catalog_generation":12}))],
        |endpoint| {
            std::thread::sleep(Duration::from_millis(3100));
            let client =
                RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint })?;
            let response = client.manage(
                "test-administrator",
                &RepositoryRequest::decode(br#"{"action":"status"}"#)?,
            )?;
            Ok(response.catalog_generation.to_string())
        },
    )?;
    assert_eq!(result?, "12");
    assert_eq!(requests, vec![serde_json::json!({"action":"status"})]);
    Ok(())
}

#[test]
fn scripted_status_server_accepts_delivery_within_the_native_request_budget() -> TestResult {
    let (result, requests) = scripted_requests(
        &[(200, serde_json::json!({"catalog_generation":12}))],
        |endpoint| {
            let mut stream = TcpStream::connect(endpoint)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            write!(
                stream,
                "POST {} HTTP/1.1\r\nHost: fixture\r\n",
                positron_api::repository::HTTP_PATH
            )?;
            std::thread::sleep(Duration::from_millis(1100));
            let body = br#"{"action":"status"}"#;
            write!(stream, "Content-Length: {}\r\n\r\n", body.len())?;
            stream.write_all(body)?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            assert!(
                response.starts_with("HTTP/1.1 200 "),
                "fixture response: {response:?}"
            );
            let (_, body) = response.split_once("\r\n\r\n").ok_or("response body")?;
            let decoded: serde_json::Value = serde_json::from_str(body)?;
            Ok(decoded["catalog_generation"].to_string())
        },
    )?;
    assert_eq!(result?, "12");
    assert_eq!(requests, vec![serde_json::json!({"action":"status"})]);
    Ok(())
}

#[test]
fn wait_reconciles_lost_read_response_using_the_same_retained_operation() -> TestResult {
    let mut terminal = success();
    terminal["operation"]["status"] = serde_json::json!("succeeded");
    terminal["operation"]["phase"] = serde_json::json!("published");
    let (result, requests) = scripted_requests(
        &[(0, serde_json::Value::Null), (200, terminal)],
        |endpoint| {
            let output = wait(
                &native_binary::executable(),
                "repository",
                endpoint,
                "test-administrator",
                "11111111111111111111111111111111",
            )?;
            field(&output, "status")
        },
    )?;
    assert_eq!(result?, "succeeded");
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests.first().and_then(|request| request.get("action")),
        Some(&serde_json::json!("status"))
    );
    assert_eq!(
        requests
            .first()
            .and_then(|request| request.get("operation_id")),
        Some(&serde_json::json!("11111111111111111111111111111111"))
    );
    assert_eq!(
        requests.first(),
        requests.get(1),
        "only the same read-only operation status may be replayed"
    );
    Ok(())
}

#[test]
fn wait_refuses_authentication_failure_without_replaying_operation_status() -> TestResult {
    let (result, requests) = scripted_requests(
        &[
            (401, serde_json::json!({"code":"authentication_rejected"})),
            (200, serde_json::json!({})),
        ],
        |endpoint| {
            let output = wait(
                &native_binary::executable(),
                "repository",
                endpoint,
                "test-administrator",
                "11111111111111111111111111111111",
            )?;
            field(&output, "status")
        },
    )?;
    assert!(result.is_err());
    assert_eq!(
        requests.len(),
        2,
        "one status read followed by maintenance diagnostics"
    );
    assert_ne!(
        requests.first(),
        requests.get(1),
        "definite rejection must not replay the operation status"
    );
    Ok(())
}

fn success() -> serde_json::Value {
    serde_json::json!({"catalog_generation":12,"operation":{
        "id":"11111111111111111111111111111111","status":"pending","phase":"accepted",
        "progress_percent":0,"retry":"inspect_by_operation_id","cancellation":"allowed_before_drain",
        "irreversible_boundary":"not_crossed"
    }})
}
#[test]
fn mutation_capacity_replays_exact_request_and_returns_original_operation() -> TestResult {
    let (result, requests) = scripted_mutation(&[
        (200, serde_json::json!({"catalog_generation":10})),
        (503, serde_json::json!({"code":"capacity_unavailable"})),
        (200, success()),
    ])?;
    assert_eq!(result?, "11111111111111111111111111111111");
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests.get(1),
        requests.get(2),
        "capacity may follow acceptance; replay the original request"
    );
    Ok(())
}
#[test]
fn mutation_refreshes_generation_only_after_definite_staleness() -> TestResult {
    let (result, requests) = scripted_mutation(&[
        (503, serde_json::json!({"code":"capacity_unavailable"})),
        (200, serde_json::json!({"catalog_generation":10})),
        (409, serde_json::json!({"code":"stale_generation"})),
        (200, serde_json::json!({"catalog_generation":11})),
        (200, success()),
    ])?;
    result?;
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests
            .get(2)
            .and_then(|r| r.get("expected_catalog_generation")),
        Some(&serde_json::json!(10))
    );
    assert_eq!(
        requests
            .get(4)
            .and_then(|r| r.get("expected_catalog_generation")),
        Some(&serde_json::json!(11))
    );
    assert_eq!(
        requests.get(2).and_then(|r| r.get("idempotency_key")),
        requests.get(4).and_then(|r| r.get("idempotency_key"))
    );
    Ok(())
}
#[test]
fn mutation_refuses_terminal_error_without_retry() -> TestResult {
    let (result, requests) = scripted_mutation(&[
        (200, serde_json::json!({"catalog_generation":10})),
        (409, serde_json::json!({"code":"idempotency_conflict"})),
    ])?;
    assert!(result.is_err());
    assert_eq!(requests.len(), 2);
    Ok(())
}

#[path = "upgrade_status_tests.rs"]
mod upgrade_status_tests;
