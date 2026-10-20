use super::*;

fn scripted_mutation(
    responses: &[(u16, serde_json::Value)],
) -> TestResult<(TestResult<String>, Vec<serde_json::Value>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let responses = responses.to_vec();
    let server = std::thread::spawn(move || -> Result<_, String> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut requests = Vec::new();
        for (status, body) in responses {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Ok(requests);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    },
                    Err(error) => return Err(error.to_string()),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
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
            let bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).map_err(|e| e.to_string())?;
            stream.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        Ok(requests)
    });
    let result = mutate(
        "repository",
        serde_json::json!({
            "action":"init", "idempotency_key":"11111111-1111-4111-8111-111111111111",
            "repository_id":"22222222-2222-4222-8222-222222222222", "locator":"/fixture/repository"
        }),
        endpoint,
        "test-administrator",
    );
    let requests = server.join().map_err(|_| "script server panic")??;
    Ok((result, requests))
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
