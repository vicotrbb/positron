//! Real HTTP responses preserve the canonical policy error taxonomy.
use positron_api::policy::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BEARER: &str = "private-policy-credential-canary";

fn exchange<T>(
    path: &str,
    expected_body: serde_json::Value,
    status: u16,
    body: &str,
    call: impl FnOnce(PolicyPreviewTransport) -> T,
) -> std::io::Result<T> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| -> std::io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(std::io::Error::other("peer accept deadline"));
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    },
                    Err(e) => return Err(e),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let mut bytes = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(std::io::Error::other("peer read deadline"));
                }
                stream.set_read_timeout(Some(remaining))?;
                let count = stream.read(&mut buffer)?;
                if count == 0 || bytes.len() + count > 8192 {
                    return Err(std::io::Error::other("peer request bound"));
                }
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                    let headers =
                        std::str::from_utf8(&bytes[..end]).map_err(std::io::Error::other)?;
                    assert!(headers.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
                    assert!(
                        headers
                            .to_ascii_lowercase()
                            .contains(&format!("authorization: bearer {BEARER}"))
                    );
                    let length = headers
                        .lines()
                        .find_map(|l| {
                            let (n, v) = l.split_once(':')?;
                            n.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .ok_or_else(|| std::io::Error::other("peer length absent"))?;
                    if bytes.len() >= end + 4 + length {
                        let actual: serde_json::Value =
                            serde_json::from_slice(&bytes[end + 4..end + 4 + length])
                                .map_err(std::io::Error::other)?;
                        assert_eq!(actual, expected_body);
                        break;
                    }
                }
            }
            write!(
                stream,
                "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
            Ok(())
        });
        let result = call(PolicyPreviewTransport::PlaintextOptOut { endpoint });
        peer.join()
            .map_err(|_| std::io::Error::other("peer panicked"))??;
        Ok(result)
    })
}

#[test]
fn activation_keeps_stale_generation_distinct_from_conflict_and_untrusted_errors() -> TestResult {
    let request = PolicyActivateRequest::new(
        "{\"generation\":2,\"rules\":[]}".into(),
        1,
        "01010101-0101-0101-0101-010101010101".into(),
    );
    let cases = [
        (
            400,
            r#"{"code":"invalid_request"}"#,
            PolicyActivateServiceClientFailure::InvalidRequest,
        ),
        (
            401,
            r#"{"code":"authentication_rejected"}"#,
            PolicyActivateServiceClientFailure::AuthenticationRejected,
        ),
        (
            409,
            r#"{"code":"stale_generation","resource_generation":2,"semantic_diff":"generation advanced"}"#,
            PolicyActivateServiceClientFailure::StaleGeneration {
                resource_generation: 2,
                semantic_diff: "generation advanced".into(),
            },
        ),
        (
            409,
            r#"{"code":"idempotency_conflict"}"#,
            PolicyActivateServiceClientFailure::IdempotencyConflict,
        ),
        (
            503,
            r#"{"code":"administration_unavailable"}"#,
            PolicyActivateServiceClientFailure::AdministrationUnavailable,
        ),
        (
            409,
            r#"{"code":"stale_generation","resource_generation":0,"semantic_diff":"private-response-canary"}"#,
            PolicyActivateServiceClientFailure::Transport,
        ),
        (
            409,
            r#"{"code":"stale_generation","resource_generation":2,"semantic_diff":""}"#,
            PolicyActivateServiceClientFailure::Transport,
        ),
        (
            409,
            r#"{"code":"stale_generation","resource_generation":"2","semantic_diff":"private-response-canary"}"#,
            PolicyActivateServiceClientFailure::Transport,
        ),
        (
            409,
            r#"{"code":"stale_generation","resource_generation":2}"#,
            PolicyActivateServiceClientFailure::Transport,
        ),
        (
            409,
            r#"{"code":"future-private-response-canary"}"#,
            PolicyActivateServiceClientFailure::Transport,
        ),
        (
            401,
            r#"{"code":"stale_generation","resource_generation":2,"semantic_diff":"private-response-canary"}"#,
            PolicyActivateServiceClientFailure::Transport,
        ),
        (
            503,
            "private-response-canary",
            PolicyActivateServiceClientFailure::Transport,
        ),
        (
            200,
            "private-response-canary",
            PolicyActivateServiceClientFailure::Transport,
        ),
    ];
    for (status, body, expected) in cases {
        let result = exchange(
            HTTP_ACTIVATE_PATH,
            serde_json::to_value(&request)?,
            status,
            body,
            |transport| PolicyActivateServiceClient::new(transport)?.activate(BEARER, &request),
        )?;
        let error = result.expect_err("published rejection");
        assert_eq!(error, expected);
        assert!(!format!("{error} {error:?}").contains("private-response-canary"));
        assert!(!error.to_string().contains(BEARER));
    }
    let large=serde_json::json!({"code":"stale_generation","resource_generation":2,"semantic_diff":"x".repeat(1025)}).to_string();
    assert_eq!(
        exchange(
            HTTP_ACTIVATE_PATH,
            serde_json::to_value(&request)?,
            409,
            &large,
            |t| PolicyActivateServiceClient::new(t)?.activate(BEARER, &request)
        )?,
        Err(PolicyActivateServiceClientFailure::Transport)
    );
    Ok(())
}

#[test]
fn read_only_policy_clients_keep_published_rejections_and_redact_unknown_responses() -> TestResult {
    // Each distinct generated client must preserve the published mapping, even
    // though their request/response schemas differ.
    let preview = PolicyPreviewRequest::new("{}".into());
    let test = PolicyTestRequest::new("{}".into(), "{}".into());
    let diff = PolicyDiffRequest::new("{}".into(), "{}".into());
    let explain = PolicyExplainRequest::new("{}".into(), "{}".into());
    for (status, body) in [
        (400, r#"{"code":"invalid_request"}"#),
        (401, r#"{"code":"authentication_rejected"}"#),
        (503, r#"{"code":"administration_unavailable"}"#),
        (409, r#"{"code":"future-private-response-canary"}"#),
        (503, "private-response-canary"),
    ] {
        let a = exchange(
            HTTP_VALIDATE_PATH,
            serde_json::to_value(&preview)?,
            status,
            body,
            |t| PolicyPreviewServiceClient::new(t)?.validate(BEARER, &preview),
        )?
        .unwrap_err();
        let b = exchange(
            HTTP_TEST_PATH,
            serde_json::to_value(&test)?,
            status,
            body,
            |t| PolicyTestServiceClient::new(t)?.test(BEARER, &test),
        )?
        .unwrap_err();
        let c = exchange(
            HTTP_DIFF_PATH,
            serde_json::to_value(&diff)?,
            status,
            body,
            |t| PolicyDiffServiceClient::new(t)?.diff(BEARER, &diff),
        )?
        .unwrap_err();
        let d = exchange(
            HTTP_EXPLAIN_PATH,
            serde_json::to_value(&explain)?,
            status,
            body,
            |t| PolicyExplainServiceClient::new(t)?.explain(BEARER, &explain),
        )?
        .unwrap_err();
        match status {
            400 => {
                assert_eq!(a, PolicyPreviewServiceClientFailure::InvalidRequest);
                assert_eq!(b, PolicyTestServiceClientFailure::InvalidRequest);
                assert_eq!(c, PolicyDiffServiceClientFailure::InvalidRequest);
                assert_eq!(d, PolicyExplainServiceClientFailure::InvalidRequest);
            },
            401 => {
                assert_eq!(a, PolicyPreviewServiceClientFailure::AuthenticationRejected);
                assert_eq!(b, PolicyTestServiceClientFailure::AuthenticationRejected);
                assert_eq!(c, PolicyDiffServiceClientFailure::AuthenticationRejected);
                assert_eq!(d, PolicyExplainServiceClientFailure::AuthenticationRejected);
            },
            503 if body.starts_with('{') => {
                assert_eq!(
                    a,
                    PolicyPreviewServiceClientFailure::AdministrationUnavailable
                );
                assert_eq!(b, PolicyTestServiceClientFailure::AdministrationUnavailable);
                assert_eq!(c, PolicyDiffServiceClientFailure::AdministrationUnavailable);
                assert_eq!(
                    d,
                    PolicyExplainServiceClientFailure::AdministrationUnavailable
                );
            },
            _ => {
                assert_eq!(a, PolicyPreviewServiceClientFailure::Transport);
                assert_eq!(b, PolicyTestServiceClientFailure::Transport);
                assert_eq!(c, PolicyDiffServiceClientFailure::Transport);
                assert_eq!(d, PolicyExplainServiceClientFailure::Transport);
            },
        }
        for error in [a.to_string(), b.to_string(), c.to_string(), d.to_string()] {
            assert!(!error.contains("private-response-canary"));
            assert!(!error.contains(BEARER));
        }
    }
    Ok(())
}
