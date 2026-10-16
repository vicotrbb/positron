//! Wait retains one operation identity across typed transient read failures.
use positron_api::repository::{RepositoryRequest, RepositoryResponse};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
const ID: &str = "abababababababababababababababab";
const CREDENTIAL: &str = "repository-wait-administrator";
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn response(status: &str) -> TestResult<String> {
    Ok(String::from_utf8(
        RepositoryResponse {
            catalog_generation: 7,
            operation: Some(positron_api::repository::RepositoryOperation {
                id: ID.into(),
                status: status.into(),
                phase: if status == "succeeded" {
                    "published"
                } else {
                    "accepted"
                }
                .into(),
                progress_percent: if status == "succeeded" { 100 } else { 0 },
                retry: "inspect_by_operation_id".into(),
                cancellation: "allowed_before_drain".into(),
                irreversible_boundary: "not_crossed".into(),
                lookup_expires_at_unix_seconds: None,
            }),
            identity: None,
            doctor: None,
            policy: None,
        }
        .encode()
        .map_err(|_| "response encoding")?,
    )?)
}
fn run(
    replies: Vec<(u16, String)>,
    wait: bool,
) -> TestResult<(std::process::Output, Vec<RepositoryRequest>)> {
    run_with_delay(replies, wait, Duration::ZERO)
}
fn run_with_delay(
    replies: Vec<(u16, String)>,
    wait: bool,
    delay: Duration,
) -> TestResult<(std::process::Output, Vec<RepositoryRequest>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let stopped = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&stopped);
    let server = std::thread::spawn(move || -> TestResult<Vec<RepositoryRequest>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut requests = Vec::new();
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                },
                Err(error) => return Err(error.into()),
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            assert_eq!(line, "POST /v1/repositories:manage HTTP/1.1\r\n");
            let mut length = None;
            let mut authenticated = false;
            loop {
                line.clear();
                reader.read_line(&mut line)?;
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    length = Some(value.trim().parse::<usize>()?);
                }
                authenticated |= lower.trim() == format!("authorization: bearer {CREDENTIAL}");
            }
            assert!(authenticated);
            let length = length.ok_or("request length")?;
            assert!(length <= positron_api::repository::MAX_REQUEST_BYTES);
            let mut body = vec![0; length];
            reader.read_exact(&mut body)?;
            requests.push(RepositoryRequest::decode(&body).map_err(|_| "request encoding")?);
            let (status, body) = replies
                .get(requests.len() - 1)
                .or_else(|| replies.last())
                .ok_or("reply")?;
            std::thread::sleep(delay);
            let sent = write!(
                stream,
                "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            if let Err(error) = sent
                && !(stop.load(Ordering::Acquire)
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ))
            {
                return Err(error.into());
            }
        }
        Ok(requests)
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"));
    child.args([
        "repository",
        if wait { "wait" } else { "status" },
        "--endpoint",
        &endpoint.to_string(),
        "--credential-stdin",
        "--allow-plaintext",
        "--operation-id",
        ID,
    ]);
    if wait {
        child.args(["--wait-seconds", "1"]);
    }
    let mut child = child
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("credential pipe")?
        .write_all(CREDENTIAL.as_bytes())?;
    let output = child.wait_with_output()?;
    stopped.store(true, Ordering::Release);
    let requests = server.join().map_err(|_| "server panic")??;
    for request in &requests {
        assert_eq!(request.action, "status");
        assert_eq!(request.operation_id.as_deref(), Some(ID));
        assert!(request.idempotency_key.is_none());
    }
    assert!(!String::from_utf8_lossy(&output.stdout).contains(CREDENTIAL));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CREDENTIAL));
    Ok((output, requests))
}
#[test]
fn wait_retries_only_transient_status_reads_for_the_same_operation() -> TestResult {
    let (output, requests) = run(
        vec![
            (503, r#"{"code":"administration_unavailable"}"#.into()),
            (200, response("pending")?),
            (503, r#"{"code":"administration_unavailable"}"#.into()),
            (503, r#"{"code":"capacity_unavailable"}"#.into()),
            (200, response("succeeded")?),
        ],
        true,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(requests.len(), 5);
    assert!(String::from_utf8(output.stdout)?.contains("status=succeeded"));
    Ok(())
}
#[test]
fn wait_does_not_retry_rejected_credentials_and_status_remains_one_shot() -> TestResult {
    for (wait, code, body, expected) in [
        (
            true,
            401,
            "authentication_rejected",
            "authentication rejected",
        ),
        (
            false,
            503,
            "administration_unavailable",
            "administration unavailable",
        ),
    ] {
        let (output, requests) = run(vec![(code, format!("{{\"code\":\"{body}\"}}"))], wait)?;
        assert!(!output.status.success());
        assert_eq!(requests.len(), 1);
        assert!(String::from_utf8(output.stderr)?.contains(expected));
    }
    Ok(())
}
#[test]
fn unavailable_wait_expires_without_resetting_its_original_budget() -> TestResult {
    let (output, requests) = run(
        vec![(503, r#"{"code":"administration_unavailable"}"#.into())],
        true,
    )?;
    assert!(!output.status.success());
    assert!(requests.len() > 1);
    assert!(String::from_utf8(output.stderr)?.contains("operation outcome remains unknown"));
    assert!(!String::from_utf8(output.stdout)?.contains("status=succeeded"));
    Ok(())
}

#[test]
fn wait_bounds_an_in_flight_status_read_by_its_remaining_budget() -> TestResult {
    let (output, requests) = run_with_delay(
        vec![(200, response("succeeded")?)],
        true,
        Duration::from_secs(2),
    )?;
    assert!(
        !output.status.success(),
        "a response after the wait deadline must not become success"
    );
    assert_eq!(requests.len(), 1);
    assert!(String::from_utf8(output.stderr)?.contains("operation outcome remains unknown"));
    Ok(())
}

#[test]
fn exhausted_status_read_budget_never_sends_a_request() -> TestResult {
    use positron_api::repository::{
        RepositoryServiceClient, RepositoryServiceClientFailure, RepositoryTransport,
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut {
        endpoint: listener.local_addr()?,
    })?;
    let request = RepositoryRequest::decode(
        format!(r#"{{"action":"status","operation_id":"{ID}"}}"#).as_bytes(),
    )
    .map_err(|_| "request encoding")?;
    assert!(matches!(
        client.manage_with_timeout(CREDENTIAL, &request, Duration::ZERO),
        Err(RepositoryServiceClientFailure::Transport)
    ));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn expired_wait_preserves_last_known_operation_state_after_unavailable_reads() -> TestResult {
    let (output, requests) = run(
        vec![
            (200, response("pending")?),
            (503, r#"{"code":"administration_unavailable"}"#.into()),
        ],
        true,
    )?;
    assert!(!output.status.success());
    assert!(requests.len() > 1);
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(&format!("operation_id={ID} status=pending")));
    assert!(!stdout.contains("status=succeeded"));
    assert!(String::from_utf8(output.stderr)?.contains("operation outcome remains unknown"));
    Ok(())
}
