//! Wait retains one operation identity across typed transient read failures.
use positron_api::backup::{BackupRequest, BackupResponse};
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
const CREDENTIAL: &str = "backup-wait-administrator";
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn response(status: &str) -> TestResult<String> {
    let value = BackupResponse {
        verification_report: None,
        verification_report_checksum: None,
        operation_revision: 1,
        terminal_error_code: None,
        kind: "verification".into(),
        cleanup_pending: false,
        retention_receipt: None,
        operation: positron_api::repository::RepositoryOperation {
            id: ID.into(),
            status: status.into(),
            phase: if status == "cancelled" {
                "cancelled"
            } else {
                "accepted"
            }
            .into(),
            progress_percent: if status == "cancelled" { 100 } else { 0 },
            retry: "inspect_by_operation_id".into(),
            cancellation: if status == "cancelled" {
                "cancelled"
            } else {
                "allowed_before_publication"
            }
            .into(),
            irreversible_boundary: "not_crossed".into(),
            lookup_expires_at_unix_seconds: None,
        },
        repository: None,
        receipt: None,
        restored_publication: None,
    };
    Ok(String::from_utf8(
        value.encode().map_err(|_| "response encoding")?,
    )?)
}

fn run(
    replies: Vec<(u16, String)>,
    wait: bool,
) -> TestResult<(std::process::Output, Vec<BackupRequest>, Duration)> {
    run_with_delay(replies, wait, Duration::ZERO)
}
fn run_with_delay(
    replies: Vec<(u16, String)>,
    wait: bool,
    delay: Duration,
) -> TestResult<(std::process::Output, Vec<BackupRequest>, Duration)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let stopped = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&stopped);
    let server = std::thread::spawn(move || -> TestResult<(Vec<BackupRequest>, Duration)> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut requests = Vec::new();
        let mut first_request = None;
        let mut request_span = Duration::ZERO;
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                },
                Err(error) => return Err(error.into()),
            };
            let received = Instant::now();
            request_span = received.duration_since(*first_request.get_or_insert(received));
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            assert_eq!(line, "POST /v1/backups:manage HTTP/1.1\r\n");
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
            assert!(length <= positron_api::backup::MAX_REQUEST_BYTES);
            let mut body = vec![0; length];
            reader.read_exact(&mut body)?;
            requests.push(BackupRequest::decode(&body).map_err(|_| "request encoding")?);
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
        Ok((requests, request_span))
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"));
    child.args([
        "backup",
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
    let (requests, request_span) = server.join().map_err(|_| "server panic")??;
    for request in &requests {
        assert_eq!(request.action, "status");
        assert_eq!(request.operation_id.as_deref(), Some(ID));
        assert!(request.idempotency_key.is_none());
    }
    assert!(!String::from_utf8_lossy(&output.stdout).contains(CREDENTIAL));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CREDENTIAL));
    Ok((output, requests, request_span))
}
#[test]
fn wait_retries_only_typed_capacity_for_the_same_operation() -> TestResult {
    let (output, requests, _) = run(
        vec![
            (503, r#"{"code":"capacity_unavailable"}"#.into()),
            (200, response("running")?),
            (503, r#"{"code":"capacity_unavailable"}"#.into()),
            (200, response("cancelled")?),
        ],
        true,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(requests.len(), 4);
    assert!(String::from_utf8(output.stdout)?.contains("status=cancelled"));
    Ok(())
}
#[test]
fn wait_keeps_other_errors_fatal_and_status_one_shot() -> TestResult {
    for (wait, status, code, expected) in [
        (
            true,
            401,
            "authentication_rejected",
            "authentication rejected",
        ),
        (
            true,
            503,
            "administration_unavailable",
            "administration unavailable",
        ),
        (true, 503, "unknown", "transport outcome unknown"),
        (true, 409, "precondition_failed", "precondition failed"),
        (false, 503, "capacity_unavailable", "capacity unavailable"),
    ] {
        let (output, requests, _) = run(vec![(status, format!("{{\"code\":\"{code}\"}}"))], wait)?;
        assert!(!output.status.success());
        assert_eq!(requests.len(), 1);
        assert!(String::from_utf8(output.stderr)?.contains(expected));
    }
    Ok(())
}
#[test]
fn capacity_wait_expires_within_its_original_budget() -> TestResult {
    let (output, requests, request_span) = run(
        vec![(503, r#"{"code":"capacity_unavailable"}"#.into())],
        true,
    )?;
    assert!(!output.status.success());
    assert!(requests.len() > 1);
    assert!(
        request_span < Duration::from_secs(1),
        "request span {request_span:?}"
    );
    assert!(String::from_utf8(output.stderr)?.contains("operation outcome remains unknown"));
    Ok(())
}
#[test]
fn wait_bounds_the_first_status_read_by_its_original_budget() -> TestResult {
    let (output, requests, _) = run_with_delay(
        vec![(200, response("cancelled")?)],
        true,
        Duration::from_secs(2),
    )?;
    assert!(
        !output.status.success(),
        "late response must not become success"
    );
    assert_eq!(requests.len(), 1);
    assert!(String::from_utf8(output.stderr)?.contains("operation outcome remains unknown"));
    Ok(())
}

#[test]
fn expired_wait_retains_the_last_observed_state_after_capacity_refusals() -> TestResult {
    let (output, requests, request_span) = run(
        vec![
            (200, response("running")?),
            (503, r#"{"code":"capacity_unavailable"}"#.into()),
        ],
        true,
    )?;
    assert!(!output.status.success());
    assert!(requests.len() > 1);
    assert!(request_span < Duration::from_secs(1));
    assert!(
        String::from_utf8(output.stdout)?.contains(&format!("operation_id={ID} status=running"))
    );
    assert!(String::from_utf8(output.stderr)?.contains("operation outcome remains unknown"));
    Ok(())
}

#[test]
fn exhausted_generated_client_read_budget_sends_no_request() -> TestResult {
    use positron_api::backup::{BackupServiceClient, BackupServiceClientFailure, BackupTransport};
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut {
        endpoint: listener.local_addr()?,
    })?;
    let request =
        BackupRequest::decode(format!(r#"{{"action":"status","operation_id":"{ID}"}}"#).as_bytes())
            .map_err(|_| "request encoding")?;
    assert!(matches!(
        client.manage_with_timeout(CREDENTIAL, &request, Duration::ZERO),
        Err(BackupServiceClientFailure::Transport)
    ));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}
