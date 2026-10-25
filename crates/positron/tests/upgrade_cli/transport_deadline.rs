type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[path = "../support/bounded_child_output.rs"]
mod bounded_child_output;

fn receive_status_request(
    listener: &TcpListener,
    deadline: Instant,
) -> std::io::Result<(std::net::TcpStream, Vec<u8>)> {
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::other("peer accept deadline"));
                }
                std::thread::sleep(Duration::from_millis(1));
            },
            Err(error) => return Err(error),
        }
    };
    stream.set_nonblocking(false)?;
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    let body = loop {
        stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        let count = stream.read(&mut buffer)?;
        if count == 0 || request.len() + count > 8192 {
            return Err(std::io::Error::other(
                "peer request incomplete or oversized",
            ));
        }
        request.extend_from_slice(&buffer[..count]);
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..end])
                .map_err(|_| std::io::Error::other("peer headers invalid"))?;
            assert!(headers.starts_with("POST /v1/upgrades:manage HTTP/1.1\r\n"));
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .ok_or_else(|| std::io::Error::other("peer length absent"))?;
            if request.len() >= end + 4 + length {
                break request[end + 4..].to_vec();
            }
        }
    };
    Ok((stream, body))
}

fn invoke_status(
    delay: Duration,
    wait: Option<u64>,
    reply: bool,
    pending_first: bool,
) -> TestResult<(std::process::Output, std::io::Result<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let peer = std::thread::spawn(move || -> std::io::Result<_> {
        let (mut stream, body) = receive_status_request(&listener, deadline)?;
        if pending_first {
            let first_delay = Duration::from_millis(2500);
            if deadline.saturating_duration_since(Instant::now()) <= first_delay + delay {
                return Err(std::io::Error::other(
                    "peer has insufficient polling hold time",
                ));
            }
            std::thread::sleep(first_delay);
            let pending = serde_json::json!({"catalog_generation":7,"operation":{"id":"ab".repeat(16),"status":"running","phase":"preflight","progress_percent":0,"retry":"inspect_by_operation_id","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"},"details":{"source_version":"0.0.0","target_version":"0.0.1","source_manifest":"11".repeat(32),"target_manifest":"22".repeat(32),"source_artifact":"33".repeat(32),"target_artifact":"44".repeat(32),"configuration":"55".repeat(32),"format_epoch":2,"repository_id":"66666666-6666-6666-6666-666666666666","rollback_available":false}});
            let pending = positron_api::upgrade::UpgradeResponse::decode(
                &serde_json::to_vec(&pending).map_err(std::io::Error::other)?,
            )
            .and_then(|response| response.encode())
            .map_err(|_| std::io::Error::other("pending response invalid"))?;
            stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                pending.len()
            )?;
            stream.write_all(&pending)?;
            drop(stream);
            let (next, repeated) = receive_status_request(&listener, deadline)?;
            assert_eq!(repeated, body, "poll changed the original typed request");
            stream = next;
        }
        if !reply {
            drop(stream);
            let observe_until = Instant::now() + Duration::from_secs(1);
            while Instant::now() < observe_until {
                match listener.accept() {
                    Ok(_) => return Err(std::io::Error::other("unexpected request replay")),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    },
                    Err(error) => return Err(error),
                }
            }
            return Ok((body, Ok(())));
        }
        if deadline.saturating_duration_since(Instant::now()) <= delay {
            return Err(std::io::Error::other(
                "peer has insufficient response hold time",
            ));
        }
        std::thread::sleep(delay);
        let response = positron_api::upgrade::UpgradeResponse {
            catalog_generation: 7,
            operation: None,
            details: None,
        }
        .encode()
        .map_err(|_| std::io::Error::other("canonical response invalid"))?;
        stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        let delivery = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .and_then(|()| stream.write_all(&response));
        Ok((body, delivery))
    });
    let output = (|| -> std::io::Result<_> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
        command.args([
            "upgrade",
            if wait.is_some() { "wait" } else { "status" },
            "--operation-id",
            "abababababababababababababababab",
            "--endpoint",
            &endpoint.to_string(),
            "--credential-stdin",
            "--allow-plaintext",
        ]);
        if let Some(seconds) = wait {
            command.args(["--wait-seconds", &seconds.to_string()]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let credential = (|| -> std::io::Result<()> {
            let mut input = child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::other("credential input"))?;
            writeln!(input, "deadline-credential-canary")
        })();
        if let Err(error) = credential {
            let killed = child.kill();
            let reaped = child.wait();
            killed?;
            reaped?;
            return Err(error);
        }
        bounded_child_output::wait_before(
            child,
            deadline,
            Duration::from_millis(5),
            "upgrade fixture deadline",
        )
    })();
    let peer = peer.join().map_err(|_| "peer thread failed")?;
    let output = output?;
    assert!(
        !output
            .stdout
            .windows(26)
            .any(|value| value == b"deadline-credential-canary"),
        "credential exposed"
    );
    assert!(
        !output
            .stderr
            .windows(26)
            .any(|value| value == b"deadline-credential-canary"),
        "credential exposed"
    );
    let (body, delivery) = peer?;
    let request = positron_api::upgrade::UpgradeRequest::decode(&body)?;
    assert_eq!(request.action, "status");
    assert_eq!(
        request.operation_id.as_deref(),
        Some("abababababababababababababababab")
    );
    Ok((output, delivery))
}

#[test]
fn upgrade_status_accepts_a_valid_response_after_the_sdk_default_deadline() -> TestResult {
    let (output, delivery) = invoke_status(Duration::from_secs(6), None, true, false)?;
    if !output.status.success() {
        assert_eq!(output.stderr, b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n");
    }
    assert!(
        output.status.success(),
        "valid delayed upgrade status was refused"
    );
    assert_eq!(output.stdout, b"catalog_generation=7\n");
    assert!(output.stderr.is_empty());
    delivery?;
    Ok(())
}

#[test]
fn upgrade_transport_unknown_is_not_replayed() -> TestResult {
    let (output, delivery) = invoke_status(Duration::ZERO, None, false, false)?;
    delivery?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n");
    Ok(())
}

#[test]
fn upgrade_wait_bounds_its_first_request_by_the_original_allowance() -> TestResult {
    let (output, delivery) = invoke_status(Duration::from_secs(2), Some(1), true, false)?;
    if let Err(error) = delivery {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
        ));
    }
    assert!(
        !output.status.success(),
        "late valid response cannot complete an expired wait"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n");
    Ok(())
}

#[test]
fn upgrade_wait_keeps_the_original_deadline_after_a_running_receipt() -> TestResult {
    let (output, delivery) = invoke_status(Duration::from_millis(2500), Some(4), true, true)?;
    if let Err(error) = delivery {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
        ));
    }
    assert!(
        !output.status.success(),
        "a later poll cannot reset the original wait allowance"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n");
    Ok(())
}
