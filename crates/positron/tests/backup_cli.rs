//! Backup CLI sends bounded authenticated requests to the serving owner.
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[path = "support/bounded_child_output.rs"]
mod bounded_child_output;

#[test]
fn backup_status_uses_canonical_route_and_prints_operation_truth() -> TestResult {
    backup_status_after(std::time::Duration::ZERO)
}

#[test]
fn backup_status_accepts_a_valid_response_after_the_sdk_default_deadline() -> TestResult {
    backup_status_after(std::time::Duration::from_secs(6))
}

fn backup_status_after(delay: std::time::Duration) -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let server = std::thread::spawn(move || -> Result<String, std::io::Error> {
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::other("backup peer deadline"));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                },
                Err(error) => return Err(error),
            }
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + length {
                    break;
                }
            }
        }
        let body = r#"{"operation_revision":1,"kind":"snapshot","cleanup_pending":false,"operation":{"id":"11111111111111111111111111111111","status":"running","phase":"backup_transfer","progress_percent":20,"retry":"inspect_by_operation_id","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"}}"#;
        if deadline.saturating_duration_since(std::time::Instant::now()) <= delay {
            return Err(std::io::Error::other(
                "insufficient backup response hold time",
            ));
        }
        std::thread::sleep(delay);
        stream.set_write_timeout(Some(
            deadline.saturating_duration_since(std::time::Instant::now()),
        ))?;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        Ok(String::from_utf8_lossy(&request).into_owned())
    });
    let output = (|| -> std::io::Result<_> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args([
                "backup",
                "status",
                "--endpoint",
                &endpoint.to_string(),
                "--allow-plaintext",
                "--credential-stdin",
                "--operation-id",
                "11111111111111111111111111111111",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let credential = (|| -> std::io::Result<()> {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::other("stdin"))?;
            writeln!(stdin, "operator-test-credential")
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
            std::time::Duration::from_millis(5),
            "backup CLI fixture deadline",
        )
    })();
    let request = server.join().map_err(|_| "server thread failed")?;
    let output = output?;
    assert!(
        !output
            .stdout
            .windows(24)
            .any(|bytes| bytes == b"operator-test-credential"),
        "credential exposed"
    );
    assert!(
        !output
            .stderr
            .windows(24)
            .any(|bytes| bytes == b"operator-test-credential"),
        "credential exposed"
    );
    if !output.status.success() {
        assert_eq!(output.stderr, b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n");
    }
    assert!(
        output.status.success(),
        "valid backup status response was refused"
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("phase=backup_transfer"));
    assert!(text.contains("irreversible_boundary=not_crossed"));
    assert!(!text.contains("operator-test-credential"));
    let request = request?;
    assert!(request.starts_with("POST /v1/backups:manage HTTP/1.1"));
    assert!(request.contains("\"action\":\"status\""));
    assert!(request.contains("11111111111111111111111111111111"));
    Ok(())
}
