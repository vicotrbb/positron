//! Backup CLI sends bounded authenticated requests to the serving owner.
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn backup_cancel_binds_exact_operation_revision_and_reports_new_revision() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<String, std::io::Error> {
        let (mut stream, _) = listener.accept()?;
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
        let body = r#"{"operation_revision":43,"kind":"snapshot","cleanup_pending":true,"operation":{"id":"11111111111111111111111111111111","status":"running","phase":"backup_cancellation","progress_percent":20,"retry":"inspect_by_operation_id","cancellation":"cancel_requested_cleanup_pending","irreversible_boundary":"not_crossed"}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        Ok(String::from_utf8_lossy(&request).into_owned())
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "backup",
            "cancel",
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
            "--credential-stdin",
            "--expected-operation-revision",
            "42",
            "--idempotency-key",
            "22222222-2222-4222-8222-222222222222",
            "--operation-id",
            "11111111111111111111111111111111",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("stdin")?;
    writeln!(stdin, "operator-test-credential")?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("phase=backup_cancellation"));
    assert!(text.contains("irreversible_boundary=not_crossed"));
    assert!(!text.contains("operator-test-credential"));
    let request = server.join().map_err(|_| "server thread failed")??;
    assert!(request.starts_with("POST /v1/backups:manage HTTP/1.1"));
    assert!(request.contains("\"action\":\"cancel\""));
    assert!(request.contains("\"expected_operation_revision\":42"));
    assert!(!request.contains("expected_catalog_generation"));
    assert!(text.contains("operation_revision=43"));
    assert!(request.contains("11111111111111111111111111111111"));
    Ok(())
}
#[test]
fn backup_cli_rejects_global_missing_and_zero_cancel_preconditions() -> TestResult {
    for extra in [
        vec!["--expected-generation", "1"],
        vec![],
        vec!["--expected-operation-revision", "0"],
        vec![
            "--expected-operation-revision",
            "1",
            "--expected-generation",
            "1",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args([
                "backup",
                "cancel",
                "--endpoint",
                "127.0.0.1:1",
                "--allow-plaintext",
                "--credential-stdin",
                "--operation-id",
                "11111111111111111111111111111111",
                "--idempotency-key",
                "22222222-2222-4222-8222-222222222222",
            ])
            .args(extra)
            .output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid backup request"));
    }
    Ok(())
}
