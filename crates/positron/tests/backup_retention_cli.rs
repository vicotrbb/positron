//! Backup CLI sends bounded authenticated requests to the serving owner.
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn backup_expiry_uses_exact_snapshot_manifest_preconditions() -> TestResult {
    expiry_command(false, false)
}
#[test]
fn backup_expiry_prints_known_not_due_terminal_reason() -> TestResult {
    expiry_command(true, false)
}
#[test]
fn backup_verification_submits_exact_target_and_prints_immutable_report() -> TestResult {
    expiry_command(false, true)
}
fn expiry_command(terminal_failure: bool, verification: bool) -> TestResult {
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
        let report_body;
        let body = if verification {
            use sha2::{Digest, Sha256};
            let report = b"signed report fixture";
            let checksum = Sha256::digest(report)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let report = report
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            report_body = serde_json::json!({"operation_revision":4,"kind":"verification","cleanup_pending":false,"verification_report":report,"verification_report_checksum":checksum,
                "operation":{"id":"11111111111111111111111111111111","status":"succeeded","phase":"published","progress_percent":100,"retry":"never","cancellation":"not_allowed_during_publication","irreversible_boundary":"verification_report_published"},
                "repository":{"repository_id":"11111111-1111-4111-8111-111111111111","instance_id":"22222222-2222-4222-8222-222222222222","provider_kind":"local_filesystem","format_epoch":1,"integrity_fingerprint":"1".repeat(64),"prefix_commitment":"2".repeat(64)}}).to_string();
            report_body.as_str()
        } else if terminal_failure {
            r#"{"operation_revision":2,"kind":"retention","cleanup_pending":false,"terminal_error_code":"backup_retention_not_due","operation":{"id":"11111111111111111111111111111111","status":"failed","phase":"backup_retention_scan","progress_percent":20,"retry":"never","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"}}"#
        } else {
            r#"{"operation_revision":1,"kind":"retention","cleanup_pending":false,"operation":{"id":"11111111111111111111111111111111","status":"succeeded","phase":"published","progress_percent":100,"retry":"never","cancellation":"not_allowed_during_publication","irreversible_boundary":"backup_registry_expired"},"repository":{"repository_id":"11111111-1111-4111-8111-111111111111","instance_id":"22222222-2222-4222-8222-222222222222","provider_kind":"local_filesystem","format_epoch":1,"integrity_fingerprint":"1111111111111111111111111111111111111111111111111111111111111111","prefix_commitment":"2222222222222222222222222222222222222222222222222222222222222222"},"retention_receipt":{"snapshot_id":"22222222222222222222222222222222","manifest_checksum":"3333333333333333333333333333333333333333333333333333333333333333","registry_generation_checksum":"5555555555555555555555555555555555555555555555555555555555555555","deleted_objects":3,"already_absent_objects":2,"retained_shared_objects":1}}"#
        };
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
            if verification { "verify" } else { "expire" },
            "--endpoint",
            &endpoint.to_string(),
            "--allow-plaintext",
            "--credential-stdin",
            "--repository-id",
            "11111111-1111-4111-8111-111111111111",
            "--snapshot-id",
            "22222222222222222222222222222222",
            "--expected-manifest-checksum",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "--expected-generation",
            "1",
            "--idempotency-key",
            "44444444-4444-4444-8444-444444444444",
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
    if verification {
        assert!(text.contains("kind=verification cleanup_pending=false"));
        assert!(text.contains("verification_report_checksum="));
        assert!(text.contains("verification_report="));
        assert!(text.contains("irreversible_boundary=verification_report_published"));
    } else if terminal_failure {
        assert!(text.contains("terminal_error_code=backup_retention_not_due"));
        assert!(text.contains("status=failed"));
        assert!(text.contains("irreversible_boundary=not_crossed"));
    } else {
        assert!(
            text.contains("deleted_objects=3 already_absent_objects=2 retained_shared_objects=1")
        );
        assert!(text.contains("irreversible_boundary=backup_registry_expired"));
    }
    assert!(!text.contains("operator-test-credential"));
    let request = server.join().map_err(|_| "server thread failed")??;
    assert!(request.starts_with("POST /v1/backups:manage HTTP/1.1"));
    assert!(request.contains(if verification {
        "\"action\":\"verify\""
    } else {
        "\"action\":\"expire\""
    }));
    assert!(request.contains("22222222222222222222222222222222"));
    Ok(())
}
