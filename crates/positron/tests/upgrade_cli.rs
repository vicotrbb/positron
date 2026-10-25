//! Real CLI binary and generated HTTP client preserve the Upgrade contract.
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    time::Duration,
};
#[test]
fn cli_sends_configured_candidate_and_reports_bound_release_status()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<String, std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut bytes = Vec::new();
        let mut byte = [0];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte)?;
            bytes.push(byte[0]);
        }
        let header = String::from_utf8_lossy(&bytes);
        let length = header
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, n)| n.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body)?;
        bytes.extend(body);
        let response=serde_json::json!({"catalog_generation":7,"operation":{"id":"ab".repeat(16),"status":"pending","phase":"preflight","progress_percent":0,"retry":"inspect_by_operation_id","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"},"details":{"source_version":"0.0.0","target_version":"0.0.1","source_manifest":"11".repeat(32),"target_manifest":"22".repeat(32),"source_artifact":"33".repeat(32),"target_artifact":"44".repeat(32),"configuration":"55".repeat(32),"format_epoch":2,"repository_id":"66666666-6666-6666-6666-666666666666","rollback_available":false}}).to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.len(),
            response
        )?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "upgrade",
            "start",
            "--endpoint",
            &address.to_string(),
            "--allow-plaintext",
            "--credential-stdin",
            "--candidate-manifest",
            &"22".repeat(32),
            "--repository-id",
            "66666666-6666-6666-6666-666666666666",
            "--retention-seconds",
            "3600",
            "--expected-generation",
            "6",
            "--idempotency-key",
            "77777777-7777-7777-7777-777777777777",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin")?
        .write_all(b"pos_fixture_secret\n")?;
    let output = child.wait_with_output()?;
    let request = server.join().map_err(|_| "server")??;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(request.starts_with("POST /v1/upgrades:manage HTTP/1.1\r\n"));
    assert!(request.contains("\"candidate_manifest\":\""));
    assert!(request.contains("\"expected_catalog_generation\":6"));
    assert!(!request.contains("project_trust_root"));
    assert!(!request.contains("artifact_path"));
    assert!(stdout.contains("phase=preflight"));
    assert!(stdout.contains("target_version=0.0.1"));
    assert!(stdout.contains("rollback_available=false"));
    assert!(!stdout.contains("pos_fixture_secret"));
    Ok(())
}

#[path = "upgrade_cli/transport_deadline.rs"]
mod transport_deadline;
