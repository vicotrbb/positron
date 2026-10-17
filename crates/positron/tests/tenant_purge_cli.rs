//! Public command exercises the generated HTTP client and protected credential input.
#![cfg(unix)]
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
};
#[test]
fn purge_command_transmits_explicit_confirmation_and_prints_managed_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<Vec<u8>, String> {
        let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("request ended before body".into());
            }
            bytes.extend_from_slice(buffer.get(..count).ok_or("request range")?);
            if bytes.len() > 8192 {
                return Err("request exceeded bound".into());
            }
            if let Some(end) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                let headers = std::str::from_utf8(bytes.get(..end).ok_or("headers")?)
                    .map_err(|e| e.to_string())?;
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .ok_or("request length")?;
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        let body = br#"{"catalog_generation":7,"managed_scope":"managed_repositories_only;unmanaged_copies_not_revoked"}"#;
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(|e| e.to_string())?;
        stream.write_all(body).map_err(|e| e.to_string())?;
        Ok(bytes)
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "tenant",
            "purge",
            "start",
            "--endpoint",
            &endpoint.to_string(),
            "--credential-stdin",
            "--allow-plaintext",
            "--tenant-id",
            "41414141-4141-4141-4141-414141414141",
            "--confirmation-slug",
            "example",
            "--expected-generation",
            "7",
            "--expected-lifecycle-generation",
            "2",
            "--idempotency-key",
            "42424242-4242-4242-4242-424242424242",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("credential stdin")?
        .write_all(b"protected-test-bearer\n")?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("unmanaged_copies_not_revoked"));
    assert!(!stdout.contains("protected-test-bearer"));
    let request = server.join().map_err(|_| "HTTP fixture panicked")??;
    let request = String::from_utf8(request)?;
    assert!(request.starts_with("POST /v1/tenant-purges:manage HTTP/1.1"));
    let body = request.split_once("\r\n\r\n").ok_or("request body")?.1;
    let request = positron_api::tenant_purge::TenantPurgeRequest::decode(body.as_bytes())?;
    assert_eq!(request.confirmation_slug.as_deref(), Some("example"));
    assert_eq!(request.expected_lifecycle_generation, Some(2));
    Ok(())
}
