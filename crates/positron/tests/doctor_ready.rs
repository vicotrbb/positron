//! Container health consumes the authoritative Operations readiness endpoint.
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
};

#[test]
fn readiness_probe_has_no_credential_and_refuses_unready_or_redirected_health() {
    for (status, success) in [(200, true), (503, false), (302, false)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0; 4096];
            let count = stream.read(&mut bytes).unwrap();
            let request = std::str::from_utf8(&bytes[..count]).unwrap();
            assert!(request.starts_with("GET /health/ready HTTP/1.1\r\n"));
            assert!(!request.to_lowercase().contains("authorization:"));
            write!(
                stream,
                "HTTP/1.1 {status} test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args([
                "doctor",
                "--ready",
                "--endpoint",
                &endpoint.to_string(),
                "--allow-plaintext",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        server.join().unwrap();
    }
}

#[test]
fn readiness_probe_refuses_ambiguous_modes_credentials_and_missing_tls_trust() {
    for args in [
        vec!["--ready"],
        vec!["--ready", "--offline"],
        vec!["--ready", "--endpoint", "127.0.0.1:1", "--credential-stdin"],
        vec![
            "--ready",
            "--endpoint",
            "127.0.0.1:1",
            "--config",
            "untrusted.toml",
        ],
        vec!["--ready", "--endpoint", "127.0.0.1:0", "--allow-plaintext"],
        vec!["--ready", "--endpoint", "127.0.0.1:1"],
        vec![
            "--ready",
            "--endpoint",
            "127.0.0.1:1",
            "--server-name",
            "localhost",
            "--trust-file",
            "/nonexistent/ca.pem",
        ],
        vec![
            "--ready",
            "--endpoint",
            "127.0.0.1:1",
            "--allow-plaintext",
            "--server-name",
            "localhost",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_positron"))
            .arg("doctor")
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stdout).contains("status=ready"));
    }
}
