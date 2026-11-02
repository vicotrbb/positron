//! The shell-free native CLI requests the existing process-owned reload.
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::{Command, Stdio},
};

#[test]
fn configuration_reload_refusals_have_closed_diagnostics_and_never_retry() {
    for (response, hold_open, reason) in [
        (
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 22\r\n\r\nresponse-secret-canary"
                .as_slice(),
            false,
            "authentication_rejected",
        ),
        (
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            false,
            "owner_unavailable",
        ),
        (b"", false, "peer_closed"),
        (
            b"HTTP/1.1 202 Accepted\r\nContent-Length: 24\r\n\r\nstatus=reload_",
            false,
            "incomplete_response",
        ),
        (b"", true, "timeout"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            false,
            "unexpected_status",
        ),
        (
            b"malformed-response-secret-canary\r\n\r\n",
            false,
            "invalid_response",
        ),
    ] {
        let root = std::path::Path::new("/tmp").join(format!(
            "p120-reload-failure-{}-{reason}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (done, received) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 512);
            }
            assert_eq!(request, b"POST /control/configuration/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer reload-test-administrator\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(response).unwrap();
            if !hold_open {
                drop(stream);
            }
            received
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            listener.set_nonblocking(true).unwrap();
            assert!(
                listener
                    .accept()
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
                "reload must send exactly one request"
            );
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["config", "reload", "--control-path"])
            .arg(&path)
            .arg("--credential-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"reload-test-administrator\n")
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        done.send(()).unwrap();
        server.join().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, format!("positron: configuration reload request unavailable; application not confirmed; reason={reason}\n").as_bytes());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn configuration_reload_endpoint_failure_has_no_path_or_credential_details() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "config",
            "reload",
            "--control-path",
            "/unavailable-reload-path-canary/control.sock",
            "--credential-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"reload-test-administrator\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"positron: configuration reload request unavailable; application not confirmed; reason=endpoint_unavailable\n");
}

#[test]
fn configuration_reload_uses_owner_control_and_reports_request_not_application() {
    exercise(false, false);
}

#[test]
fn configuration_reload_accepts_a_complete_fragmented_response_after_the_peer_closes() {
    exercise(true, false);
}

#[test]
fn configuration_reload_returns_after_the_valid_frame_without_waiting_for_peer_eof() {
    exercise(false, true);
}

fn exercise(fragmented: bool, hold_open: bool) {
    let base = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    let root = std::path::Path::new(base).join(format!(
        "p120-reload-{}-{fragmented}-{hold_open}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("control.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let (done, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 512);
        }
        assert_eq!(request,b"POST /control/configuration/reload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer reload-test-administrator\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let padding = if fragmented {
            format!("X-Padding: {}\r\n", "x".repeat(512))
        } else {
            String::new()
        };
        let response = format!(
            "HTTP/1.1 202 Accepted\r\n{padding}Content-Length: 24\r\nConnection: close\r\n\r\nstatus=reload_requested\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
        if hold_open {
            received
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        }
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["config", "reload", "--control-path"])
        .arg(&path)
        .arg("--credential-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"reload-test-administrator\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    if hold_open {
        done.send(()).unwrap();
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"status=reload_requested\n");
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn configuration_reload_refuses_invalid_stdin_without_echoing_it() {
    for input in [
        Vec::new(),
        b"reload-canary\nInjected: value".to_vec(),
        vec![b'x'; 1025],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args([
                "config",
                "reload",
                "--control-path",
                "/nonexistent/positron-control.sock",
                "--credential-stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"positron: invalid credential input\n");
    }
}
