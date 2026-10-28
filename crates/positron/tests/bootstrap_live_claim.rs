//! Owner-only live claim stays on the exec stream, never the server's output.
#[path = "support/native_binary.rs"]
mod native_binary;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn exercise_live_claim(lost_response: bool) {
    let base = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    let root = std::path::Path::new(base)
        .join(format!("p120-claim-{}-{lost_response}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let config = root.join("positron.toml");
    let socket = root.join("control.sock");
    let mut listeners = Vec::new();
    for _ in 0..5 {
        listeners.push(TcpListener::bind("127.0.0.1:0").unwrap());
    }
    let endpoints: Vec<_> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect();
    let mut text = format!(
        "schema_version=1\n[storage]\ndata_directory='{}'\nsecrets_directory='{}'\n[security]\nlocal_key_file='{}'\n[listener]\ncontrol_path='{}'\n",
        root.join("data").display(),
        root.join("secrets").display(),
        root.join("secrets/local-root-key.v1").display(),
        socket.display()
    );
    for (role, endpoint) in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"]
        .into_iter()
        .zip(&endpoints)
    {
        text.push_str(&format!(
            "{role}_bind_address='{endpoint}'\n{role}_transport='plaintext'\n"
        ));
    }
    fs::write(&config, text).unwrap();
    let executable = native_binary::executable();
    let binary = executable.as_os_str();
    assert!(
        Command::new(binary)
            .args(["bootstrap", "prepare-storage", "--config"])
            .arg(&config)
            .output()
            .unwrap()
            .status
            .success()
    );
    drop(listeners);
    let stdout = fs::File::create(root.join("stdout")).unwrap();
    let stderr = fs::File::create(root.join("stderr")).unwrap();
    let mut server = Server(
        Command::new(binary)
            .args(["serve", "--init-if-empty", "--config"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let ready = Command::new(binary)
            .args([
                "doctor",
                "--ready",
                "--endpoint",
                &endpoints[0].to_string(),
                "--allow-plaintext",
            ])
            .output()
            .unwrap();
        if ready.status.success() {
            break;
        }
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "native startup failed"
        );
        assert!(
            Instant::now() < deadline,
            "native startup never became ready"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    for endpoint in [endpoints[0], endpoints[1]] {
        let mut stream = TcpStream::connect(endpoint).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"POST /control/bootstrap/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let response = rejection_response(&mut stream).unwrap();
        assert!(response.starts_with("HTTP/1.1 404"));
    }
    // The startup Control listener reaches the sole process reload owner.
    let reload = Command::new(binary)
        .args(["config", "reload", "--control-path"])
        .arg(&socket)
        .output()
        .unwrap();
    assert!(
        reload.status.success(),
        "{}",
        String::from_utf8_lossy(&reload.stderr)
    );
    assert_eq!(reload.stdout, b"status=reload_requested\n");
    for endpoint in [endpoints[0], endpoints[1]] {
        let mut stream = TcpStream::connect(endpoint).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(b"POST /control/configuration/reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let response = rejection_response(&mut stream).unwrap();
        assert!(response.starts_with("HTTP/1.1 404"));
    }
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"POST /control/configuration/reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").unwrap();
    let response = rejection_response(&mut stream).unwrap();
    assert!(response.starts_with("HTTP/1.1 400"));
    assert!(
        root.join("secrets/bootstrap-claim.v1").is_file(),
        "malformed request must not consume the claim"
    );
    // An unexpected request body cannot consume a claim.
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"POST /control/bootstrap/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").unwrap();
    let response = rejection_response(&mut stream).unwrap();
    assert!(response.starts_with("HTTP/1.1 400"));
    assert!(
        root.join("secrets/bootstrap-claim.v1").is_file(),
        "malformed request must not consume the claim"
    );
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    let claim = || {
        Command::new(binary)
            .args(["bootstrap", "claim", "--control-path"])
            .arg(&socket)
            .output()
            .unwrap()
    };
    let refused = claim();
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    if lost_response {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(b"POST /control/bootstrap/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while root.join("secrets/bootstrap-claim.v1").exists() {
            assert!(
                Instant::now() < deadline,
                "lost response did not consume the accepted claim"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(stream); // The accepted response is deliberately never read.
    } else {
        let delivered = claim();
        assert!(
            delivered.status.success(),
            "{}",
            String::from_utf8_lossy(&delivered.stderr)
        );
        assert!(delivered.stdout.starts_with(b"administrator_secret=pos_"));
    }
    assert!(!root.join("secrets/bootstrap-claim.v1").exists());
    let refused = claim();
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    for path in ["stdout", "stderr"] {
        assert!(
            !fs::read(root.join(path))
                .unwrap()
                .windows(21)
                .any(|bytes| bytes == b"administrator_secret=")
        );
    }
    let status = Command::new("kill")
        .args(["-TERM", &server.0.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(server.0.wait().unwrap().success());
    drop(server);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn live_claim_requires_the_owner_socket_and_is_destroyed_before_one_time_delivery() {
    exercise_live_claim(false);
}

#[test]
fn failed_live_response_never_recreates_or_redisplays_consumed_credentials() {
    exercise_live_claim(true);
}

fn rejection_response(stream: &mut impl Read) -> std::io::Result<String> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        if bytes.len() + count > 4096 {
            return Err(invalid());
        }
        bytes.extend_from_slice(chunk.get(..count).ok_or_else(invalid)?);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(bytes.get(..end).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            let mut lengths = head.lines().filter_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim())
            });
            let length = lengths
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(invalid)?;
            if length > 512
                || lengths.next().is_some()
                || head
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:"))
                || !matches!(
                    head.lines().next(),
                    Some("HTTP/1.1 400 Bad Request" | "HTTP/1.1 404 Not Found")
                )
                || (head.starts_with("HTTP/1.1 400 ") && length != 0)
            {
                return Err(invalid());
            }
            let expected = end.checked_add(4 + length).ok_or_else(invalid)?;
            if bytes.len() > expected {
                return Err(invalid());
            }
            if bytes.len() == expected {
                return String::from_utf8(bytes).map_err(|_| invalid());
            }
        }
    }
}

#[test]
fn rejected_response_requires_complete_bounded_framing() {
    let valid = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    assert!(rejection_response(&mut std::io::Cursor::new(valid)).is_ok());
    assert!(
        rejection_response(&mut std::io::Cursor::new(
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\n\r\n{}"
        ))
        .is_ok()
    );
    for invalid in [
        valid[..valid.len() - 1].to_vec(),
        [valid.as_slice(), b"x"].concat(),
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".to_vec(),
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec(),
        vec![b'x'; 4097],
    ] {
        assert!(rejection_response(&mut std::io::Cursor::new(invalid)).is_err());
    }
}
