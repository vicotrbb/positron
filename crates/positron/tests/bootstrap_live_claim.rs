//! Owner-only live claim stays on the exec stream, never the server's output.
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
    let binary = env!("CARGO_BIN_EXE_positron");
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
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 404"));
    }
    // An unexpected request body cannot consume a claim.
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"POST /control/bootstrap/claim HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400"));
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
