use super::TestResult;
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[path = "../support/bounded_child_output.rs"]
mod bounded_child_output;

#[test]
fn repository_status_accepts_a_valid_response_after_the_sdk_default_deadline() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let peer = std::thread::spawn(move || -> std::io::Result<_> {
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
        if deadline.saturating_duration_since(Instant::now()) <= Duration::from_secs(6) {
            return Err(std::io::Error::other(
                "peer has insufficient response hold time",
            ));
        }
        std::thread::sleep(Duration::from_secs(6));
        let response = positron_api::repository::RepositoryResponse {
            catalog_generation: 7,
            operation: None,
            identity: None,
            doctor: None,
            policy: None,
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args([
                "repository",
                "status",
                "--endpoint",
                &endpoint.to_string(),
                "--credential-stdin",
                "--allow-plaintext",
            ])
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
            "repository fixture deadline",
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
    assert_eq!(
        positron_api::repository::RepositoryRequest::decode(&body)?.action,
        "status"
    );
    if !output.status.success() {
        assert_eq!(output.stderr, b"positron: transport outcome unknown; inspect the same operation or idempotency key before retrying\n");
    }
    assert!(
        output.status.success(),
        "valid delayed repository status was refused"
    );
    assert_eq!(output.stdout, b"catalog_generation=7\n");
    assert!(output.stderr.is_empty());
    delivery?;
    Ok(())
}
