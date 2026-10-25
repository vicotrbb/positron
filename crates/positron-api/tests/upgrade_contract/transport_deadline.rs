use positron_api::upgrade::{
    UpgradeRequest, UpgradeResponse, UpgradeServiceClient, UpgradeServiceClientFailure,
    UpgradeTransport,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::mpsc,
    time::{Duration, Instant},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn status_request() -> Result<UpgradeRequest, Box<dyn std::error::Error>> {
    Ok(UpgradeRequest::decode(
        br#"{"action":"status","operation_id":"abababababababababababababababab"}"#,
    )?)
}
fn response() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(UpgradeResponse {
        catalog_generation: 7,
        operation: None,
        details: None,
    }
    .encode()?)
}

enum Reply {
    Complete {
        status: u16,
        body: Vec<u8>,
        delay: Duration,
    },
    Held {
        trickle: bool,
    },
}
fn peer(
    reply: Reply,
) -> std::io::Result<(
    SocketAddr,
    mpsc::Sender<()>,
    std::thread::JoinHandle<std::io::Result<()>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = listener.local_addr()?;
    let (release, released) = mpsc::channel();
    let task = std::thread::spawn(move || -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(40);
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
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            let count = stream.read(&mut buffer)?;
            if count == 0 || bytes.len() + count > 8192 {
                return Err(std::io::Error::other("peer request invalid"));
            }
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&bytes[..end])
                    .map_err(|_| std::io::Error::other("peer headers invalid"))?;
                assert!(headers.starts_with("POST /v1/upgrades:manage HTTP/1.1\r\n"));
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .ok_or_else(|| std::io::Error::other("peer length absent"))?;
                if bytes.len() >= end + 4 + length {
                    let request = UpgradeRequest::decode(&bytes[end + 4..])
                        .map_err(|_| std::io::Error::other("peer canonical request invalid"))?;
                    assert_eq!(request.action, "status");
                    break;
                }
            }
        }
        match reply {
            Reply::Complete {
                status,
                body,
                delay,
            } => {
                std::thread::sleep(delay);
                let delivery = write!(
                    stream,
                    "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .and_then(|()| stream.write_all(&body));
                if let Err(error) = delivery
                    && !matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    )
                {
                    return Err(error);
                }
            },
            Reply::Held { trickle } => {
                if trickle {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n"
                    )?;
                }
                loop {
                    match released.recv_timeout(Duration::from_millis(50)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {},
                    }
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("peer release deadline"));
                    }
                    if trickle && let Err(error) = stream.write_all(b" ") {
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ) {
                            break;
                        }
                        return Err(error);
                    }
                }
            },
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        Ok(())
    });
    Ok((endpoint, release, task))
}

#[test]
fn explicit_listener_allowance_preserves_delayed_success_and_typed_rejection() -> TestResult {
    for (status, body, rejected) in [
        (200, response()?, false),
        (409, br#"{"code":"stale_generation"}"#.to_vec(), true),
    ] {
        let (endpoint, release, task) = peer(Reply::Complete {
            status,
            body,
            delay: Duration::from_secs(6),
        })?;
        let client = UpgradeServiceClient::new(UpgradeTransport::PlaintextOptOut { endpoint })?;
        let result = client.manage_with_default_listener_timeout(
            "deadline-test-key",
            &status_request()?,
            Duration::from_secs(30),
        );
        drop(release);
        task.join().map_err(|_| "peer panic")??;
        if rejected {
            assert_eq!(result, Err(UpgradeServiceClientFailure::StaleGeneration));
        } else {
            assert_eq!(result?.catalog_generation, 7);
        }
    }
    Ok(())
}

#[test]
fn existing_sdk_manage_keeps_the_five_second_cap() -> TestResult {
    let (endpoint, release, task) = peer(Reply::Complete {
        status: 200,
        body: response()?,
        delay: Duration::from_secs(6),
    })?;
    let client = UpgradeServiceClient::new(UpgradeTransport::PlaintextOptOut { endpoint })?;
    let result = client.manage("deadline-test-key", &status_request()?);
    drop(release);
    task.join().map_err(|_| "peer panic")??;
    assert_eq!(result, Err(UpgradeServiceClientFailure::Transport));
    Ok(())
}

#[test]
fn explicit_allowance_bounds_headers_and_trickled_body_by_one_remaining_duration() -> TestResult {
    for trickle in [false, true] {
        let (endpoint, release, task) = peer(Reply::Held { trickle })?;
        let client = UpgradeServiceClient::new(UpgradeTransport::PlaintextOptOut { endpoint })?;
        let started = Instant::now();
        let result = client.manage_with_default_listener_timeout(
            "deadline-test-key",
            &status_request()?,
            Duration::from_millis(250),
        );
        let elapsed = started.elapsed();
        let released = release.send(());
        task.join().map_err(|_| "peer panic")??;
        released?;
        assert_eq!(result, Err(UpgradeServiceClientFailure::Transport));
        assert!(elapsed >= Duration::from_millis(250));
        assert!(elapsed < Duration::from_secs(2));
    }
    Ok(())
}

#[test]
fn explicit_allowance_caps_long_supplied_duration_at_default_listener_thirty_seconds() -> TestResult
{
    let (endpoint, release, task) = peer(Reply::Held { trickle: false })?;
    let client = UpgradeServiceClient::new(UpgradeTransport::PlaintextOptOut { endpoint })?;
    let started = Instant::now();
    let result = client.manage_with_default_listener_timeout(
        "deadline-test-key",
        &status_request()?,
        Duration::from_secs(60),
    );
    let elapsed = started.elapsed();
    let released = release.send(());
    task.join().map_err(|_| "peer panic")??;
    released?;
    assert_eq!(result, Err(UpgradeServiceClientFailure::Transport));
    assert!(elapsed >= Duration::from_secs(30));
    assert!(elapsed < Duration::from_secs(35));
    Ok(())
}

#[test]
fn exhausted_allowance_refuses_before_sending_a_request() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = UpgradeServiceClient::new(UpgradeTransport::PlaintextOptOut {
        endpoint: listener.local_addr()?,
    })?;
    assert_eq!(
        client.manage_with_default_listener_timeout(
            "deadline-test-key",
            &status_request()?,
            Duration::ZERO,
        ),
        Err(UpgradeServiceClientFailure::Transport),
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}
