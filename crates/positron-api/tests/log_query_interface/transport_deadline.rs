use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use positron_api::log_query::{LogQueryServiceClient, LogQueryTransport};

#[test]
fn generated_query_client_accepts_complete_response_after_five_seconds()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, response) = query_exchange()?;
    let expected_request = request.encode()?;
    let response_bytes = response.encode()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stream = receive_request(&listener, "/v1/logs:query", &expected_request)?;
        std::thread::sleep(Duration::from_secs(6));
        let write = (|| {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_bytes.len()
            )?;
            stream.write_all(&response_bytes)
        })();
        if let Err(error) = write
            && !matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )
        {
            return Err(error);
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        Ok(())
    });
    let client = LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut { endpoint })?;
    let result = client.execute("test-only-query-key", &request);
    server.join().map_err(|_| "query fixture panicked")??;
    assert_eq!(result?, response);
    Ok(())
}

fn query_exchange() -> Result<
    (
        super::LogQueryRequest,
        positron_api::log_query::LogQueryResponse,
    ),
    Box<dyn std::error::Error>,
> {
    let mut response = super::empty_complete_response();
    let request = super::LogQueryRequest {
        pipeline: "logs | range query_time 0 1 | limit 1".into(),
        budget: Some(super::LogQueryBudget {
            wall_seconds: 5,
            scanned_bytes: 1,
            decoded_records: 1,
            output_rows: 1,
            output_bytes: 1,
            memory_bytes: 1,
            cpu_work_units: 1,
            maximum_time_range_nanoseconds: 1,
        }),
    };
    for event in &mut response.events {
        match &mut event.event {
            Some(positron_api::log_query::log_query_event::Event::Header(header)) => {
                header.effective_budget = request.budget;
            },
            Some(positron_api::log_query::log_query_event::Event::Terminal(terminal)) => {
                terminal
                    .stats
                    .as_mut()
                    .ok_or("canonical terminal statistics missing")?
                    .cumulative_budget = request.budget;
            },
            _ => {},
        }
    }
    Ok((request, response))
}

fn receive_request(
    listener: &TcpListener,
    path: &str,
    expected_request: &[u8],
) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::other("query fixture accept deadline"));
                }
                std::thread::sleep(Duration::from_millis(1));
            },
            Err(error) => return Err(error),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    assert!(
        !line.contains("test-only-query-key"),
        "credential leaked into request target"
    );
    assert_eq!(line, format!("POST {path} HTTP/1.1\r\n"));
    let mut length = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::Error::other("query fixture incomplete request"));
        }
        assert!(line.len() <= 8192);
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("content-length: ") {
            length = value
                .trim()
                .parse::<usize>()
                .map_err(std::io::Error::other)?;
        }
    }
    assert!(length <= 8192);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    assert!(
        !body
            .windows(b"test-only-query-key".len())
            .any(|part| part == b"test-only-query-key"),
        "credential leaked into request body"
    );
    assert_eq!(body, expected_request);
    Ok(stream)
}

#[test]
fn query_transport_total_deadline_bounds_held_headers_and_trickled_body()
-> Result<(), Box<dyn std::error::Error>> {
    for trickle in [false, true] {
        let (request, response) = query_exchange()?;
        let expected_request = request.encode()?;
        let response_bytes = response.encode()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let (release, released) = mpsc::channel();
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let mut stream = receive_request(&listener, "/v1/logs:query", &expected_request)?;
            if trickle {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response_bytes.len()
                )?;
            }
            let deadline = Instant::now() + Duration::from_secs(35);
            loop {
                match released.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) => return Ok(()),
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(std::io::Error::other("query fixture release lost"));
                    },
                    Err(mpsc::RecvTimeoutError::Timeout) => {},
                }
                if Instant::now() >= deadline {
                    return Err(std::io::Error::other("query fixture release deadline"));
                }
                if trickle && let Err(error) = stream.write_all(b" ") {
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) {
                        released
                            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                            .map_err(std::io::Error::other)?;
                        return Ok(());
                    }
                    return Err(error);
                }
            }
        });
        let client = LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut { endpoint })?;
        let started = Instant::now();
        let result = client.execute("test-only-query-key", &request);
        let elapsed = started.elapsed();
        let released = release.send(());
        let joined = server.join();
        released?;
        joined.map_err(|_| "query fixture panicked")??;
        assert_eq!(
            result.unwrap_err(),
            positron_api::log_query::LogQueryServiceClientFailure::Transport
        );
        assert!(
            elapsed >= Duration::from_secs(29) && elapsed < Duration::from_secs(35),
            "total query deadline was not enforced"
        );
    }
    Ok(())
}

#[test]
fn ordinary_generated_client_keeps_its_five_second_total_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::tenant_service::{
        TenantListRequest, TenantServiceClient, TenantServiceClientFailure,
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let mut stream =
            receive_request(&listener, "/v1/tenants:list", br#"{"continuation":null}"#)?;
        std::thread::sleep(Duration::from_secs(6));
        if let Err(error) = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"tenants\":[]}",
        ) && !matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ) {
            return Err(error);
        }
        Ok(())
    });
    let client = TenantServiceClient::new(LogQueryTransport::PlaintextOptOut { endpoint })?;
    let started = Instant::now();
    let result = client.list("test-only-query-key", &TenantListRequest::new());
    let elapsed = started.elapsed();
    server.join().map_err(|_| "ordinary fixture panicked")??;
    assert_eq!(result.unwrap_err(), TenantServiceClientFailure::Transport);
    assert!(elapsed >= Duration::from_secs(4));
    Ok(())
}

#[test]
fn query_deadline_preserves_typed_rejections_and_inclusive_response_byte_bound()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::log_query::{
        LogQueryServiceClientFailure as Failure, MAX_RESPONSE_BYTES, query_rejection,
    };
    let (request, response) = query_exchange()?;
    let mut inclusive = response.encode()?;
    inclusive.resize(MAX_RESPONSE_BYTES, b' ');
    let mut excessive = inclusive.clone();
    excessive.push(b' ');
    for (status, body, expected) in [
        (
            401,
            query_rejection(401, "authentication_rejected")?,
            Some(Failure::AuthenticationRejected),
        ),
        (
            429,
            query_rejection(429, "capacity_unavailable")?,
            Some(Failure::CapacityUnavailable),
        ),
        (
            503,
            query_rejection(503, "query_unavailable")?,
            Some(Failure::QueryUnavailable),
        ),
        (200, inclusive, None),
        (200, excessive, Some(Failure::Transport)),
    ] {
        let expected_request = request.encode()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let mut stream = receive_request(&listener, "/v1/logs:query", &expected_request)?;
            write!(
                stream,
                "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(&body)?;
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
            Ok(())
        });
        let client = LogQueryServiceClient::new(LogQueryTransport::PlaintextOptOut { endpoint })?;
        let result = client.execute("test-only-query-key", &request);
        server.join().map_err(|_| "query fixture panicked")??;
        match expected {
            Some(failure) => assert_eq!(result.unwrap_err(), failure),
            None => assert_eq!(result?, response),
        }
    }
    Ok(())
}
