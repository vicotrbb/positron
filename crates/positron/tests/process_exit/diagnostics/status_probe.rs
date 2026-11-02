//! Real HTTP outcomes for the existing bounded read-only status probe.
use super::*;
use std::net::TcpListener;
use std::sync::mpsc::{self, TryRecvError};
use std::time::Instant;

type ProbeResult = Result<String, Box<dyn std::error::Error>>;

#[test]
fn status_probe_rejects_nonretryable_http_responses() -> Result<(), Box<dyn std::error::Error>> {
    for status in [401, 403, 500] {
        let (result, requests) = probe(
            vec![status, 200],
            &[],
            Instant::now() + STARTUP_PROBE_BUDGET,
            Duration::ZERO,
        )?;
        assert!(
            result.is_err(),
            "an unexpected status cannot become a later success"
        );
        let message = result
            .err()
            .ok_or("unexpected status was accepted")?
            .to_string();
        assert!(
            !message.contains("probe-canary"),
            "safe refusal context redacts credentials"
        );
        assert_eq!(
            requests, 1,
            "authentication or unexpected failures are not retried"
        );
    }
    Ok(())
}

#[test]
fn status_probe_accepts_transient_service_unavailable_then_success()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, requests) = probe(
        vec![503, 200],
        &[],
        Instant::now() + STARTUP_PROBE_BUDGET,
        Duration::ZERO,
    )?;
    assert!(result?.starts_with("HTTP/1.1 200 "));
    assert_eq!(requests, 2);
    Ok(())
}

#[test]
fn status_probe_permanent_unavailable_exhausts_the_passed_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_millis(100);
    let (result, requests) = probe(vec![503], &[], deadline, Duration::ZERO)?;
    let message = result
        .err()
        .ok_or("permanent unavailable response was accepted")?
        .to_string();
    assert!(message.contains("deadline"));
    assert!(!message.contains("probe-canary"));
    assert!(
        requests < 100,
        "the passed deadline must stop the existing attempt loop"
    );
    if requests > 0 {
        assert!(
            message.contains("503"),
            "timeout retains bounded refusal context"
        );
    }
    Ok(())
}

#[test]
fn status_probe_expired_shared_deadline_launches_no_request()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, requests) = probe(vec![200], &[], Instant::now(), Duration::ZERO)?;
    assert!(
        result
            .err()
            .ok_or("expired window was accepted")?
            .to_string()
            .contains("deadline")
    );
    assert_eq!(
        requests, 0,
        "status cannot reset a window already consumed by readiness"
    );
    Ok(())
}

#[test]
fn status_probe_keeps_existing_successful_publication_polling()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, requests) = probe(
        vec![200, 200],
        &["\"generation\":2"],
        Instant::now() + STARTUP_PROBE_BUDGET,
        Duration::ZERO,
    )?;
    assert!(result?.contains("\"generation\":2"));
    assert_eq!(requests, 2);
    Ok(())
}

#[test]
fn status_probe_waits_for_the_same_inflight_response_across_io_ticks()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, requests) = probe(
        vec![200],
        &[],
        Instant::now() + STARTUP_PROBE_BUDGET,
        Duration::from_millis(150),
    )?;
    assert!(
        result.is_ok(),
        "a polling tick cannot abort an admitted GET before its shared deadline"
    );
    assert_eq!(
        requests, 1,
        "waiting for an inflight response cannot replay the GET"
    );
    Ok(())
}

fn probe(
    statuses: Vec<u16>,
    expected: &[&str],
    deadline: Instant,
    first_response_delay: Duration,
) -> Result<(ProbeResult, usize), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let (stop, stopping) = mpsc::channel::<()>();
    let worker = std::thread::spawn(move || -> std::io::Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut requests = 0;
        while Instant::now() < deadline {
            match stopping.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {},
            }
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                },
                Err(error) => return Err(error),
            };
            stream.set_read_timeout(Some(Duration::from_millis(100)))?;
            stream.set_write_timeout(Some(Duration::from_millis(100)))?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0; 1];
                if stream.read(&mut byte)? == 0 || request.len() >= 4096 {
                    return Err(std::io::Error::other(
                        "incomplete or overlong fixture request",
                    ));
                }
                request.extend_from_slice(&byte);
            }
            if !request.starts_with(b"GET /status HTTP/1.1\r\n") {
                return Err(std::io::Error::other(
                    "fixture received a non-status request",
                ));
            }
            let status = statuses
                .get(requests)
                .or_else(|| statuses.last())
                .copied()
                .ok_or_else(|| std::io::Error::other("empty response fixture"))?;
            requests += 1;
            if requests == 1 {
                std::thread::sleep(first_response_delay);
            }
            let body = format!(
                "{{\"generation\":{requests},\"echo\":\"Bearer probe-canary probe-canary\"}}"
            );
            write!(
                stream,
                "HTTP/1.1 {status} fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
        }
        Ok(requests)
    });
    let result = wait_for_configuration_status(port, "Bearer probe-canary", expected, deadline);
    drop(stop);
    let requests = worker
        .join()
        .map_err(|_| "status fixture thread panicked")??;
    Ok((result, requests))
}
