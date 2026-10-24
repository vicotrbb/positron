use std::time::{Duration, Instant};

use positron_api::repository::{RepositoryRequest, RepositoryResponse, RepositoryServiceClient};

type Inspection = Result<RepositoryResponse, String>;

pub(super) fn inspect(
    client: &RepositoryServiceClient,
    credential: &str,
    request: &RepositoryRequest,
    deadline: Instant,
) -> Inspection {
    use positron_api::repository::RepositoryServiceClientFailure;
    if request.action != "status" {
        return Err("repository status inspection requires a read-only status request".into());
    }
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("repository status inspection deadline".into());
        }
        let result = client.manage_with_timeout(credential, request, remaining);
        if Instant::now() >= deadline {
            return Err("repository status inspection deadline".into());
        }
        match result {
            Ok(response) => {
                if request.operation_id.as_deref().is_some_and(|expected| {
                    response
                        .operation
                        .as_ref()
                        .map(|operation| operation.id.as_str())
                        != Some(expected)
                }) {
                    return Err("repository status operation identity changed".into());
                }
                return Ok(response);
            },
            Err(RepositoryServiceClientFailure::CapacityUnavailable) => {
                std::thread::sleep(
                    Duration::from_millis(25)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            },
            Err(failure) => return Err(format!("{failure:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use positron_api::repository::RepositoryTransport;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::mpsc;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn scripted(
        responses: &[(u16, &str)],
        request: &RepositoryRequest,
        budget: Duration,
    ) -> TestResult<(Inspection, Vec<Vec<u8>>, Duration)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint: SocketAddr = listener.local_addr()?;
        let client =
            RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint })
                .map_err(|failure| format!("client: {failure:?}"))?;
        let responses = responses
            .iter()
            .map(|(status, body)| (*status, body.to_string()))
            .collect::<Vec<_>>();
        let (done, finished) = mpsc::channel::<()>();
        let server = std::thread::spawn(move || -> Result<Vec<Vec<u8>>, String> {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if matches!(finished.try_recv(), Err(mpsc::TryRecvError::Disconnected))
                            {
                                return Ok(requests);
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        },
                        Err(error) => return Err(error.to_string()),
                    }
                };
                stream
                    .set_nonblocking(false)
                    .map_err(|error| error.to_string())?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|error| error.to_string())?;
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream
                        .read_exact(&mut byte)
                        .map_err(|error| error.to_string())?;
                    headers.extend_from_slice(&byte);
                    if headers.len() > 8192 {
                        return Err("headers exceeded bound".into());
                    }
                }
                let text = std::str::from_utf8(&headers).map_err(|error| error.to_string())?;
                let length = text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .ok_or("content length")?;
                if length > 4096 {
                    return Err("body exceeded bound".into());
                }
                let mut bytes = vec![0; length];
                stream
                    .read_exact(&mut bytes)
                    .map_err(|error| error.to_string())?;
                headers.extend_from_slice(&bytes);
                requests.push(headers);
                if status != 0 {
                    write!(stream, "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).map_err(|error| error.to_string())?;
                }
            }
            Ok(requests)
        });
        let started = Instant::now();
        let result = inspect(
            &client,
            "status-credential-canary",
            request,
            Instant::now() + budget,
        );
        let elapsed = started.elapsed();
        drop(done);
        let requests = server.join().map_err(|_| "server panicked")??;
        Ok((result, requests, elapsed))
    }

    #[test]
    fn explicit_capacity_refusal_does_not_prevent_the_same_status_inspection() -> TestResult {
        let request = RepositoryRequest::decode(br#"{"action":"status"}"#)?;
        let (result, requests, _) = scripted(
            &[
                (503, r#"{"code":"capacity_unavailable"}"#),
                (200, r#"{"catalog_generation":7}"#),
            ],
            &request,
            Duration::from_secs(10),
        )?;
        assert_eq!(result?.catalog_generation, 7);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests.first(), requests.get(1));
        Ok(())
    }

    #[test]
    fn other_refusals_and_unknown_delivery_are_not_retried() -> TestResult {
        let request = RepositoryRequest::decode(br#"{"action":"status"}"#)?;
        for (status, body, expected) in [
            (
                401,
                r#"{"code":"authentication_rejected"}"#,
                "AuthenticationRejected",
            ),
            (
                503,
                r#"{"code":"administration_unavailable"}"#,
                "AdministrationUnavailable",
            ),
            (503, r#"{"code":"unknown"}"#, "Transport"),
            (409, r#"{"code":"stale_generation"}"#, "StaleGeneration"),
            (0, "", "Transport"),
            (200, "{}", "Transport"),
        ] {
            let (result, requests, _) = scripted(
                &[(status, body), (200, r#"{"catalog_generation":7}"#)],
                &request,
                Duration::from_secs(10),
            )?;
            assert_eq!(result, Err(expected.into()));
            assert_eq!(requests.len(), 1);
        }
        Ok(())
    }

    #[test]
    fn mutations_are_never_sent_by_status_inspection() -> TestResult {
        let request = RepositoryRequest::decode(br#"{"action":"init","expected_catalog_generation":1,"idempotency_key":"61616161-6161-4161-8161-616161616161","repository_id":"62626262-6262-4262-8262-626262626262","locator":"/repository"}"#)?;
        let (result, requests, _) = scripted(
            &[(503, r#"{"code":"capacity_unavailable"}"#)],
            &request,
            Duration::from_secs(10),
        )?;
        assert_eq!(
            result,
            Err("repository status inspection requires a read-only status request".into())
        );
        assert!(requests.is_empty());
        Ok(())
    }

    #[test]
    fn capacity_refusals_do_not_reset_the_supplied_deadline() -> TestResult {
        let request = RepositoryRequest::decode(br#"{"action":"status"}"#)?;
        let responses = vec![(503, r#"{"code":"capacity_unavailable"}"#); 64];
        let (result, requests, elapsed) =
            scripted(&responses, &request, Duration::from_millis(100))?;
        assert_eq!(result, Err("repository status inspection deadline".into()));
        assert!(elapsed < Duration::from_secs(2));
        assert!(requests.iter().all(|value| Some(value) == requests.first()));
        let (result, requests, _) = scripted(&responses, &request, Duration::ZERO)?;
        assert_eq!(result, Err("repository status inspection deadline".into()));
        assert!(requests.is_empty());
        Ok(())
    }

    #[test]
    fn operation_status_cannot_switch_identity_or_replay_a_terminal_failure() -> TestResult {
        let request = RepositoryRequest::decode(
            br#"{"action":"status","operation_id":"11111111111111111111111111111111"}"#,
        )?;
        let body = r#"{"catalog_generation":7,"operation":{"id":"22222222222222222222222222222222","status":"failed","phase":"preflight","progress_percent":0,"retry":"never","cancellation":"not_allowed_after_drain","irreversible_boundary":"not_crossed"}}"#;
        let (result, requests, _) = scripted(&[(200, body)], &request, Duration::from_secs(10))?;
        assert_eq!(
            result,
            Err("repository status operation identity changed".into())
        );
        assert_eq!(requests.len(), 1);
        let matching = body.replace(
            "22222222222222222222222222222222",
            "11111111111111111111111111111111",
        );
        let (result, requests, _) =
            scripted(&[(200, &matching)], &request, Duration::from_secs(10))?;
        assert_eq!(
            result?.operation.ok_or("operation missing")?.status,
            "failed"
        );
        assert_eq!(requests.len(), 1);
        Ok(())
    }
}
