use super::*;
use std::error::Error;

const RELEASE_WINDOW: Duration = Duration::from_secs(2);
const PROBE_BACKOFF: Duration = Duration::from_millis(5);

fn transport_closed(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            )
        }) {
            return true;
        }
        current = error.source();
    }
    false
}

async fn backoff(deadline: tokio::time::Instant) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout_at(deadline, tokio::time::sleep(PROBE_BACKOFF))
        .await
        .map_err(|_| "replacement admission deadline expired".into())
}

pub(super) async fn http_after_release(endpoint: SocketAddr) -> Result<String, Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + RELEASE_WINDOW;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("replacement admission deadline expired".into());
        }
        let mut response = Vec::new();
        let attempt = tokio::time::timeout_at(deadline, async {
            let mut stream = connect_from(Ipv4Addr::LOCALHOST, endpoint).await?;
            stream.write_all(b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n").await?;
            stream.shutdown().await?;
            stream.take(1025).read_to_end(&mut response).await?;
            Ok::<(), std::io::Error>(())
        }).await.map_err(|_| "replacement admission deadline expired")?;
        match attempt {
            Ok(()) if response.is_empty() => {},
            Err(error) if response.is_empty() && transport_closed(&error) => {},
            Err(_) => return Err("replacement HTTP transport failed".into()),
            Ok(()) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err("replacement admission deadline expired".into());
                }
                if response.len() > 1024 {
                    return Err("replacement HTTP response exceeded bound".into());
                }
                return String::from_utf8(response)
                    .map_err(|_| "replacement HTTP response invalid".into());
            },
        }
        backoff(deadline).await?;
    }
}

pub(super) async fn grpc_after_release(
    endpoint: SocketAddr,
) -> Result<tonic::Status, Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + RELEASE_WINDOW;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("replacement admission deadline expired".into());
        }
        let connected = tokio::time::timeout_at(
            deadline,
            LogsServiceClient::connect(format!("http://{endpoint}")),
        )
        .await
        .map_err(|_| "replacement admission deadline expired")?;
        match connected {
            Err(error) if transport_closed(&error) => {},
            Err(_) => return Err("replacement gRPC connection failed".into()),
            Ok(mut client) => {
                let result = tokio::time::timeout_at(
                    deadline,
                    client.export(Request::new(ExportLogsServiceRequest::default())),
                )
                .await
                .map_err(|_| "replacement admission deadline expired")?;
                match result {
                    Err(status) if status.code() == Code::Unauthenticated => {
                        if tokio::time::Instant::now() >= deadline {
                            return Err("replacement admission deadline expired".into());
                        }
                        return Ok(status);
                    },
                    Err(status) if transport_closed(&status) => {},
                    Err(_) => return Err("replacement gRPC returned a protocol refusal".into()),
                    Ok(_) => {
                        return Err(
                            "unauthenticated replacement gRPC unexpectedly succeeded".into()
                        );
                    },
                }
            },
        }
        backoff(deadline).await?;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn generated_grpc_replacement_distinguishes_transport_close_from_wire_unknown()
-> Result<(), Box<dyn Error>> {
    for (reset_first, status) in [(true, "16"), (false, "2")] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?;
        let peer = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            let mut accepted = 0;
            if reset_first {
                let (stream, _) = tokio::time::timeout_at(deadline, listener.accept()).await??;
                rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO))?;
                let mut first =
                    tokio::time::timeout_at(deadline, h2::server::handshake(stream)).await??;
                let request = tokio::time::timeout_at(deadline, first.accept())
                    .await?
                    .ok_or("first replacement RPC missing")??;
                drop(request);
                drop(first);
                accepted += 1;
            }
            let (stream, _) = match tokio::time::timeout_at(deadline, listener.accept()).await {
                Ok(accepted) => accepted?,
                Err(_) if reset_first => return Ok::<_, Box<dyn Error + Send + Sync>>(accepted),
                Err(_) => return Err("replacement peer accept deadline".into()),
            };
            accepted += 1;
            let mut connection =
                tokio::time::timeout_at(deadline, h2::server::handshake(stream)).await??;
            let (mut request, mut reply) = tokio::time::timeout_at(deadline, connection.accept())
                .await?
                .ok_or("replacement peer missing RPC")??;
            while let Some(bytes) =
                tokio::time::timeout_at(deadline, request.body_mut().data()).await?
            {
                let bytes = bytes?;
                request
                    .body_mut()
                    .flow_control()
                    .release_capacity(bytes.len())?;
            }
            reply.send_response(
                http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", status)
                    .body(())?,
                true,
            )?;
            let _ = tokio::time::timeout_at(deadline, connection.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>(accepted)
        });
        let result = grpc_after_release(endpoint).await;
        let accepted = peer.await?.map_err(|_| "replacement peer failed")?;
        if reset_first {
            assert_eq!(result?.code(), Code::Unauthenticated);
            assert_eq!(accepted, 2);
        } else {
            assert_eq!(
                result
                    .err()
                    .ok_or("wire Unknown unexpectedly satisfied release")?
                    .to_string(),
                "replacement gRPC returned a protocol refusal"
            );
            assert_eq!(accepted, 1);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http_replacement_requires_complete_protocol_response_and_expires_closed_peers()
-> Result<(), Box<dyn Error>> {
    for status in [405, 500] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = listener.local_addr()?;
        let peer = tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            let (stream, _) = tokio::time::timeout_at(deadline, listener.accept()).await??;
            rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO))?;
            drop(stream);
            let (mut stream, _) = tokio::time::timeout_at(deadline, listener.accept()).await??;
            let mut request = [0; 1024];
            tokio::time::timeout_at(deadline, stream.read(&mut request)).await??;
            stream
                .write_all(
                    format!("HTTP/1.1 {status} Result\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let result = http_after_release(endpoint).await;
        peer.await?.map_err(|_| "replacement HTTP peer failed")?;
        assert!(result?.starts_with(&format!("HTTP/1.1 {status} ")));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = listener.local_addr()?;
    let peer = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(Ok((stream, _))) = tokio::time::timeout_at(deadline, listener.accept()).await {
            drop(stream);
        }
    });
    let started = Instant::now();
    let result = http_after_release(endpoint).await;
    let elapsed = started.elapsed();
    peer.await?;
    assert_eq!(
        result
            .err()
            .ok_or("repeated closed peer unexpectedly succeeded")?
            .to_string(),
        "replacement admission deadline expired"
    );
    assert!(
        elapsed >= RELEASE_WINDOW && elapsed < Duration::from_millis(2750),
        "replacement admission deadline was not enforced before peer shutdown"
    );
    assert!(!transport_closed(&std::io::Error::from(
        std::io::ErrorKind::ConnectionRefused
    )));
    assert!(!transport_closed(&tonic::Status::unknown("wire refusal")));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn generated_grpc_repeated_preprotocol_closure_cannot_reset_release_deadline()
-> Result<(), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = listener.local_addr()?;
    let peer = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(Ok((stream, _))) = tokio::time::timeout_at(deadline, listener.accept()).await {
            rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO))?;
            let mut connection =
                match tokio::time::timeout_at(deadline, h2::server::handshake(stream)).await {
                    Ok(Ok(connection)) => connection,
                    _ => break,
                };
            if let Ok(Some(Ok(request))) =
                tokio::time::timeout_at(deadline, connection.accept()).await
            {
                drop(request);
            }
            drop(connection);
        }
        Ok::<_, std::io::Error>(())
    });
    let started = Instant::now();
    let result = grpc_after_release(endpoint).await;
    let elapsed = started.elapsed();
    peer.await??;
    assert_eq!(
        result
            .err()
            .ok_or("repeated closed peer unexpectedly succeeded")?
            .to_string(),
        "replacement admission deadline expired"
    );
    assert!(
        elapsed >= RELEASE_WINDOW && elapsed < Duration::from_millis(2750),
        "replacement admission deadline was not enforced before peer shutdown"
    );
    Ok(())
}
