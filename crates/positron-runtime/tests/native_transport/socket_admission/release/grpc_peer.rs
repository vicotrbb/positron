use super::*;

pub(super) async fn reply_after_body(
    connection: &mut h2::server::Connection<tokio::net::TcpStream, bytes::Bytes>,
    mut request: http::Request<h2::RecvStream>,
    mut reply: h2::server::SendResponse<bytes::Bytes>,
    status: &str,
    deadline: tokio::time::Instant,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let body = async {
        while let Some(bytes) = request.body_mut().data().await {
            let bytes = bytes?;
            request
                .body_mut()
                .flow_control()
                .release_capacity(bytes.len())?;
        }
        Ok::<_, h2::Error>(())
    };
    // RecvStream only progresses while its connection is polled. HEADERS and
    // DATA may arrive separately even for the generated client's empty message.
    tokio::select! {
        result = tokio::time::timeout_at(deadline, body) => result??,
        closed = std::future::poll_fn(|context| connection.poll_closed(context)) => {
            closed?;
            return Err("replacement peer closed before request body completed".into());
        },
    }
    reply.send_response(
        http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .header("grpc-status", status)
            .body(())?,
        true,
    )?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_refusal_receives_body_that_arrives_after_headers() -> Result<(), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = listener.local_addr()?;
    let deadline = tokio::time::Instant::now() + RELEASE_WINDOW;
    let (accepted, headers) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout_at(deadline, listener.accept()).await??;
        let mut connection =
            tokio::time::timeout_at(deadline, h2::server::handshake(stream)).await??;
        let (request, reply) = tokio::time::timeout_at(deadline, connection.accept())
            .await?
            .ok_or("split-frame peer missing request")??;
        accepted.send(()).map_err(|_| "header observer closed")?;
        reply_after_body(&mut connection, request, reply, "16", deadline).await?;
        let _ = tokio::time::timeout_at(deadline, connection.accept()).await;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let stream = tokio::net::TcpStream::connect(endpoint).await?;
    let (mut client, connection) = h2::client::handshake(stream).await?;
    let driver = tokio::spawn(connection);
    let request = http::Request::builder()
        .method("POST")
        .uri(format!(
            "http://{endpoint}/opentelemetry.proto.collector.logs.v1.LogsService/Export"
        ))
        .header("content-type", "application/grpc")
        .body(())?;
    let (response, mut body) = client.send_request(request, false)?;
    tokio::time::timeout_at(deadline, headers).await??;
    body.send_data(bytes::Bytes::from_static(&[0, 0, 0, 0, 0]), true)?;
    let response = tokio::time::timeout_at(deadline, response).await??;
    assert_eq!(
        response.headers().get("grpc-status"),
        Some(&http::HeaderValue::from_static("16"))
    );
    drop(body);
    drop(client);
    peer.await?.map_err(|error| error.to_string())?;
    driver.await??;
    Ok(())
}
