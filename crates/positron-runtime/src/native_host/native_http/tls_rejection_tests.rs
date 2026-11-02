use super::*;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::sync::{Arc, mpsc};

#[test]
fn native_tls_handshake_failure_is_closed_and_observable() -> Result<(), Box<dyn std::error::Error>>
{
    let roots = crate::process_lifecycle::TestRoots::new("tls-handshake")?;
    let paths = roots.bootstrap_paths()?;
    drop(crate::InstanceBootstrap::initialize(
        &paths,
        crate::InitializationPlan::non_interactive(),
    )?);
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/native_transport/fixtures");
    let tls = crate::TransportProfile::tls(
        fixtures.join("api-test-cert.pem"),
        fixtures.join("api-test-key.pem"),
    )?;
    let plain = crate::TransportProfile::plaintext_opt_out();
    let ephemeral = "127.0.0.1:0".parse()?;
    let host = crate::NativeHost::new(crate::NativeBindings::new_with_listener_transports(
        std::path::PathBuf::from("/tmp").join(format!(
            "p-http-handshake-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        )),
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
        plain.clone(),
        plain.clone(),
        plain.clone(),
        tls,
        plain,
    )?);
    let process = crate::ApplicationRuntime::start(
        crate::ServeConfiguration::new(paths, crate::InitializationMode::ExistingOnly),
        crate::HostInputs::new(&host, &host),
    )?;
    let outcome = (|| -> Result<(), Box<dyn std::error::Error>> {
        let address = process
            .bound_endpoints()
            .iter()
            .find(|endpoint| endpoint.role() == ListenerRole::OtlpHttp)
            .and_then(crate::BoundEndpoint::socket_address)
            .ok_or("TLS endpoint missing")?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(b"not-a-tls-handshake")?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let records: Vec<serde_json::Value> = serde_json::from_str(
                &process
                    .health()
                    .operational_logs_json()
                    .map_err(|_| "operational ring unavailable")?,
            )?;
            if records.iter().any(|record| {
                record["event"] == "native_http_connection_failed"
                    && record["stage"] == "tls_handshake"
                    && record["listener"] == "otlp_http"
            }) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("closed handshake failure diagnostic missing".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    let shutdown = process.shutdown(crate::ShutdownTrigger::FirstSignal);
    outcome?;
    assert_eq!(shutdown, crate::ExitOutcome::Graceful);
    Ok(())
}

#[test]
fn tls_invalid_bearer_receives_complete_rejection_with_a_separate_unread_body()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = crate::process_lifecycle::TestRoots::new("tls-rejection-body")?;
    let paths = roots.bootstrap_paths()?;
    drop(crate::InstanceBootstrap::initialize(
        &paths,
        crate::InitializationPlan::non_interactive(),
    )?);
    let instance = Arc::new(crate::InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let state = crate::health::ProcessState::starting();
    state.set_inspection_authority(instance)?;
    state.transition(crate::ProcessPhase::Serving);
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/native_transport/fixtures");
    let certificate = fixtures.join("api-test-cert.pem");
    let profile =
        crate::ApiTransportProfile::tls(certificate.clone(), fixtures.join("api-test-key.pem"))?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let (responded_tx, responded_rx) = mpsc::sync_channel(1);
    let (body_tx, body_rx) = mpsc::sync_channel(1);
    let (closed_tx, closed_rx) = mpsc::sync_channel(1);
    let server = std::thread::spawn(move || -> Result<(), String> {
        let (socket, peer) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("accept deadline".into());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                },
                Err(error) => return Err(error.to_string()),
            }
        };
        socket
            .set_nonblocking(false)
            .map_err(|error| error.to_string())?;
        let connection = profile
            .server_connection()
            .map_err(|error| format!("{error:?}"))?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        crate::native_host::complete_tls_handshake(
            &mut stream,
            deadline.saturating_duration_since(Instant::now()),
        )
        .map_err(|error| format!("{error:?}"))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        serve_tls_connection(
            &mut stream,
            ListenerRole::OtlpHttp,
            peer,
            None,
            &state.health(),
            RouteDependencies::new(Some(&services), None),
            ConnectionProtection::new(
                std::num::NonZeroU16::MIN,
                remaining,
                remaining,
                remaining,
                remaining,
                remaining,
            ),
        )
        .map_err(|_| "native response completion failed")?;
        responded_tx
            .send(())
            .map_err(|_| "response observer gone")?;
        body_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "separate body not sent")?;
        stream
            .sock
            .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
            .map_err(|error| error.to_string())?;
        let mut queued = [0; 1];
        if stream
            .sock
            .peek(&mut queued)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Err("separate TLS body did not reach the socket".into());
        }
        drop(stream);
        closed_tx.send(()).map_err(|_| "close observer gone")?;
        Ok(())
    });
    let outcome = (|| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut trust = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(certificate)? {
            trust.add(certificate?)?;
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(trust)
            .with_no_client_auth();
        let connection =
            rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost")?)?;
        let socket = TcpStream::connect_timeout(
            &address,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        socket.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        socket.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        stream.write_all(b"POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer invalid-credential\r\nContent-Type: application/json\r\nContent-Length: 16384\r\nConnection: close\r\n\r\n")?;
        stream.flush()?;
        responded_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
        stream
            .write_all(&[b' '; 16384])
            .map_err(|error| format!("separate body write: {error}"))?;
        stream
            .flush()
            .map_err(|error| format!("separate body flush: {error}"))?;
        body_tx.send(())?;
        closed_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
        let mut response = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            if let Some(end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let head = std::str::from_utf8(&response[..end])?;
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .ok_or("response length missing")?
                    .parse::<usize>()?;
                if response.len() >= end + 4 + length {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("rejection observation deadline elapsed".into());
            }
            let read = stream.read(&mut buffer).map_err(|error| {
                format!(
                    "rejection read after {received} bytes: {error}",
                    received = response.len()
                )
            })?;
            if read == 0 {
                return Err("peer closed before complete rejection".into());
            }
            if response.len() + read > 8192 {
                return Err("rejection exceeds response bound".into());
            }
            response.extend_from_slice(&buffer[..read]);
        }
        Ok(response)
    })();
    drop(body_tx);
    let server_outcome = server.join().map_err(|_| "TLS server panicked");
    let response = outcome.map_err(|error| {
        format!("TLS client failed: {error}; server outcome: {server_outcome:?}")
    })?;
    server_outcome??;
    assert!(response.starts_with(b"HTTP/1.1 401 "), "{response:?}");
    assert!(std::str::from_utf8(&response)?.contains("\"code\":16"));
    Ok(())
}
