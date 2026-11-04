use super::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const STATUS: &[u8] = br#"{"tasks":[],"returned":0,"total":0,"queued":0,"running":0,"deferred":0,"terminal":0,"integrity_findings":[]}"#;

fn delayed_response<T>(
    hold_close: bool,
    request: impl FnOnce(SocketAddr, PathBuf) -> TestResult<T>,
) -> TestResult<T> {
    let root = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures"
    ));
    let trust = root.join("api-test-cert.pem");
    let certificates = CertificateDer::pem_file_iter(&trust)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(root.join("api-test-key.pem"))?;
    let configuration = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (release, held) = std::sync::mpsc::sync_channel(1);
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let connection =
            ServerConnection::new(Arc::new(configuration)).map_err(std::io::Error::other)?;
        let mut stream = StreamOwned::new(connection, socket);
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            head.push(byte[0]);
            if head.len() > 4096 {
                return Err(std::io::Error::other("fixture header bound"));
            }
        }
        let head = std::str::from_utf8(&head).map_err(std::io::Error::other)?;
        let length = head
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .ok_or_else(|| std::io::Error::other("fixture length"))?;
        if length > 128 {
            return Err(std::io::Error::other("fixture body bound"));
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body)?;
        std::thread::sleep(Duration::from_secs(3));
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                STATUS.len()
            )
            .as_bytes(),
        )?;
        stream.write_all(STATUS)?;
        stream.flush()?;
        if hold_close {
            held.recv_timeout(Duration::from_secs(10))
                .map_err(std::io::Error::other)?;
        }
        stream.conn.send_close_notify();
        stream.flush()
    });
    let result = request(address, trust);
    let released = if hold_close {
        release.send(()).map_err(|_| "TLS fixture release failed")
    } else {
        Ok(())
    };
    let completed = server.join().map_err(|_| "TLS fixture peer panicked")?;
    match (result, completed) {
        (Err(failure), _) => Err(failure),
        (Ok(_), Err(failure)) => Err(failure.into()),
        (Ok(value), Ok(())) => {
            released?;
            Ok(value)
        },
    }
}

#[test]
fn generated_administration_client_accepts_a_response_within_its_five_second_cap() -> TestResult {
    delayed_response(false, |endpoint, trust_file| {
        use positron_api::maintenance::{
            MaintenanceServiceClient, MaintenanceStatusRequest, MaintenanceTransport,
        };
        let client = MaintenanceServiceClient::new(MaintenanceTransport::Tls {
            endpoint,
            server_name: "localhost".into(),
            trust_file,
        })?;
        let status = client.status("fixture-admin", &MaintenanceStatusRequest::decode(br"{}")?)?;
        assert_eq!(status.total, 0);
        Ok(())
    })
}

#[test]
fn administrative_fixture_accepts_a_response_within_the_generated_administration_cap() -> TestResult
{
    delayed_response(false, |endpoint, trust| {
        let response = administrative_tls_http(
            "retention-budget",
            endpoint,
            &trust,
            "POST",
            "/v1/maintenance:status",
            &[("Content-Type", "application/json")],
            br"{}",
        )?;
        assert_status(response, 200);
        Ok(())
    })
}

#[test]
fn administrative_fixture_never_refreshes_its_budget_after_response_bytes() -> TestResult {
    let started = std::time::Instant::now();
    let failure = delayed_response(true, |endpoint, trust| {
        administrative_tls_http(
            "retention-budget",
            endpoint,
            &trust,
            "POST",
            "/v1/maintenance:status",
            &[("Content-Type", "application/json")],
            br"{}",
        )
    })
    .expect_err("a held-open peer must not claim completion")
    .to_string();
    assert!(failure.contains("content_length_complete=true"));
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "response bytes cannot refresh the original administrative budget"
    );
    Ok(())
}
