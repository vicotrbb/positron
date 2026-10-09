use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread::JoinHandle;
use std::time::Duration;

use positron_api::api_keys::{ApiKeyServiceClient, ApiKeyTransport};
use positron_api::maintenance::MaintenanceServiceClient;
use positron_api::policy::{
    PolicyActivateServiceClient, PolicyDiffServiceClient, PolicyExplainServiceClient,
    PolicyPreviewServiceClient, PolicyTestServiceClient,
};
use positron_api::tenant_aliases::TenantAliasServiceClient;
use positron_api::tenant_lifecycle::TenantLifecycleServiceClient;
use positron_api::tenant_quotas::TenantQuotaServiceClient;
use positron_api::tenant_retention::TenantRetentionServiceClient;
use positron_api::tenant_service::{
    MAX_RESPONSE_BYTES, TenantListRequest, TenantServiceClient, TenantServiceClientFailure,
};

type Server = JoinHandle<std::io::Result<()>>;

fn response_server(
    status: u16,
    body: Vec<u8>,
    advertised_bytes: usize,
) -> std::io::Result<(SocketAddr, Server)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        assert_eq!(line, "POST /v1/tenants:list HTTP/1.1\r\n");
        let mut length = 0;
        loop {
            line.clear();
            reader.read_line(&mut line)?;
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
        assert!(length <= 1024);
        let mut request = vec![0; length];
        reader.read_exact(&mut request)?;
        assert_eq!(request, br#"{"continuation":null}"#);
        write!(
            stream,
            "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {advertised_bytes}\r\nConnection: close\r\n\r\n"
        )?;
        stream.write_all(&body)?;
        Ok(())
    });
    Ok((endpoint, server))
}

#[test]
fn tenant_client_accepts_the_inclusive_response_bound_and_refuses_excess()
-> Result<(), Box<dyn std::error::Error>> {
    for (length, accepted) in [(MAX_RESPONSE_BYTES, true), (MAX_RESPONSE_BYTES + 1, false)] {
        let mut body = b"{\"tenants\":[]}".to_vec();
        body.resize(length, b' ');
        let (endpoint, server) = response_server(200, body, length)?;
        let client = TenantServiceClient::new(ApiKeyTransport::PlaintextOptOut { endpoint })?;
        let result = client.list("test-key", &TenantListRequest::new());
        if accepted {
            assert!(result?.tenants.is_empty());
        } else {
            assert_eq!(result.unwrap_err(), TenantServiceClientFailure::Transport);
        }
        server.join().expect("HTTP fixture thread")?;
    }
    Ok(())
}

#[test]
fn tenant_client_preserves_error_mapping_and_refuses_incomplete_responses()
-> Result<(), Box<dyn std::error::Error>> {
    for (status, body, truncated, expected) in [
        (
            401,
            b"{\"code\":\"authentication_rejected\"}".as_slice(),
            false,
            TenantServiceClientFailure::AuthenticationRejected,
        ),
        (
            409,
            b"{\"code\":\"stale_continuation\"}".as_slice(),
            false,
            TenantServiceClientFailure::StaleContinuation,
        ),
        (
            503,
            b"{\"code\":\"unknown\"}".as_slice(),
            false,
            TenantServiceClientFailure::Transport,
        ),
        (
            200,
            b"{\"tenants\":[]}".as_slice(),
            true,
            TenantServiceClientFailure::Transport,
        ),
    ] {
        let (endpoint, server) =
            response_server(status, body.to_vec(), body.len() + usize::from(truncated))?;
        let client = TenantServiceClient::new(ApiKeyTransport::PlaintextOptOut { endpoint })?;
        assert_eq!(
            client
                .list("test-key", &TenantListRequest::new())
                .unwrap_err(),
            expected
        );
        server.join().expect("HTTP fixture thread")?;
    }
    Ok(())
}

#[test]
fn every_service_refuses_invalid_tls_identity_before_credentials_can_be_sent() {
    let trust_file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem");
    for (server_name, accepted) in [
        ("localhost".to_owned(), true),
        (String::new(), false),
        ("a".repeat(254), false),
        ("127.0.0.2".to_owned(), false),
    ] {
        let transport = ApiKeyTransport::Tls {
            endpoint: "127.0.0.1:443".parse().expect("literal endpoint"),
            server_name,
            trust_file: trust_file.clone(),
        };
        assert_eq!(
            ApiKeyServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            MaintenanceServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            TenantAliasServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            TenantLifecycleServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            TenantQuotaServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            TenantRetentionServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            TenantServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            PolicyActivateServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            PolicyDiffServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            PolicyExplainServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(
            PolicyPreviewServiceClient::new(transport.clone()).is_ok(),
            accepted
        );
        assert_eq!(PolicyTestServiceClient::new(transport).is_ok(), accepted);
    }
}

#[test]
fn api_key_client_preserves_its_stricter_server_name_character_check() {
    let transport = ApiKeyTransport::Tls {
        endpoint: "127.0.0.1:443".parse().expect("literal endpoint"),
        server_name: "local_host".to_owned(),
        trust_file: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"),
    };
    assert!(TenantServiceClient::new(transport.clone()).is_ok());
    assert!(ApiKeyServiceClient::new(transport).is_err());
}
