use super::*;
use positron_kernel::key_provider::{
    CredentialFileReference, OpenBaoTransitKeyProvider, TransitAuthentication,
};

#[test]
fn openbao_native_tls_private_ca_accepts_published_wire_and_refuses_untrusted_peers()
-> Result<(), Box<dyn std::error::Error>> {
    use rustls_pki_types::pem::PemObject;
    use std::io::{Read, Write};
    let certificate = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"
    );
    let private_key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../positron-runtime/tests/native_transport/fixtures/api-test-key.pem"
    );
    let certificates = rustls_pki_types::CertificateDer::pem_file_iter(certificate)?
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(&std::fs::read(private_key)?)?;
    let config = std::sync::Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)?,
    );
    for trusted in [false, true] {
        let root = Root::new()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let config = config.clone();
        // Six fixed published-format responses; no provider state, keys, dynamic
        // cryptography or request-dependent responses are simulated.
        let server = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let health =
                    r#"{"version":"2.7.1","initialized":true,"sealed":false,"standby":false}"#;
                let metadata = r#"{"data":{"name":"root","type":"aes256-gcm96","derived":true,"convergent_encryption":false,"supports_encryption":true,"supports_decryption":true,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"latest_version":1,"keys":{"1":1442851412},"soft_deleted":false}}"#;
                for (path, body) in [
                    (
                        "/v1/auth/token/lookup-self",
                        r#"{"data":{"id":"fictional-token-canary","ttl":300,"renewable":true,"type":"service","num_uses":0}}"#,
                    ),
                    ("/v1/sys/health", health),
                    ("/v1/transit/keys/root", metadata),
                    ("/v1/sys/health", health),
                    ("/v1/transit/keys/root", metadata),
                    (
                        "/v1/transit/encrypt/root",
                        r#"{"data":{"ciphertext":"vault:v1:XjsPWPjqPrBi1N2Ms2s1QM798YyFWnO4TR4lsFA=","key_version":1}}"#,
                    ),
                ] {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    let socket = loop {
                        match listener.accept() {
                            Ok((socket, _)) => break socket,
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    && std::time::Instant::now() < deadline =>
                            {
                                std::thread::sleep(std::time::Duration::from_millis(10))
                            },
                            Err(e) => return Err(Box::new(e)),
                        }
                    };
                    socket.set_nonblocking(false)?;
                    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
                    socket.set_write_timeout(Some(std::time::Duration::from_secs(3)))?;
                    let connection = rustls::ServerConnection::new(config.clone())?;
                    let mut stream = rustls::StreamOwned::new(connection, socket);
                    let mut head = zeroize::Zeroizing::new(Vec::with_capacity(8192));
                    loop {
                        let mut byte = [0];
                        match stream.read_exact(&mut byte) {
                            Ok(()) => head.extend_from_slice(&byte),
                            Err(_) if !trusted => {
                                assert!(head.is_empty(), "plaintext sent to untrusted TLS peer");
                                return Ok(());
                            },
                            Err(e) => return Err(Box::new(e)),
                        }
                        assert!(head.len() <= 8192, "native request header bound exceeded");
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = std::str::from_utf8(&head)?;
                    assert!(
                        text.lines()
                            .next()
                            .is_some_and(|line| line.split_whitespace().nth(1) == Some(path)),
                        "unexpected native request path"
                    );
                    if path != "/v1/sys/health" {
                        assert!(
                            text.contains("x-vault-token: fictional-token-canary"),
                            "missing machine token"
                        );
                    }
                    let length = text
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .map(str::parse::<usize>)
                        .transpose()?
                        .unwrap_or(0);
                    assert!(length <= 4096, "native request body bound exceeded");
                    let mut request = zeroize::Zeroizing::new(vec![0; length]);
                    stream.read_exact(&mut request)?;
                    if path.ends_with("/encrypt/root") {
                        assert!(
                            !request
                                .windows(b"\"nonce\"".len())
                                .any(|w| w == b"\"nonce\"")
                        );
                    }
                    stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )?;
                    stream.write_all(body.as_bytes())?;
                    stream.flush()?;
                }
                Ok(())
            },
        );
        let token = root.0.join("token");
        std::fs::write(&token, b"fictional-token-canary")?;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
        let (authority, tenant) =
            provider_authority(&root, OpenBaoTransitKeyProvider::required_resources())?;
        let governor = authority.governor();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(async {
            let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
                tenant,
                positron_kernel::WorkKind::SecurityLifecycle,
                OpenBaoTransitKeyProvider::required_resources(),
            )?)?;
            let identity = ProviderKeyUri::new(
                ProviderFamily::OpenBaoTransit,
                &format!("https://localhost:{port}/v1/transit/keys/root"),
                "1",
            )?;
            let roots = CredentialFileReference::new(&std::fs::canonicalize(certificate)?)?;
            let provider = OpenBaoTransitKeyProvider::from_native(
                identity,
                TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&token)?),
                "",
                trusted.then_some(&roots),
                grant,
            )?;
            let outcome = provider
                .create_envelope(EnvelopeContext::new(
                    [1; 16],
                    KeyScope::System,
                    [2; 32],
                    1,
                    1,
                )?)
                .await;
            if trusted {
                let envelope = outcome?;
                assert_eq!(envelope.identity(), provider.identity());
            } else {
                assert_eq!(
                    outcome.err(),
                    Some(positron_kernel::key_provider::KeyProviderFailure::Unavailable)
                );
            }
            drop(provider);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while governor.inspect()?.outstanding_reservations() != 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "native TLS workers retained admission"
                );
                tokio::task::yield_now().await;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        let server_result = server
            .join()
            .map_err(|_| "native TLS transcript panicked")?;
        if let Err(error) = &result {
            eprintln!("native TLS public outcome: {error}");
        }
        server_result.map_err(|error| format!("native TLS transcript failed: {error}"))?;
        result?;
    }
    Ok(())
}

#[test]
fn openbao_native_constructor_keeps_grants_credentials_and_targets_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::KeyProviderFailure;
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, OpenBaoTransitKeyProvider::required_resources())?;
    let governor = authority.governor();
    let path = root.0.join("token");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        for (family, mount, bytes, mode, expected) in [
            (
                ProviderFamily::VaultTransit,
                "",
                b"fictional-token".as_slice(),
                0o600,
                KeyProviderFailure::InvalidConfiguration,
            ),
            (
                ProviderFamily::OpenBaoTransit,
                "jwt",
                b"fictional-token".as_slice(),
                0o600,
                KeyProviderFailure::InvalidConfiguration,
            ),
            (
                ProviderFamily::OpenBaoTransit,
                "",
                b"fictional-token".as_slice(),
                0o644,
                KeyProviderFailure::PermissionDenied,
            ),
            (
                ProviderFamily::OpenBaoTransit,
                "",
                b"".as_slice(),
                0o600,
                KeyProviderFailure::InvalidConfiguration,
            ),
        ] {
            std::fs::write(&path, bytes)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
                tenant,
                positron_kernel::WorkKind::SecurityLifecycle,
                OpenBaoTransitKeyProvider::required_resources(),
            )?)?;
            assert_eq!(
                OpenBaoTransitKeyProvider::from_native(
                    ProviderKeyUri::new(family, "https://bao.example/v1/transit/keys/root", "1")?,
                    TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&path)?),
                    mount,
                    None,
                    grant
                )
                .err(),
                Some(expected)
            );
            assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        }
        std::fs::write(&path, b"fictional-token")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            positron_kernel::ResourceAmounts::new([1; 11]),
        )?)?;
        assert_eq!(
            OpenBaoTransitKeyProvider::from_native(
                ProviderKeyUri::new(
                    ProviderFamily::OpenBaoTransit,
                    "https://bao.example/v1/transit/keys/root",
                    "1"
                )?,
                TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&path)?),
                "",
                None,
                grant
            )
            .err(),
            Some(KeyProviderFailure::LimitExceeded)
        );
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        let alias = root.0.join("alias");
        std::os::unix::fs::symlink(&path, &alias)?;
        let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            OpenBaoTransitKeyProvider::required_resources(),
        )?)?;
        assert_eq!(
            OpenBaoTransitKeyProvider::from_native(
                ProviderKeyUri::new(
                    ProviderFamily::OpenBaoTransit,
                    "https://bao.example/v1/transit/keys/root",
                    "1"
                )?,
                TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&alias)?),
                "",
                None,
                grant
            )
            .err(),
            Some(KeyProviderFailure::InvalidConfiguration)
        );
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
