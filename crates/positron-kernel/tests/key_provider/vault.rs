use super::*;
use positron_kernel::key_provider::{
    CredentialFileReference, TransitAuthentication, VaultTransitKeyProvider,
};

#[test]
fn vault_native_admission_and_credential_bounds_fail_before_network_work()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::KeyProviderFailure;
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, VaultTransitKeyProvider::required_resources())?;
    let governor = authority.governor();
    let token = root.0.join("token");
    let identity = || {
        ProviderKeyUri::new(
            ProviderFamily::VaultTransit,
            "https://vault.example/v1/transit/keys/root",
            "1",
        )
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            positron_kernel::ResourceAmounts::new([1; 11]),
        )?)?;
        let rejected = VaultTransitKeyProvider::from_native(
            identity()?,
            TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&token)?),
            "",
            None,
            grant,
        )
        .err()
        .ok_or("unadmitted source accepted")?;
        assert_eq!(rejected, KeyProviderFailure::LimitExceeded);
        for (bytes, expected) in [
            (Vec::new(), KeyProviderFailure::InvalidConfiguration),
            (vec![0xff], KeyProviderFailure::InvalidConfiguration),
            (vec![b'a'; 8193], KeyProviderFailure::LimitExceeded),
        ] {
            std::fs::write(&token, bytes)?;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
            let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
                tenant,
                positron_kernel::WorkKind::SecurityLifecycle,
                VaultTransitKeyProvider::required_resources(),
            )?)?;
            let rejected = VaultTransitKeyProvider::from_native(
                identity()?,
                TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&token)?),
                "",
                None,
                grant,
            )
            .err()
            .ok_or("invalid credential accepted")?;
            assert_eq!(rejected, expected);
            assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        }
        std::fs::write(&token, b"fictional-token")?;
        let alias = root.0.join("token-alias");
        std::os::unix::fs::symlink(&token, &alias)?;
        let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            VaultTransitKeyProvider::required_resources(),
        )?)?;
        assert_eq!(
            VaultTransitKeyProvider::from_native(
                identity()?,
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

#[test]
fn vault_native_private_ca_requires_a_bounded_valid_trust_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, VaultTransitKeyProvider::required_resources())?;
    let governor = authority.governor();
    let token = root.0.join("token");
    std::fs::write(&token, b"fictional-token")?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    let ca = root.0.join("ca.pem");
    std::fs::write(&ca, b"not a certificate")?;
    let ca = CredentialFileReference::new(&ca)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            VaultTransitKeyProvider::required_resources(),
        )?)?;
        let identity = ProviderKeyUri::new(
            ProviderFamily::VaultTransit,
            "https://vault.example/v1/transit/keys/root",
            "1",
        )?;
        let error = VaultTransitKeyProvider::from_native(
            identity,
            TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&token)?),
            "",
            Some(&ca),
            grant,
        )
        .err()
        .ok_or("invalid CA accepted")?;
        assert_eq!(
            error,
            positron_kernel::key_provider::KeyProviderFailure::InvalidConfiguration
        );
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn vault_native_private_ca_refuses_writable_trust_input() -> Result<(), Box<dyn std::error::Error>>
{
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, VaultTransitKeyProvider::required_resources())?;
    let governor = authority.governor();
    let token = root.0.join("token");
    std::fs::write(&token, b"fictional-token")?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    let ca = root.0.join("ca.pem");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"
        ),
        &ca,
    )?;
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o666))?;
    let ca = CredentialFileReference::new(&ca)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            VaultTransitKeyProvider::required_resources(),
        )?)?;
        let identity = ProviderKeyUri::new(
            ProviderFamily::VaultTransit,
            "https://vault.example/v1/transit/keys/root",
            "1",
        )?;
        let error = VaultTransitKeyProvider::from_native(
            identity,
            TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&token)?),
            "",
            Some(&ca),
            grant,
        )
        .err()
        .ok_or("writable CA accepted")?;
        assert_eq!(
            error,
            positron_kernel::key_provider::KeyProviderFailure::PermissionDenied
        );
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn vault_native_custody_retains_admission_and_refuses_unsafe_token_files()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, VaultTransitKeyProvider::required_resources())?;
    let governor = authority.governor();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let token = root.0.join("token");
    std::fs::write(&token, b"fictional-vault-token-canary")?;
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
    let identity = || {
        ProviderKeyUri::new(
            ProviderFamily::VaultTransit,
            "https://vault.example:8200/v1/transit/keys/root",
            "1",
        )
    };
    let grant = || -> Result<_, Box<dyn std::error::Error>> {
        Ok(governor.reserve(positron_kernel::WorkClaim::tenant(
            tenant,
            positron_kernel::WorkKind::SecurityLifecycle,
            VaultTransitKeyProvider::required_resources(),
        )?)?)
    };
    runtime.block_on(async {
        let provider = VaultTransitKeyProvider::from_native(
            identity()?,
            TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&token)?),
            "",
            None,
            grant()?,
        )?;
        assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
        drop(provider);
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644))?;
        let rejected = VaultTransitKeyProvider::from_native(
            identity()?,
            TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&token)?),
            "",
            None,
            grant()?,
        )
        .err()
        .ok_or("unsafe token accepted")?;
        assert_eq!(
            rejected,
            positron_kernel::key_provider::KeyProviderFailure::PermissionDenied
        );
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn vault_kubernetes_native_projected_jwt_rotation_preserves_protected_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let (authority, tenant) =
        provider_authority(&root, VaultTransitKeyProvider::required_resources())?;
    let governor = authority.governor();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    for generation in ["..first", "..second"] {
        let directory = root.0.join(generation);
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let jwt = directory.join("jwt");
        std::fs::write(&jwt, b"fictional-projected-jwt-canary")?;
        std::fs::set_permissions(&jwt, std::fs::Permissions::from_mode(0o600))?;
    }
    std::os::unix::fs::symlink("..first", root.0.join("..data"))?;
    std::os::unix::fs::symlink("..data/jwt", root.0.join("jwt"))?;
    for generation in ["..first", "..second"] {
        if generation == "..second" {
            std::os::unix::fs::symlink(generation, root.0.join("..next"))?;
            std::fs::rename(root.0.join("..next"), root.0.join("..data"))?;
        }
        runtime.block_on(async {
            let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
                tenant,
                positron_kernel::WorkKind::SecurityLifecycle,
                VaultTransitKeyProvider::required_resources(),
            )?)?;
            let identity = ProviderKeyUri::new(
                ProviderFamily::VaultTransit,
                "https://vault.example/v1/transit/keys/root",
                "1",
            )?;
            let provider = VaultTransitKeyProvider::from_native(
                identity,
                TransitAuthentication::Kubernetes {
                    role: "positron".to_owned(),
                    jwt_file: CredentialFileReference::new(&root.0.join("jwt"))?,
                },
                "kubernetes",
                None,
                grant,
            )?;
            drop(provider);
            assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn vault_native_tls_private_ca_accepts_published_wire_and_refuses_untrusted_peers()
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
                    r#"{"version":"2.1.2","initialized":true,"sealed":false,"standby":false}"#;
                let metadata = r#"{"data":{"name":"root","type":"aes256-gcm96","derived":true,"convergent_encryption":false,"supports_encryption":true,"supports_decryption":true,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"latest_version":1,"keys":{"1":1442851412}}}"#;
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
            provider_authority(&root, VaultTransitKeyProvider::required_resources())?;
        let governor = authority.governor();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(async {
            let grant = governor.reserve(positron_kernel::WorkClaim::tenant(
                tenant,
                positron_kernel::WorkKind::SecurityLifecycle,
                VaultTransitKeyProvider::required_resources(),
            )?)?;
            let identity = ProviderKeyUri::new(
                ProviderFamily::VaultTransit,
                &format!("https://localhost:{port}/v1/transit/keys/root"),
                "1",
            )?;
            let roots = CredentialFileReference::new(&std::fs::canonicalize(certificate)?)?;
            let provider = VaultTransitKeyProvider::from_native(
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
