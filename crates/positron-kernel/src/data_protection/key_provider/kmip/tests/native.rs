use super::*;
#[tokio::test]
async fn native_identity_custody_is_bounded_and_reopened_after_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    for (name, kind, failure) in [
        ("cert", 0, KeyProviderFailure::PermissionDenied),
        ("key", 1, KeyProviderFailure::LimitExceeded),
        ("ca", 2, KeyProviderFailure::InvalidConfiguration),
        ("key", 3, KeyProviderFailure::PermissionDenied),
    ] {
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let credentials = model(&root.path)?;
        let path = root.path.join(name);
        match kind {
            0 => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?,
            1 => std::fs::write(&path, vec![0; 32769])?,
            2 => {
                std::fs::remove_file(&path)?;
                std::os::unix::fs::symlink(root.path.join("cert"), &path)?;
            },
            _ => std::fs::hard_link(&path, root.path.join("extra-link"))?,
        }
        let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            Kmip21KeyProvider::required_resources(),
        )?)?;
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            "kmip://localhost:5696/objects/immutable-id",
            PIN,
        )?;
        assert_eq!(
            Kmip21KeyProvider::from_native(identity, credentials, grant).err(),
            Some(failure)
        );
        assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    }
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let credentials = model(&root.path)?;
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        "kmip://localhost:5696/objects/immutable-id",
        PIN,
    )?;
    let provider = Kmip21KeyProvider::from_native(identity, credentials, grant)?;
    std::fs::write(root.path.join("key"), b"credential-reload-canary")?;
    let failure = provider
        .probe(EnvelopeContext::new(
            [1; 16],
            KeyScope::System,
            [2; 32],
            1,
            1,
        )?)
        .await
        .err();
    assert_eq!(failure, Some(KeyProviderFailure::InvalidConfiguration));
    assert!(!format!("{failure:?}").contains("canary"));
    drop(provider);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}
#[tokio::test]
async fn native_tls_refuses_untrusted_peer_and_tls12_without_plaintext_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    for tls12 in [false, true] {
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let credentials = model(&root.path)?;
        if !tls12 {
            std::fs::write(root.path.join("ca"), CLIENT_CERT)?;
        }
        let versions = if tls12 {
            &[&rustls::version::TLS12][..]
        } else {
            &[&rustls::version::TLS13][..]
        };
        let (port, server) = transcript_transport(|_| vec![Vec::new()], versions).await?;
        let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            Kmip21KeyProvider::required_resources(),
        )?)?;
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )?;
        let provider = Kmip21KeyProvider::from_native(identity, credentials, grant)?;
        assert_eq!(
            provider
                .probe(EnvelopeContext::new(
                    [1; 16],
                    KeyScope::System,
                    [2; 32],
                    1,
                    1
                )?)
                .await
                .err(),
            Some(KeyProviderFailure::PermissionDenied)
        );
        assert!(server.await?.is_empty());
        drop(provider);
        assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    }
    Ok(())
}
#[tokio::test]
async fn authenticated_native_probe_refuses_protocol_downgrade()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let (port, server) = transcript(hex(DOWNGRADE)).await?;
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let provider = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    assert_eq!(
        provider.probe(context).await,
        Err(KeyProviderFailure::PermissionDenied)
    );
    server.await?;
    Ok(())
}
#[tokio::test]
async fn invalid_native_identity_is_rejected_without_network_work()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let path = root.path.join("kmip-identity");
    std::fs::write(&path, b"private-identity-canary")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let reference = CredentialFileReference::new(&path)?;
    let model = ProviderCredentialModel::KmipMutualTls {
        certificate: reference.clone(),
        private_key: reference.clone(),
        trust_roots: reference,
    };
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        "kmip://hsm.test/objects/immutable-id",
        PIN,
    )?;
    let rejected = Kmip21KeyProvider::from_native(identity, model, grant).err();
    assert_eq!(rejected, Some(KeyProviderFailure::InvalidConfiguration));
    assert!(!format!("{rejected:?}").contains("canary"));
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}
