use super::*;

#[tokio::test(start_paused = true)]
async fn renewable_machine_tokens_use_returned_ttl_and_fail_closed_on_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let auth=br#"{"auth":{"client_token":"fictional-token-canary","lease_duration":100,"renewable":true,"token_type":"service","num_uses":0}}"#;
    let (provider, transcript) = fixture(vec![
        reply(auth),
        reply(HEALTH),
        reply(METADATA),
        reply(HEALTH),
        reply(METADATA),
    ]);
    provider
        .token
        .lock()
        .map_err(|_| "poisoned")?
        .as_mut()
        .ok_or("missing token")?
        .renew_at = tokio::time::Instant::now();
    provider.probe(context()).await?;
    provider.probe(context()).await?;
    assert_eq!(
        transcript
            .requests
            .lock()
            .map_err(|_| "poisoned")?
            .first()
            .ok_or("missing renewal")?
            .url,
        "https://vault.example:8200/v1/auth/token/renew-self"
    );
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 5);
    for (from, to, expected) in [
        (
            "fictional-token-canary",
            "changed-token",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            "\"renewable\":true",
            "\"renewable\":false",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            "\"token_type\":\"service\"",
            "\"token_type\":\"batch\"",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            "\"lease_duration\":100",
            "\"lease_duration\":0",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            "\"num_uses\":0",
            "\"num_uses\":1",
            KeyProviderFailure::PermissionDenied,
        ),
    ] {
        let (provider, transcript) =
            fixture(vec![reply(std::str::from_utf8(auth)?.replace(from, to))]);
        provider
            .token
            .lock()
            .map_err(|_| "poisoned")?
            .as_mut()
            .ok_or("missing token")?
            .renew_at = tokio::time::Instant::now();
        assert_eq!(provider.probe(context()).await.err(), Some(expected));
        assert!(provider.token.lock().map_err(|_| "poisoned")?.is_none());
        assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 1);
    }
    let mut denied = reply(b"secret-renewal-rejection-canary");
    denied.status = http::StatusCode::FORBIDDEN;
    let (provider, transcript) = fixture(vec![denied]);
    provider
        .token
        .lock()
        .map_err(|_| "poisoned")?
        .as_mut()
        .ok_or("missing token")?
        .renew_at = tokio::time::Instant::now();
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::PermissionDenied)
    );
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn expired_jwt_authentication_reopens_the_rotated_native_projection()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let path = root.path.join("jwt");
    std::fs::write(&path, b"fictional-first-jwt")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let auth=br#"{"auth":{"client_token":"fictional-machine-token","lease_duration":2,"renewable":true,"token_type":"service","num_uses":0}}"#;
    let (mut provider, transcript) = fixture(vec![
        reply(auth),
        reply(HEALTH),
        reply(METADATA),
        reply(auth),
        reply(HEALTH),
        reply(METADATA),
    ]);
    provider.credential_model = ProviderCredentialModel::Transit(TransitAuthentication::Jwt {
        role: "positron".to_owned(),
        jwt_file: CredentialFileReference::new(&path)?,
    });
    provider.authentication_mount = "machine-jwt".to_owned();
    *provider.token.lock().map_err(|_| "poisoned")? = None;
    provider.probe(context()).await?;
    std::fs::write(&path, b"fictional-successor-jwt")?;
    tokio::time::advance(Duration::from_secs(3)).await;
    provider.probe(context()).await?;
    let requests = transcript.requests.lock().map_err(|_| "poisoned")?;
    assert_eq!(requests.len(), 6);
    assert_eq!(
        requests.first().ok_or("missing login")?.url,
        "https://vault.example:8200/v1/auth/machine-jwt/login"
    );
    assert!(
        requests
            .get(3)
            .ok_or("missing successor login")?
            .body
            .windows(b"fictional-successor-jwt".len())
            .any(|w| w == b"fictional-successor-jwt")
    );
    Ok(())
}

#[tokio::test]
async fn protected_token_native_lookup_rejects_wrong_identity_and_nonrenewable_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let path = root.path.join("token");
    std::fs::write(&path, b"fictional-token\n")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let lookup = r#"{"data":{"id":"fictional-token","ttl":300,"renewable":true,"type":"service","num_uses":0}}"#;
    for (from, to, expected) in [
        (
            "fictional-token",
            "other-token",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            "\"renewable\":true",
            "\"renewable\":false",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            "\"num_uses\":0",
            "\"num_uses\":1",
            KeyProviderFailure::PermissionDenied,
        ),
    ] {
        let (mut provider, transcript) = fixture(vec![reply(lookup.replace(from, to))]);
        provider.credential_model = ProviderCredentialModel::Transit(
            TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&path)?),
        );
        *provider.token.lock().map_err(|_| "poisoned")? = None;
        assert_eq!(provider.probe(context()).await.err(), Some(expected));
        assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn rotation_and_cross_provider_migration_use_the_existing_session_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let source_id = uri();
    let envelope = KeyEnvelope::from_provider_response(
        source_id.clone(),
        context(),
        WrappingAlgorithm::Aes256Gcm,
        CIPHERTEXT.as_bytes().to_vec(),
    )?;
    let phases = || {
        vec![
            reply(HEALTH),
            reply(METADATA),
            reply(HEALTH),
            reply(METADATA),
            decrypted(context(), &source_id),
        ]
    };
    let (source, _) = fixture(phases());
    let dest_id = ProviderKeyUri::new(ProviderFamily::VaultTransit, source_id.locator(), "2")?;
    let dest_metadata = std::str::from_utf8(METADATA)?
        .replace("\"latest_version\":1", "\"latest_version\":2")
        .replace("\"1\":1442851412", "\"1\":1442851412,\"2\":1442851512");
    let dest_ciphertext = CIPHERTEXT.replace("vault:v1:", "vault:v2:");
    let replies = vec![
        reply(HEALTH),
        reply(&dest_metadata),
        reply(HEALTH),
        reply(&dest_metadata),
        reply(format!(
            r#"{{"data":{{"ciphertext":"{dest_ciphertext}","key_version":2}}}}"#
        )),
        reply(HEALTH),
        reply(&dest_metadata),
        reply(HEALTH),
        reply(&dest_metadata),
        decrypted(context(), &dest_id),
    ];
    let (mut destination, _) = fixture(replies);
    destination.identity = dest_id.clone();
    let successor = KeyProviderSession::new(&source)
        .rewrap(&envelope, context(), &KeyProviderSession::new(&destination))
        .await?;
    assert_eq!(successor.identity(), &dest_id);
    assert_eq!(envelope.identity(), &source_id);
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let local = LocalKeyProvider::from_custody(
        crate::data_protection::BootstrapKeyCustody::initialize(&root.path)?,
    )?;
    let (source, _) = fixture(phases());
    let migrated = KeyProviderSession::new(&source)
        .rewrap(&envelope, context(), &KeyProviderSession::new(&local))
        .await?;
    KeyProviderSession::new(&local)
        .verify(&migrated, context())
        .await?;
    let (restarted, _) = fixture(phases());
    KeyProviderSession::new(&restarted)
        .verify(&KeyEnvelope::decode(&envelope.encode())?, context())
        .await?;
    Ok(())
}

#[tokio::test]
async fn shared_cache_never_persists_a_lease_for_an_unavailable_vault_key()
-> Result<(), Box<dyn std::error::Error>> {
    let (provider, _) = fixture(vec![]);
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let bytes = KeyProviderCache::<VaultTransitKeyProvider>::required_memory_bytes(1)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        crate::ResourceAmounts::new([bytes, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]),
    )?)?;
    let mut cache = KeyProviderCache::new(&provider, KeyCacheLease::default(), 1, grant)?;
    let envelope = KeyEnvelope::from_provider_response(
        uri(),
        context(),
        WrappingAlgorithm::Aes256Gcm,
        CIPHERTEXT.as_bytes().to_vec(),
    )?;
    assert_eq!(
        cache.load(&envelope, context()).await,
        Err(KeyProviderFailure::Unavailable)
    );
    assert_eq!(cache.resident_keys(), 0);
    assert!(cache.health().provider_degraded);
    assert!(!cache.health().system_ready);
    drop(cache);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}
