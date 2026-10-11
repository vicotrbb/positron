//! Fixed wire receipts independently derived from OpenBao a5db72ce source.
use super::*;
const BAO_HEALTH: &[u8] =
    br#"{"version":"2.7.1","initialized":true,"sealed":false,"standby":false}"#;
const BAO_METADATA: &[u8] = br#"{"data":{"name":"root","type":"aes256-gcm96","derived":true,"convergent_encryption":false,"supports_encryption":true,"supports_decryption":true,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"latest_version":1,"keys":{"1":1442851412},"soft_deleted":false}}"#;
fn bao_uri() -> ProviderKeyUri {
    ProviderKeyUri::new(
        ProviderFamily::OpenBaoTransit,
        "https://bao.example:8200/v1/transit/keys/root",
        "1",
    )
    .expect("fixed OpenBao identity")
}
fn bao(replies: Vec<native::Response>) -> (OpenBaoTransitKeyProvider, Arc<Transcript>) {
    let (mut core, transcript) = fixture(replies);
    core.identity = bao_uri();
    (OpenBaoTransitKeyProvider(core), transcript)
}
#[tokio::test]
async fn openbao_native_wrap_unwrap_and_public_session_preserve_target_context()
-> Result<(), Box<dyn std::error::Error>> {
    let (provider, transcript) = bao(vec![
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        encrypted(),
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        decrypted(context(), &bao_uri()),
    ]);
    let envelope = provider
        .wrap(payload(context(), &bao_uri()), context())
        .await?;
    assert_eq!(provider.identity(), &bao_uri());
    assert_eq!(envelope.identity(), &bao_uri());
    provider
        .unwrap(&envelope, context())
        .await?
        .verify(context(), &bao_uri())?;
    {
        let requests = transcript.requests.lock().map_err(|_| "poisoned")?;
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests.get(2).ok_or("encrypt missing")?.url,
            "https://bao.example:8200/v1/transit/encrypt/root"
        );
        let request: serde_json::Value =
            serde_json::from_slice(&requests.get(2).ok_or("encrypt missing")?.body)?;
        assert_eq!(request.get("key_version"), Some(&serde_json::json!(1)));
        assert_eq!(request.get("context"), request.get("associated_data"));
        assert!(request.get("nonce").is_none());
        assert!(request.get("batch_input").is_none());
        assert!(
            requests
                .iter()
                .filter_map(|r| r.headers.get("x-vault-token"))
                .all(http::HeaderValue::is_sensitive)
        );
    }
    let (provider, _) = bao(vec![
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        encrypted(),
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        decrypted(context(), &bao_uri()),
    ]);
    let envelope = provider.create_envelope(context()).await?;
    provider.verify_envelope(&envelope, context()).await?;
    assert!(matches!(
        provider.credential_model(),
        ProviderCredentialModel::Transit(_)
    ));
    Ok(())
}
#[tokio::test]
async fn openbao_receipts_fail_closed_on_independent_pin_deletion_and_key_policy()
-> Result<(), Box<dyn std::error::Error>> {
    for (source, from, to, expected) in [
        (
            BAO_HEALTH,
            "2.7.1",
            "2.1.2",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            BAO_HEALTH,
            "\"sealed\":false",
            "\"sealed\":true",
            KeyProviderFailure::Unavailable,
        ),
        (
            BAO_HEALTH,
            "\"standby\":false",
            "\"standby\":true",
            KeyProviderFailure::Unavailable,
        ),
        (
            BAO_METADATA,
            "\"soft_deleted\":false",
            "\"soft_deleted\":true",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            BAO_METADATA,
            ",\"soft_deleted\":false",
            "",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            BAO_METADATA,
            "\"root\"",
            "\"other\"",
            KeyProviderFailure::WrongKey,
        ),
        (
            BAO_METADATA,
            "aes256-gcm96",
            "aes128-gcm96",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            BAO_METADATA,
            "\"derived\":true",
            "\"derived\":false",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            BAO_METADATA,
            "\"convergent_encryption\":false",
            "\"convergent_encryption\":true",
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            BAO_METADATA,
            "\"supports_decryption\":true",
            "\"supports_decryption\":false",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            BAO_METADATA,
            "\"min_decryption_version\":1",
            "\"min_decryption_version\":2",
            KeyProviderFailure::PermissionDenied,
        ),
        (
            BAO_METADATA,
            "\"min_encryption_version\":0",
            "\"min_encryption_version\":2",
            KeyProviderFailure::PermissionDenied,
        ),
    ] {
        let changed = std::str::from_utf8(source)?.replace(from, to);
        let replies = if source == BAO_HEALTH {
            vec![reply(changed)]
        } else {
            vec![reply(BAO_HEALTH), reply(changed)]
        };
        let (provider, _) = bao(replies);
        assert_eq!(
            provider
                .wrap(payload(context(), &bao_uri()), context())
                .await
                .err(),
            Some(expected)
        );
    }
    for bytes in [
        b"{}".to_vec(),
        vec![b' '; 32769],
        br#"{"data":{"ciphertext":"vault:v2:AAAA","key_version":2}}"#.to_vec(),
    ] {
        let (provider, _) = bao(vec![reply(BAO_HEALTH), reply(BAO_METADATA), reply(bytes)]);
        assert!(
            provider
                .wrap(payload(context(), &bao_uri()), context())
                .await
                .is_err()
        );
    }
    Ok(())
}
#[tokio::test]
async fn openbao_wrong_scope_payload_ciphertext_and_family_never_cross_targets()
-> Result<(), Box<dyn std::error::Error>> {
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let envelope = KeyEnvelope::from_provider_response(
        bao_uri(),
        wrong,
        WrappingAlgorithm::Aes256Gcm,
        CIPHERTEXT.as_bytes().to_vec(),
    )?;
    let (provider, _) = bao(vec![
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        decrypted(context(), &bao_uri()),
    ]);
    assert_eq!(
        provider.unwrap(&envelope, wrong).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    for (identity, ctx, bytes, algorithm, expected) in [
        (
            bao_uri(),
            wrong,
            CIPHERTEXT.as_bytes().to_vec(),
            WrappingAlgorithm::Aes256Gcm,
            KeyProviderFailure::ContextMismatch,
        ),
        (
            uri(),
            context(),
            CIPHERTEXT.as_bytes().to_vec(),
            WrappingAlgorithm::Aes256Gcm,
            KeyProviderFailure::WrongKey,
        ),
        (
            bao_uri(),
            context(),
            CIPHERTEXT.replace("v1:", "v2:").into_bytes(),
            WrappingAlgorithm::Aes256Gcm,
            KeyProviderFailure::WrongKey,
        ),
        (
            bao_uri(),
            context(),
            b"vault:v1:!".to_vec(),
            WrappingAlgorithm::Aes256Gcm,
            KeyProviderFailure::ContextMismatch,
        ),
        (
            bao_uri(),
            context(),
            CIPHERTEXT.as_bytes().to_vec(),
            WrappingAlgorithm::Aes256Kwp,
            KeyProviderFailure::ContextMismatch,
        ),
    ] {
        let (provider, transcript) = bao(vec![]);
        let envelope = KeyEnvelope::from_provider_response(identity, ctx, algorithm, bytes)?;
        assert_eq!(
            provider.unwrap(&envelope, context()).await.err(),
            Some(expected)
        );
        assert!(
            transcript
                .requests
                .lock()
                .map_err(|_| "poisoned")?
                .is_empty()
        );
    }
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn openbao_outage_retry_and_ambiguous_encryption_have_bounded_public_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    for (status, expected) in [
        (403, KeyProviderFailure::PermissionDenied),
        (404, KeyProviderFailure::WrongKey),
        (400, KeyProviderFailure::ContextMismatch),
        (500, KeyProviderFailure::Ambiguous),
        (503, KeyProviderFailure::Unavailable),
    ] {
        let mut failure = reply(b"fictional-secret-response-canary");
        failure.status = http::StatusCode::from_u16(status)?;
        let (provider, transcript) = bao(vec![reply(BAO_HEALTH), reply(BAO_METADATA), failure]);
        let failure = provider
            .wrap(payload(context(), &bao_uri()), context())
            .await
            .err()
            .ok_or("failure accepted")?;
        assert_eq!(failure, expected);
        assert!(!format!("{failure:?} {failure}").contains("canary"));
        assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 3);
    }
    let mut throttled = reply(b"{\"errors\":[\"rate limit exceeded\"]}");
    throttled.status = http::StatusCode::TOO_MANY_REQUESTS;
    throttled.headers.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_static("1"),
    );
    let (provider, transcript) = bao(vec![
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        throttled,
        encrypted(),
    ]);
    provider
        .wrap(payload(context(), &bao_uri()), context())
        .await?;
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 4);
    let (mut provider, _) = bao(vec![]);
    let transcript = Arc::new(Transcript {
        replies: Mutex::new(vec![reply(BAO_HEALTH), reply(BAO_METADATA)].into()),
        requests: Mutex::new(Vec::new()),
        pending: true,
        delay: Duration::ZERO,
    });
    provider.0.runtime = transcript.clone();
    let operation = provider.wrap(payload(context(), &bao_uri()), context());
    tokio::pin!(operation);
    tokio::select! {r=&mut operation=>panic!("pending operation completed {}",r.is_ok()),()=tokio::task::yield_now()=>{}}
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(operation.await.err(), Some(KeyProviderFailure::Ambiguous));
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 3);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn openbao_native_authentication_lookup_login_renewal_and_reauthentication_are_bounded()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let file = root.path.join("credential");
    std::fs::write(&file, b"fictional-token-canary")?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    let lookup=br#"{"data":{"id":"fictional-token-canary","ttl":100,"renewable":true,"type":"service","num_uses":0}}"#;
    let auth=br#"{"auth":{"client_token":"fictional-token-canary","lease_duration":100,"renewable":true,"token_type":"service","num_uses":0}}"#;
    let (provider, transcript) = bao(vec![
        reply(lookup),
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
        reply(auth),
        reply(BAO_HEALTH),
        reply(BAO_METADATA),
    ]);
    provider.0.token.lock().map_err(|_| "poisoned")?.take();
    provider
        .0
        .credential_model
        .validate(ProviderFamily::OpenBaoTransit)?;
    // The protected file reference is explicit; no ambient token is discovered.
    let mut provider = provider;
    provider.0.credential_model = ProviderCredentialModel::Transit(
        TransitAuthentication::ProtectedTokenFile(CredentialFileReference::new(&file)?),
    );
    provider.probe(context()).await?;
    tokio::time::advance(Duration::from_secs(50)).await;
    provider.probe(context()).await?;
    {
        let requests = transcript.requests.lock().map_err(|_| "poisoned")?;
        assert_eq!(
            requests.first().ok_or("lookup missing")?.url,
            "https://bao.example:8200/v1/auth/token/lookup-self"
        );
        assert_eq!(
            requests.get(3).ok_or("renew missing")?.url,
            "https://bao.example:8200/v1/auth/token/renew-self"
        );
    }
    for kubernetes in [false, true] {
        std::fs::write(&file, b"fictional-original-jwt")?;
        let mut denied = reply(b"fictional-renewal-denial-canary");
        denied.status = http::StatusCode::FORBIDDEN;
        let (mut provider, transcript) = bao(vec![
            reply(auth),
            reply(BAO_HEALTH),
            reply(BAO_METADATA),
            denied,
            reply(auth),
            reply(BAO_HEALTH),
            reply(BAO_METADATA),
        ]);
        provider.0.credential_model = ProviderCredentialModel::Transit(if kubernetes {
            TransitAuthentication::Kubernetes {
                role: "positron".to_owned(),
                jwt_file: CredentialFileReference::new(&file)?,
            }
        } else {
            TransitAuthentication::Jwt {
                role: "positron".to_owned(),
                jwt_file: CredentialFileReference::new(&file)?,
            }
        });
        provider.0.authentication_mount = "workload".to_owned();
        provider.0.token.lock().map_err(|_| "poisoned")?.take();
        provider.probe(context()).await?;
        tokio::time::advance(Duration::from_secs(50)).await;
        assert_eq!(
            provider.probe(context()).await.err(),
            Some(KeyProviderFailure::PermissionDenied)
        );
        std::fs::write(&file, b"fictional-successor-jwt")?;
        provider.probe(context()).await?;
        let requests = transcript.requests.lock().map_err(|_| "poisoned")?;
        assert_eq!(requests.len(), 7);
        let recovered = requests.get(4).ok_or("reauthentication missing")?;
        assert_eq!(
            recovered.url,
            "https://bao.example:8200/v1/auth/workload/login"
        );
        assert!(
            recovered
                .body
                .windows(b"fictional-successor-jwt".len())
                .any(|b| b == b"fictional-successor-jwt")
        );
    }
    for (from, to, expected) in [
        (
            "\"num_uses\":0",
            "\"num_uses\":1",
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
        (",\"num_uses\":0", "", KeyProviderFailure::ContextMismatch),
    ] {
        let (mut provider, transcript) =
            bao(vec![reply(std::str::from_utf8(auth)?.replace(from, to))]);
        provider.0.credential_model =
            ProviderCredentialModel::Transit(TransitAuthentication::Jwt {
                role: "positron".to_owned(),
                jwt_file: CredentialFileReference::new(&file)?,
            });
        provider.0.authentication_mount = "jwt".to_owned();
        provider.0.token.lock().map_err(|_| "poisoned")?.take();
        assert_eq!(provider.probe(context()).await.err(), Some(expected));
        assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 1);
    }
    let (mut provider, _) = bao(vec![]);
    provider.0.credential_model = ProviderCredentialModel::Transit(TransitAuthentication::Jwt {
        role: "positron".to_owned(),
        jwt_file: CredentialFileReference::new(&file)?,
    });
    provider.0.authentication_mount = "jwt".to_owned();
    provider.0.token.lock().map_err(|_| "poisoned")?.take();
    provider.0.runtime = Arc::new(Transcript {
        replies: Mutex::new(
            vec![reply(
                std::str::from_utf8(auth)?
                    .replace("\"lease_duration\":100", "\"lease_duration\":2"),
            )]
            .into(),
        ),
        requests: Mutex::new(Vec::new()),
        pending: false,
        delay: Duration::from_secs(2),
    });
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::Unavailable)
    );
    Ok(())
}

#[tokio::test]
async fn openbao_rotation_migration_and_restart_recovery_use_verified_shared_sessions()
-> Result<(), Box<dyn std::error::Error>> {
    let source_id = bao_uri();
    let envelope = KeyEnvelope::from_provider_response(
        source_id.clone(),
        context(),
        WrappingAlgorithm::Aes256Gcm,
        CIPHERTEXT.as_bytes().to_vec(),
    )?;
    let source_replies = || {
        vec![
            reply(BAO_HEALTH),
            reply(BAO_METADATA),
            reply(BAO_HEALTH),
            reply(BAO_METADATA),
            decrypted(context(), &source_id),
        ]
    };
    let (source, _) = bao(source_replies());
    let destination_id =
        ProviderKeyUri::new(ProviderFamily::OpenBaoTransit, source_id.locator(), "2")?;
    let metadata = std::str::from_utf8(BAO_METADATA)?
        .replace("\"latest_version\":1", "\"latest_version\":2")
        .replace("\"1\":1442851412", "\"1\":1442851412,\"2\":1442851512");
    let ciphertext = CIPHERTEXT.replace("vault:v1:", "vault:v2:");
    let (mut destination, _) = bao(vec![
        reply(BAO_HEALTH),
        reply(&metadata),
        reply(BAO_HEALTH),
        reply(&metadata),
        reply(format!(
            r#"{{"data":{{"ciphertext":"{ciphertext}","key_version":2}}}}"#
        )),
        reply(BAO_HEALTH),
        reply(&metadata),
        reply(BAO_HEALTH),
        reply(&metadata),
        decrypted(context(), &destination_id),
    ]);
    destination.0.identity = destination_id.clone();
    let successor = KeyProviderSession::new(&source)
        .rewrap(&envelope, context(), &KeyProviderSession::new(&destination))
        .await?;
    assert_eq!(successor.identity(), &destination_id);
    assert_eq!(envelope.identity(), &source_id);
    let (restarted, _) = bao(source_replies());
    restarted
        .verify_envelope(&KeyEnvelope::decode(&envelope.encode())?, context())
        .await?;
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let local = LocalKeyProvider::from_custody(
        crate::data_protection::BootstrapKeyCustody::initialize(&root.path)?,
    )?;
    let (source, _) = bao(source_replies());
    let migrated = KeyProviderSession::new(&source)
        .rewrap(&envelope, context(), &KeyProviderSession::new(&local))
        .await?;
    KeyProviderSession::new(&local)
        .verify(&migrated, context())
        .await?;
    Ok(())
}

#[tokio::test]
async fn openbao_unavailable_cache_keys_are_never_resident_or_ready()
-> Result<(), Box<dyn std::error::Error>> {
    let (provider, _) = bao(vec![]);
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let bytes = KeyProviderCache::<OpenBaoTransitKeyProvider>::required_memory_bytes(1)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        crate::ResourceAmounts::new([bytes, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]),
    )?)?;
    let mut cache = KeyProviderCache::new(&provider, KeyCacheLease::default(), 1, grant)?;
    let envelope = KeyEnvelope::from_provider_response(
        bao_uri(),
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
