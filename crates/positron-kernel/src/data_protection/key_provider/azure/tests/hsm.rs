//! Independent Managed HSM published-wire contract tests, without a service emulator.
use super::*;

fn hsm_uri(version: &str) -> ProviderKeyUri {
    ProviderKeyUri::new(
        ProviderFamily::AzureManagedHsm,
        &format!("https://fixture.managedhsm.azure.net/keys/root/{version}"),
        version,
    )
    .expect("published immutable Managed HSM URI")
}
fn identity() -> ProviderKeyUri {
    hsm_uri("0123456789abcdef0123456789abcdef")
}
fn hsm_metadata(identity: &ProviderKeyUri) -> Vec<u8> {
    format!(r#"{{"key":{{"kid":"{}","kty":"RSA-HSM","key_ops":["wrapKey","unwrapKey"],"n":"{}","e":"AQAB"}},"attributes":{{"enabled":true}}}}"#,
        identity.locator(), URL_SAFE_NO_PAD.encode([0xff;256])).into_bytes()
}
fn receipt(identity: &ProviderKeyUri, value: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"kid":"{}","value":"{}"}}"#,
        identity.locator(),
        URL_SAFE_NO_PAD.encode(value)
    )
    .into_bytes()
}
#[derive(Debug)]
struct HsmIdentity(&'static str);
#[async_trait::async_trait]
impl TokenCredential for HsmIdentity {
    async fn get_token(
        &self,
        scopes: &[&str],
        _: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<azure_core::credentials::AccessToken> {
        assert_eq!(scopes, &[self.0]);
        Ok(azure_core::credentials::AccessToken::new(
            "fictional-hsm-native-secret",
            azure_core::time::OffsetDateTime::now_utc() + azure_core::time::Duration::hours(1),
        ))
    }
}
fn provider(
    identity: ProviderKeyUri,
    replies: Vec<native::Response>,
) -> (AzureManagedHsmKeyProvider, Arc<Transcript>) {
    let runtime = Arc::new(Transcript {
        replies: Mutex::new(replies.into()),
        requests: Mutex::new(Vec::new()),
        wait_when_exhausted: false,
    });
    (
        AzureManagedHsmKeyProvider(AzureProvider {
            identity,
            credentials: Arc::new(HsmIdentity("https://managedhsm.azure.net/.default")),
            credential_model: ProviderCredentialModel::AzureManagedIdentity,
            runtime: runtime.clone(),
            active: AtomicBool::new(false),
        }),
        runtime,
    )
}
fn ok(body: Vec<u8>) -> native::Response {
    native::Response {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: Zeroizing::new(body),
    }
}

#[tokio::test]
async fn managed_hsm_wrap_unwrap_pins_native_service_algorithm_and_embedded_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    let canonical = payload(context(), &id);
    let (provider, runtime) = provider(
        id.clone(),
        vec![
            ok(hsm_metadata(&id)),
            ok(hsm_metadata(&id)),
            ok(receipt(&id, &[7; 256])),
            ok(hsm_metadata(&id)),
            ok(hsm_metadata(&id)),
            ok(receipt(&id, canonical.as_provider_plaintext())),
        ],
    );
    let envelope = KeyProviderSession::new(&provider)
        .wrap(SecretKek::from_owned(Box::new([9; 32])), context())
        .await?;
    assert_eq!(envelope.identity(), &id);
    KeyProviderSession::new(&provider)
        .verify(&envelope, context())
        .await?;
    let requests = runtime.requests.lock().map_err(|_| "transcript poisoned")?;
    assert_eq!(requests.len(), 6);
    let wrap = requests.get(2).ok_or("missing HSM wrap")?;
    assert_eq!(
        wrap.url,
        format!("{}/wrapkey?api-version=7.6", id.locator())
    );
    assert_eq!(wrap.method, http::Method::POST);
    let parsed: serde_json::Value = serde_json::from_slice(&wrap.body)?;
    assert_eq!(
        parsed.get("alg").and_then(serde_json::Value::as_str),
        Some("RSA-OAEP-256")
    );
    let expected = Zeroizing::new(URL_SAFE_NO_PAD.encode(canonical.as_provider_plaintext()));
    assert!(
        parsed.get("value").and_then(serde_json::Value::as_str) == Some(expected.as_str()),
        "HSM must wrap the complete canonical payload"
    );
    assert_eq!(
        requests.get(5).ok_or("missing HSM unwrap")?.url,
        format!("{}/unwrapkey?api-version=7.6", id.locator())
    );
    Ok(())
}

#[tokio::test]
async fn managed_hsm_metadata_rejects_software_keys_disabled_missing_operations_and_wrong_versions()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    let body = String::from_utf8(hsm_metadata(&id))?;
    for (body, failure) in [
        (
            body.replace("RSA-HSM", "RSA"),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            body.replace("RSA-HSM", "oct-HSM"),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            body.replace("\"enabled\":true", "\"enabled\":false"),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            body.replace("unwrapKey", "sign"),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            body.replace(
                "0123456789abcdef0123456789abcdef",
                "1123456789abcdef0123456789abcdef",
            ),
            KeyProviderFailure::WrongKey,
        ),
        (
            body.replace("AQAB", "Ag"),
            KeyProviderFailure::InvalidConfiguration,
        ),
        (
            body.replace("\"enabled\":true", "\"enabled\":true,\"exp\":0"),
            KeyProviderFailure::PermissionDenied,
        ),
        (
            body.replace(
                "\"enabled\":true",
                "\"enabled\":true,\"nbf\":18446744073709551615",
            ),
            KeyProviderFailure::PermissionDenied,
        ),
        ("{".to_owned(), KeyProviderFailure::ContextMismatch),
        (" ".repeat(32769), KeyProviderFailure::LimitExceeded),
    ] {
        let (provider, _) = provider(id.clone(), vec![ok(body.into_bytes())]);
        assert_eq!(provider.probe(context()).await.err(), Some(failure));
    }
    Ok(())
}

#[tokio::test]
async fn managed_hsm_unwrap_recovers_date_expired_keys_but_disabled_keys_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    let canonical = payload(context(), &id);
    let envelope = KeyEnvelope::from_provider_response(
        id.clone(),
        context(),
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
    )?;
    for attributes in [
        "\"enabled\":true,\"exp\":0",
        "\"enabled\":true,\"nbf\":18446744073709551615",
    ] {
        let metadata = String::from_utf8(hsm_metadata(&id))?
            .replace("\"enabled\":true", attributes)
            .into_bytes();
        let (provider, _) = provider(
            id.clone(),
            vec![
                ok(metadata),
                ok(receipt(&id, canonical.as_provider_plaintext())),
            ],
        );
        assert!(
            provider
                .unwrap(&envelope, context())
                .await?
                .verify(context(), &id)
                .is_ok()
        );
    }
    let disabled = String::from_utf8(hsm_metadata(&id))?
        .replace("\"enabled\":true", "\"enabled\":false,\"exp\":0")
        .into_bytes();
    let (provider, runtime) = provider(id, vec![ok(disabled)]);
    assert_eq!(
        provider.unwrap(&envelope, context()).await.err(),
        Some(KeyProviderFailure::PermissionDenied)
    );
    assert_eq!(runtime.requests.lock().map_err(|_| "poisoned")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn managed_hsm_receipts_and_substituted_routing_cannot_release_a_kek()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    let canonical = payload(context(), &id);
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    for (body, failure) in [
        (
            receipt(
                &hsm_uri("1123456789abcdef0123456789abcdef"),
                canonical.as_provider_plaintext(),
            ),
            KeyProviderFailure::WrongKey,
        ),
        (
            receipt(&id, b"corrupt-plaintext-canary"),
            KeyProviderFailure::ContextMismatch,
        ),
        (
            receipt(&id, &vec![7; 447]),
            KeyProviderFailure::LimitExceeded,
        ),
        (receipt(&id, b""), KeyProviderFailure::ContextMismatch),
        (b"{".to_vec(), KeyProviderFailure::ContextMismatch),
    ] {
        let (provider, _) = provider(id.clone(), vec![ok(hsm_metadata(&id)), ok(body)]);
        let envelope = KeyEnvelope::from_provider_response(
            id.clone(),
            context(),
            WrappingAlgorithm::RsaOaepSha256,
            vec![7; 256],
        )?;
        assert_eq!(
            provider.unwrap(&envelope, context()).await.err(),
            Some(failure)
        );
    }
    let (provider, runtime) = provider(
        id.clone(),
        vec![
            ok(hsm_metadata(&id)),
            ok(receipt(&id, canonical.as_provider_plaintext())),
        ],
    );
    let forged = KeyEnvelope::from_provider_response(
        id.clone(),
        wrong,
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
    )?;
    assert_eq!(
        provider.unwrap(&forged, wrong).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    assert_eq!(
        provider.unwrap(&forged, context()).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    assert_eq!(runtime.requests.lock().map_err(|_| "poisoned")?.len(), 2);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn managed_hsm_local_rbac_throttling_and_outage_have_bounded_secret_free_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    for (status, failure, attempts) in [
        (401, KeyProviderFailure::PermissionDenied, 1),
        (403, KeyProviderFailure::PermissionDenied, 1),
        (404, KeyProviderFailure::WrongKey, 1),
        (410, KeyProviderFailure::WrongKey, 1),
        (429, KeyProviderFailure::Unavailable, 2),
        (500, KeyProviderFailure::Ambiguous, 1),
        (503, KeyProviderFailure::Ambiguous, 1),
        (400, KeyProviderFailure::ContextMismatch, 1),
    ] {
        let mut replies = vec![ok(hsm_metadata(&id))];
        replies.extend((0..attempts).map(|_| native::Response {
            status: http::StatusCode::from_u16(status).expect("published status"),
            headers: http::HeaderMap::new(),
            body: Zeroizing::new(b"hsm-secret-error-canary".to_vec()),
        }));
        let (provider, runtime) = provider(id.clone(), replies);
        let error = provider
            .wrap(payload(context(), &id), context())
            .await
            .err()
            .ok_or("accepted failure")?;
        assert_eq!(error, failure);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert_eq!(
            runtime.requests.lock().map_err(|_| "poisoned")?.len(),
            attempts + 1
        );
    }
    Ok(())
}

#[tokio::test]
async fn managed_hsm_rotation_and_local_migration_keep_source_identity_and_authenticate_successor()
-> Result<(), Box<dyn std::error::Error>> {
    let source_id = identity();
    let destination_id = hsm_uri("1123456789abcdef0123456789abcdef");
    let plain = payload(context(), &source_id);
    let (source, _) = provider(
        source_id.clone(),
        vec![
            ok(hsm_metadata(&source_id)),
            ok(hsm_metadata(&source_id)),
            ok(receipt(&source_id, plain.as_provider_plaintext())),
            ok(hsm_metadata(&source_id)),
            ok(hsm_metadata(&source_id)),
            ok(receipt(&source_id, plain.as_provider_plaintext())),
        ],
    );
    let destination_plain = payload(context(), &destination_id);
    let (destination, _) = provider(
        destination_id.clone(),
        vec![
            ok(hsm_metadata(&destination_id)),
            ok(hsm_metadata(&destination_id)),
            ok(receipt(&destination_id, &[8; 256])),
            ok(hsm_metadata(&destination_id)),
            ok(hsm_metadata(&destination_id)),
            ok(receipt(
                &destination_id,
                destination_plain.as_provider_plaintext(),
            )),
        ],
    );
    let envelope = KeyEnvelope::from_provider_response(
        source_id.clone(),
        context(),
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
    )?;
    let successor = source
        .rewrap_envelope(&envelope, context(), &destination)
        .await?;
    assert_eq!(successor.identity(), &destination_id);
    assert_eq!(envelope.identity(), &source_id);
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let local = LocalKeyProvider::from_custody(
        crate::data_protection::BootstrapKeyCustody::initialize(&root.path)?,
    )?;
    let migrated = KeyProviderSession::new(&source)
        .rewrap(&envelope, context(), &KeyProviderSession::new(&local))
        .await?;
    assert_eq!(migrated.identity(), local.identity());
    KeyProviderSession::new(&local)
        .verify(&migrated, context())
        .await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn managed_hsm_deadline_cancellation_and_competing_work_release_operation_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    let (mut provider, runtime) = provider(id.clone(), vec![ok(hsm_metadata(&id))]);
    let pending = Arc::new(Transcript {
        replies: Mutex::new(std::collections::VecDeque::from([ok(hsm_metadata(&id))])),
        requests: Mutex::new(Vec::new()),
        wait_when_exhausted: true,
    });
    provider.0.runtime = pending.clone();
    {
        let operation = provider.wrap(payload(context(), &id), context());
        tokio::pin!(operation);
        tokio::select! { result=&mut operation => panic!("pending transcript completed {result:?}"), ()=tokio::task::yield_now()=>{} }
        assert_eq!(
            provider.probe(context()).await.err(),
            Some(KeyProviderFailure::LimitExceeded)
        );
    }
    // Dropping the pending future releases admission, so the next call reaches
    // the empty transcript and times out instead of remaining concurrency-refused.
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::Unavailable)
    );
    provider.0.runtime = runtime.clone();
    assert_eq!(
        provider
            .wrap(payload(context(), &id), context())
            .await
            .err(),
        Some(KeyProviderFailure::Ambiguous)
    );
    assert_eq!(runtime.requests.lock().map_err(|_| "poisoned")?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn managed_hsm_cold_cache_outage_and_harness_family_mismatch_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    let (provider, runtime) = provider(id.clone(), vec![]);
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let bytes = KeyProviderCache::<AzureManagedHsmKeyProvider>::required_memory_bytes(1)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        crate::ResourceAmounts::new([bytes, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]),
    )?)?;
    let mut cache = KeyProviderCache::new(&provider, KeyCacheLease::default(), 1, grant)?;
    let envelope = KeyEnvelope::from_provider_response(
        id,
        context(),
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
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
    let target = ProviderConformanceTarget::new(
        ProviderFamily::AzureKeyVault,
        "Azure Key Vault",
        "7.6",
        "fixture",
    )?;
    let calls = runtime.requests.lock().map_err(|_| "poisoned")?.len();
    let error = KeyProviderConformance::healthy(&provider, target, context())
        .await
        .err()
        .ok_or("HSM accepted as vault")?;
    assert_eq!(error.step, ConformanceStep::Target);
    assert_eq!(error.failure, KeyProviderFailure::WrongKey);
    assert_eq!(
        runtime.requests.lock().map_err(|_| "poisoned")?.len(),
        calls
    );
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    assert_eq!(
        provider.verify_envelope(&envelope, wrong).await,
        Err(KeyProviderFailure::ContextMismatch)
    );
    assert_eq!(
        provider.verify_envelope(&envelope, context()).await,
        Err(KeyProviderFailure::Unavailable)
    );
    Ok(())
}

#[tokio::test]
async fn managed_hsm_sovereign_native_scopes_are_independent_of_vault_scopes()
-> Result<(), Box<dyn std::error::Error>> {
    for (suffix, scope) in [
        (
            "managedhsm.azure.cn",
            "https://managedhsm.azure.cn/.default",
        ),
        (
            "managedhsm.usgovcloudapi.net",
            "https://managedhsm.usgovcloudapi.net/.default",
        ),
    ] {
        let id = ProviderKeyUri::new(
            ProviderFamily::AzureManagedHsm,
            &format!("https://fixture.{suffix}/keys/root/0123456789abcdef0123456789abcdef"),
            "0123456789abcdef0123456789abcdef",
        )?;
        let (mut provider, _) = provider(id.clone(), vec![ok(hsm_metadata(&id))]);
        provider.0.credentials = Arc::new(HsmIdentity(scope));
        let capabilities = provider.probe(context()).await?;
        assert_eq!(capabilities.identity, id);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn managed_hsm_throttle_receipts_honor_bounded_delays_without_replaying_ambiguous_wrap()
-> Result<(), Box<dyn std::error::Error>> {
    let id = identity();
    for (header, value, retry) in [
        ("x-ms-retry-after-ms", "200", true),
        ("retry-after", "1", true),
        ("x-ms-retry-after-ms", "2001", false),
        ("retry-after", "3", false),
        ("retry-after", "invalid", false),
    ] {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::HeaderName::from_bytes(header.as_bytes())?,
            http::HeaderValue::from_str(value)?,
        );
        let (provider, runtime) = provider(
            id.clone(),
            vec![
                ok(hsm_metadata(&id)),
                native::Response {
                    status: http::StatusCode::TOO_MANY_REQUESTS,
                    headers,
                    body: Zeroizing::new(b"hsm-throttle-secret-canary".to_vec()),
                },
                ok(receipt(&id, &[7; 256])),
            ],
        );
        let result = provider.wrap(payload(context(), &id), context()).await;
        if retry {
            assert_eq!(result?.identity(), &id);
        } else {
            assert_eq!(result.err(), Some(KeyProviderFailure::Unavailable));
        }
        assert_eq!(
            runtime.requests.lock().map_err(|_| "poisoned")?.len(),
            if retry { 3 } else { 2 }
        );
    }
    Ok(())
}
