use super::*;

#[tokio::test(start_paused = true)]
async fn operation_deadline_and_concurrency_distinguish_wrap_ambiguity()
-> Result<(), Box<dyn std::error::Error>> {
    let transcript = Arc::new(Transcript {
        replies: Mutex::new(std::collections::VecDeque::from([native::Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: Zeroizing::new(metadata()),
        }])),
        requests: Mutex::new(Vec::new()),
        wait_when_exhausted: true,
    });
    let mut provider = fixture(vec![]);
    provider.runtime = transcript.clone();
    let wrapping = provider.wrap(payload(context(), &uri()), context());
    tokio::pin!(wrapping);
    tokio::select! { result = &mut wrapping => panic!("pending wrap completed {result:?}"), () = tokio::task::yield_now() => {} }
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    assert_eq!(wrapping.await.err(), Some(KeyProviderFailure::Ambiguous));
    assert_eq!(transcript.requests.lock().map_err(|_| "poisoned")?.len(), 2);
    assert_eq!(
        provider.probe(context()).await.err(),
        Some(KeyProviderFailure::Unavailable)
    );
    let provider = fixture(vec![metadata()]);
    let envelope = KeyEnvelope::from_provider_response(
        uri(),
        context(),
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
    )?;
    assert_eq!(
        provider.unwrap(&envelope, context()).await.err(),
        Some(KeyProviderFailure::Unavailable)
    );
    Ok(())
}
#[tokio::test]
async fn shared_cache_reports_azure_outage_without_creating_a_lease()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = fixture(vec![]);
    let kernel = crate::data_protection::tests::providers::provider_governor(2_000_000_000)?;
    let bytes = KeyProviderCache::<AzureProvider>::required_memory_bytes(1)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        crate::ResourceAmounts::new([bytes, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]),
    )?)?;
    let mut cache = KeyProviderCache::new(&provider, KeyCacheLease::default(), 1, grant)?;
    let envelope = KeyEnvelope::from_provider_response(
        uri(),
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
    Ok(())
}
#[tokio::test]
async fn rotation_and_local_migration_preserve_the_source_and_verify_successor_context()
-> Result<(), Box<dyn std::error::Error>> {
    let source_id = uri();
    let dest_id = ProviderKeyUri::new(
        ProviderFamily::AzureKeyVault,
        "https://fixture.vault.azure.net/keys/root/1123456789abcdef0123456789abcdef",
        "1123456789abcdef0123456789abcdef",
    )?;
    let plain = payload(context(), &source_id);
    let source = fixture(vec![
        metadata(),
        metadata(),
        result(plain.as_provider_plaintext()),
        metadata(),
        metadata(),
        result(plain.as_provider_plaintext()),
    ]);
    let envelope = KeyEnvelope::from_provider_response(
        source_id.clone(),
        context(),
        WrappingAlgorithm::RsaOaepSha256,
        vec![7; 256],
    )?;
    let successor_plain = payload(context(), &dest_id);
    let dest_metadata = || {
        String::from_utf8(metadata())
            .expect("wire UTF8")
            .replace(source_id.locator(), dest_id.locator())
            .into_bytes()
    };
    let dest_result = |value: &[u8]| {
        String::from_utf8(result(value))
            .expect("wire UTF8")
            .replace(source_id.locator(), dest_id.locator())
            .into_bytes()
    };
    let mut dest = fixture(vec![
        dest_metadata(),
        dest_metadata(),
        dest_result(&[8; 256]),
        dest_metadata(),
        dest_metadata(),
        dest_result(successor_plain.as_provider_plaintext()),
    ]);
    dest.identity = dest_id.clone();
    let successor = KeyProviderSession::new(&source)
        .rewrap(&envelope, context(), &KeyProviderSession::new(&dest))
        .await?;
    assert_eq!(successor.identity(), &dest_id);
    assert_eq!(envelope.identity(), &source_id);
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let local = LocalKeyProvider::from_custody(
        crate::data_protection::BootstrapKeyCustody::initialize(&root.path)?,
    )?;
    let local_id = local.identity().clone();
    let migrated = KeyProviderSession::new(&source)
        .rewrap(&envelope, context(), &KeyProviderSession::new(&local))
        .await?;
    assert_eq!(migrated.identity(), &local_id);
    KeyProviderSession::new(&local)
        .verify(&migrated, context())
        .await?;
    Ok(())
}
