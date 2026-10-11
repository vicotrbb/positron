use super::*;

fn envelope(
    identity: ProviderKeyUri,
    context: EnvelopeContext,
    length: usize,
) -> Result<KeyEnvelope, KeyProviderFailure> {
    let mut ciphertext = vec![0x55; 29 + length];
    *ciphertext
        .first_mut()
        .ok_or(KeyProviderFailure::ContextMismatch)? = 1;
    KeyEnvelope::from_provider_response(identity, context, WrappingAlgorithm::Aes256Gcm, ciphertext)
}
#[tokio::test]
async fn native_admission_and_drop_release_a_cancelled_tls_operation()
-> Result<(), Box<dyn std::error::Error>> {
    use std::future::Future;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://127.0.0.1:{port}/objects/immutable-id"),
        PIN,
    )?;
    let provider = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let mut first = Box::pin(provider.probe(context));
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(
        provider.probe(context).await.err(),
        Some(KeyProviderFailure::LimitExceeded)
    );
    drop(first);
    drop(listener);
    assert_eq!(
        provider.probe(context).await.err(),
        Some(KeyProviderFailure::Unavailable)
    );
    drop(provider);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[tokio::test]
async fn native_source_migrates_through_the_shared_verified_session_to_local_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let destination_root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let (port, server) = transcript_connections(|port| {
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )
        .expect("fixed identity");
        let payload = SecretWrappedKeyPayload::encode(
            &SecretKek::from_owned(Box::new([9; 32])),
            context,
            &identity,
        )
        .expect("fixed payload");
        vec![
            vec![discover(), metadata("immutable-id")],
            vec![
                discover(),
                metadata("immutable-id"),
                response(
                    0x20,
                    0,
                    &[
                        field(0x420094, 7, b"immutable-id"),
                        field(0x4200c2, 8, payload.as_provider_plaintext()),
                    ]
                    .concat(),
                ),
            ],
        ]
    })
    .await?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let payload = SecretWrappedKeyPayload::encode(
        &SecretKek::from_owned(Box::new([9; 32])),
        context,
        &identity,
    )?;
    let source_envelope = envelope(
        identity.clone(),
        context,
        payload.as_provider_plaintext().len(),
    )?;
    drop(payload);
    let original = source_envelope.encode();
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let source = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
    let destination = LocalKeyProvider::from_custody(
        crate::data_protection::BootstrapKeyCustody::initialize(&destination_root.path)?,
    )?;
    let destination_session = KeyProviderSession::new(&destination);
    let replacement = KeyProviderSession::new(&source)
        .rewrap(&source_envelope, context, &destination_session)
        .await?;
    assert_eq!(source_envelope.encode(), original);
    assert_ne!(replacement.identity(), source_envelope.identity());
    destination_session.verify(&replacement, context).await?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    assert_eq!(
        destination_session.verify(&replacement, wrong).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    server.await?;
    drop(source);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[tokio::test]
async fn transport_loss_is_unavailable_before_encrypt_and_ambiguous_after_submission()
-> Result<(), Box<dyn std::error::Error>> {
    for submitted in [false, true] {
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let replies = if submitted {
            vec![discover(), metadata("immutable-id"), Vec::new()]
        } else {
            vec![Vec::new()]
        };
        let (port, server) = transcript_sequence(replies).await?;
        let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            Kmip21KeyProvider::required_resources(),
        )?)?;
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )?;
        let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
        let payload = SecretWrappedKeyPayload::encode(
            &SecretKek::from_owned(Box::new([9; 32])),
            context,
            &identity,
        )?;
        let provider = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
        assert_eq!(
            provider.wrap(payload, context).await.err(),
            Some(if submitted {
                KeyProviderFailure::Ambiguous
            } else {
                KeyProviderFailure::Unavailable
            })
        );
        assert_eq!(server.await?.len(), if submitted { 3 } else { 1 });
        drop(provider);
        assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn native_cache_initialization_refuses_context_correct_substituted_probe_key()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let (port, server) = transcript_connections(|port| {
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )
        .expect("fixed identity");
        let payload = SecretWrappedKeyPayload::encode(
            &SecretKek::from_owned(Box::new([9; 32])),
            context,
            &identity,
        )
        .expect("fixed payload");
        let encrypted = response(
            0x1f,
            0,
            &[
                field(0x420094, 7, b"immutable-id"),
                field(
                    0x4200c2,
                    8,
                    &vec![0x55; payload.as_provider_plaintext().len()],
                ),
                field(0x42003d, 8, &[4; 12]),
                field(0x4200ff, 8, &[5; 16]),
            ]
            .concat(),
        );
        let plaintext = response(
            0x20,
            0,
            &[
                field(0x420094, 7, b"immutable-id"),
                field(0x4200c2, 8, payload.as_provider_plaintext()),
            ]
            .concat(),
        );
        vec![
            vec![discover(), metadata("immutable-id")],
            vec![discover(), metadata("immutable-id"), encrypted],
            vec![discover(), metadata("immutable-id")],
            vec![discover(), metadata("immutable-id"), plaintext],
        ]
    })
    .await?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let payload = SecretWrappedKeyPayload::encode(
        &SecretKek::from_owned(Box::new([9; 32])),
        context,
        &identity,
    )?;
    let source = envelope(
        identity.clone(),
        context,
        payload.as_provider_plaintext().len(),
    )?;
    drop(payload);
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let provider = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
    let memory = KeyProviderCache::<Kmip21KeyProvider>::required_memory_bytes(1)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(ResourceAmounts::new(
        [memory, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
    ))?)?;
    let mut cache = KeyProviderCache::new(&provider, KeyCacheLease::default(), 1, grant)?;
    assert_eq!(
        cache.load(&source, context).await.err(),
        Some(KeyProviderFailure::WrongKey)
    );
    server.await?;
    assert_eq!(cache.resident_keys(), 0);
    drop(cache);
    drop(provider);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}
