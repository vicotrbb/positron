use super::fixtures::*;
use super::*;
mod lifecycle;
mod native;
mod receipts;

#[tokio::test]
async fn native_envelopes_verify_canonical_payload_and_reject_wrong_scope_before_io()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let (port, server) = transcript_connections(|port| {
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )
        .expect("fixture identity");
        let payload = SecretWrappedKeyPayload::encode(
            &SecretKek::from_owned(Box::new([9; 32])),
            context,
            &identity,
        )
        .expect("fixture payload");
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
            vec![discover(), metadata("immutable-id"), encrypted],
            vec![discover(), metadata("immutable-id"), plaintext],
        ]
    })
    .await?;
    let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
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
    let provider = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
    let envelope = provider.wrap(payload, context).await?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    assert_eq!(
        provider.unwrap(&envelope, wrong).await.err(),
        Some(KeyProviderFailure::ContextMismatch)
    );
    let recovered = provider.unwrap(&envelope, context).await?;
    assert!(recovered.verify(context, provider.identity()).is_ok());
    let requests = server.await?;
    let aad = field(0x4200fe, 8, &context.encode(provider.identity()));
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.windows(aad.len()).any(|w| w == aad))
            .count(),
        2
    );
    let encrypt = requests.get(2).expect("encrypt request");
    for parameter in [
        number(0x4200cd, 2, 96),
        number(0x4200ce, 2, 16),
        field(0x4200c5, 6, &1u64.to_be_bytes()),
    ] {
        assert!(encrypt.windows(parameter.len()).any(|w| w == parameter));
    }
    drop(requests);
    drop(provider);
    assert_eq!(kernel.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[tokio::test]
async fn native_probe_rejects_replaced_material_under_the_same_object_id()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let digest = field(
        0x420034,
        1,
        &[
            number(0x420038, 5, 6),
            number(0x420042, 5, 1),
            field(0x420035, 8, &[7; 32]),
        ]
        .concat(),
    );
    let attrs = [
        number(0x420057, 5, 2),
        number(0x420028, 5, 3),
        number(0x42002a, 2, 256),
        number(0x42002c, 2, 12),
        number(0x42008d, 5, 2),
        digest,
    ]
    .concat();
    let reply = response(
        0x0b,
        0,
        &[
            field(0x420094, 7, b"immutable-id"),
            field(0x420125, 1, &attrs),
        ]
        .concat(),
    );
    let (port, server) = transcript_sequence(vec![discover(), reply]).await?;
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
        provider.probe(context).await.err(),
        Some(KeyProviderFailure::WrongKey)
    );
    server.await?;
    Ok(())
}

#[tokio::test]
async fn native_probe_requires_a_complete_raw_sha256_digest()
-> Result<(), Box<dyn std::error::Error>> {
    for (digest, failure) in [
        (Vec::new(), KeyProviderFailure::ContextMismatch),
        (digest(6, 1, &[6; 31]), KeyProviderFailure::ContextMismatch),
        (digest(4, 1, &[6; 32]), KeyProviderFailure::PermissionDenied),
        (digest(6, 2, &[6; 32]), KeyProviderFailure::PermissionDenied),
    ] {
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let attrs = [
            number(0x420057, 5, 2),
            number(0x420028, 5, 3),
            number(0x42002a, 2, 256),
            number(0x42002c, 2, 12),
            number(0x42008d, 5, 2),
            digest,
        ]
        .concat();
        let reply = response(
            0x0b,
            0,
            &[
                field(0x420094, 7, b"immutable-id"),
                field(0x420125, 1, &attrs),
            ]
            .concat(),
        );
        let (port, server) = transcript_sequence(vec![discover(), reply]).await?;
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
            Some(failure)
        );
        server.await?;
    }
    Ok(())
}
#[tokio::test]
async fn native_encrypt_refuses_published_ciphertext_of_another_payload_length()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let encrypted = response(
        0x1f,
        0,
        &[
            field(0x420094, 7, b"immutable-id"),
            field(0x4200c2, 8, &hex(OASIS_CIPHERTEXT)),
            field(0x42003d, 8, &[0; 12]),
            field(0x4200ff, 8, &hex(OASIS_TAG)),
        ]
        .concat(),
    );
    let (port, server) =
        transcript_sequence(vec![discover(), metadata("immutable-id"), encrypted]).await?;
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
        Some(KeyProviderFailure::ContextMismatch)
    );
    server.await?;
    Ok(())
}
#[tokio::test]
async fn native_server_capacity_failure_is_typed_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let reply = response(
        0x1e,
        1,
        &[
            number(0x42007e, 5, 0x3a),
            field(0x42007d, 7, b"secret-error-canary"),
        ]
        .concat(),
    );
    let (port, server) = transcript(reply).await?;
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
    let rejected = provider.probe(context).await;
    assert_eq!(rejected, Err(KeyProviderFailure::LimitExceeded));
    assert!(!format!("{rejected:?}").contains("canary"));
    server.await?;
    Ok(())
}

#[tokio::test]
async fn native_probe_refuses_malformed_untrusted_frames_and_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    let mut cases = vec![
        (
            vec![0x42, 0, 0x7b, 1, 0xff, 0xff, 0xff, 0xff],
            KeyProviderFailure::LimitExceeded,
        ),
        (
            vec![0x42, 0, 0x7b, 1, 0, 0, 0, 0],
            KeyProviderFailure::ContextMismatch,
        ),
        (
            vec![0x42, 0, 0x7b, 1, 0, 0, 0, 1],
            KeyProviderFailure::ContextMismatch,
        ),
        (
            vec![0x42, 0, 0x78, 1, 0, 0, 0, 8],
            KeyProviderFailure::ContextMismatch,
        ),
        (response(0x20, 0, &[]), KeyProviderFailure::ContextMismatch),
        (response(0x1e, 2, &[]), KeyProviderFailure::ContextMismatch),
        (
            field(0x42007b, 1, &[0x42, 0, 0x7a, 1, 0xff, 0xff, 0xff, 0xff]),
            KeyProviderFailure::LimitExceeded,
        ),
    ];
    let version = field(
        0x420069,
        1,
        &[number(0x42006a, 2, 2), number(0x42006b, 2, 1)].concat(),
    );
    cases.push((
        response(0x1e, 0, &[version.clone(), version].concat()),
        KeyProviderFailure::ContextMismatch,
    ));
    for (reply, expected) in cases {
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let (port, server) = transcript(reply).await?;
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
        assert_eq!(provider.probe(context).await.err(), Some(expected));
        server.await?;
    }
    Ok(())
}
#[tokio::test]
async fn native_probe_requires_active_pinned_aes256_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    for (tag, kind, bad) in [
        (0x420057, 5, 3),
        (0x420028, 5, 4),
        (0x42002a, 2, 128),
        (0x42002c, 2, 4),
        (0x42008d, 5, 3),
    ] {
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let good = [
            (0x420057, 5, 2),
            (0x420028, 5, 3),
            (0x42002a, 2, 256),
            (0x42002c, 2, 12),
            (0x42008d, 5, 2),
        ];
        let mut attributes = good
            .into_iter()
            .flat_map(|(t, k, v)| number(t, k, if (t, k) == (tag, kind) { bad } else { v }))
            .collect::<Vec<_>>();
        attributes.extend(digest(6, 1, &[6; 32]));
        let reply = response(
            0x0b,
            0,
            &[
                field(0x420094, 7, b"immutable-id"),
                field(0x420125, 1, &attributes),
            ]
            .concat(),
        );
        let (port, server) = transcript_sequence(vec![discover(), reply]).await?;
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
            provider.probe(context).await.err(),
            Some(KeyProviderFailure::PermissionDenied)
        );
        server.await?;
    }
    Ok(())
}
