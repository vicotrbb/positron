use super::*;

#[tokio::test]
async fn native_decrypt_refuses_substituted_receipts_and_payloads()
-> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
        let (port, server) = transcript_connections(|port| {
            let identity = ProviderKeyUri::new(
                ProviderFamily::Kmip21,
                &format!("kmip://localhost:{port}/objects/immutable-id"),
                PIN,
            )
            .expect("fixed identity");
            let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)
                .expect("wrong epoch");
            let payload = SecretWrappedKeyPayload::encode(
                &SecretKek::from_owned(Box::new([9; 32])),
                if kind == 2 { wrong } else { context },
                &identity,
            )
            .expect("fixed payload");
            let bytes = match kind {
                1 => &payload.as_provider_plaintext()[..4],
                3 => &[0; 1025],
                _ => payload.as_provider_plaintext(),
            };
            let reply = response(
                if kind == 4 { 0x1f } else { 0x20 },
                0,
                &[
                    field(
                        0x420094,
                        7,
                        if kind == 0 {
                            b"replaced-id"
                        } else {
                            b"immutable-id"
                        },
                    ),
                    field(0x4200c2, 8, bytes),
                ]
                .concat(),
            );
            vec![vec![discover(), metadata("immutable-id"), reply]]
        })
        .await?;
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )?;
        let source = KeyEnvelope::from_provider_response(
            identity.clone(),
            context,
            WrappingAlgorithm::Aes256Gcm,
            [vec![1], vec![0; 40]].concat(),
        )?;
        let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            Kmip21KeyProvider::required_resources(),
        )?)?;
        let provider = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
        let expected = match kind {
            0 => KeyProviderFailure::WrongKey,
            3 => KeyProviderFailure::LimitExceeded,
            _ => KeyProviderFailure::ContextMismatch,
        };
        assert_eq!(
            provider.unwrap(&source, context).await.err(),
            Some(expected)
        );
        server.await?;
    }
    Ok(())
}

#[tokio::test]
async fn native_encrypt_requires_exact_iv_tag_identity_and_strict_success()
-> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..5 {
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
            // OASIS §9.18: a well-formed Success cannot include Result Reason.
            let extra = match kind {
                3 => number(0x42007e, 5, 1),
                4 => number(0x420123, 5, 1),
                _ => Vec::new(),
            };
            let reply = response_extra(
                0x1f,
                0,
                &[
                    field(
                        0x420094,
                        7,
                        if kind == 0 {
                            b"replaced-id"
                        } else {
                            b"immutable-id"
                        },
                    ),
                    field(
                        0x4200c2,
                        8,
                        &vec![0x55; payload.as_provider_plaintext().len()],
                    ),
                    field(0x42003d, 8, &vec![4; if kind == 1 { 11 } else { 12 }]),
                    field(0x4200ff, 8, &vec![5; if kind == 2 { 15 } else { 16 }]),
                ]
                .concat(),
                &extra,
            );
            vec![vec![discover(), metadata("immutable-id"), reply]]
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
        let kernel = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            Kmip21KeyProvider::required_resources(),
        )?)?;
        let provider = Kmip21KeyProvider::from_native(identity, model(&root.path)?, grant)?;
        assert_eq!(
            provider.wrap(payload, context).await.err(),
            Some(if kind == 0 {
                KeyProviderFailure::WrongKey
            } else {
                KeyProviderFailure::ContextMismatch
            })
        );
        server.await?;
    }
    Ok(())
}
