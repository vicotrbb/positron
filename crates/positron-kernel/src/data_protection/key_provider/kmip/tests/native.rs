use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_recovery_rejects_substituted_system_payload_and_keeps_data_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    for wrong_context in [false, true] {
        let credentials = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let source = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let authority = crate::data_protection::tests::providers::provider_governor_with_slots(
            400_000_000,
            32,
        )?
        .into_authority();
        let session = crate::RootRewrapSession::admit_provider(&authority)?;
        let instance = crate::InstanceId::new([1; 16])?;
        let current = session.lease_system(
            crate::BootstrapKeyCustody::initialize(&source.path)?,
            instance,
            KeyCacheLease::default(),
        )?;
        let before = current.active_provider_identity()?;
        let context = session.system_context(instance, current.bootstrap_identity())?;
        let (port, server) = transcript_connections(|port| {
            let identity = ProviderKeyUri::new(
                ProviderFamily::Kmip21,
                &format!("kmip://localhost:{port}/objects/immutable-id"),
                PIN,
            )
            .expect("fixed identity");
            let mut returned_context = context;
            if wrong_context {
                returned_context.instance = [2; 16];
            }
            let payload = SecretWrappedKeyPayload::encode(
                &SecretKek::from_owned(Box::new([9; 32])),
                returned_context,
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
        let mut ciphertext = vec![0x55; 29 + payload.as_provider_plaintext().len()];
        *ciphertext
            .first_mut()
            .ok_or(KeyProviderFailure::ContextMismatch)? = 1;
        let envelope = KeyEnvelope::from_provider_response(
            identity.clone(),
            context,
            WrappingAlgorithm::Aes256Gcm,
            ciphertext,
        )?;
        current.invalidate_for_rotation()?;
        assert!(
            current
                .protect(
                    instance,
                    crate::BootstrapObjectPurpose::Initialized,
                    b"fenced"
                )
                .is_err()
        );
        let provider = session.native_provider(NativeRootConfiguration::Kmip {
            identity,
            credentials: model(&credentials.path)?,
        })?;
        assert!(
            session
                .prepare_provider_activation(&current, provider, instance, 2, &envelope.encode())
                .is_err()
        );
        assert_eq!(current.active_provider_identity()?, before);
        assert!(
            current
                .protect(
                    instance,
                    crate::BootstrapObjectPurpose::Initialized,
                    b"still fenced"
                )
                .is_err()
        );
        assert_eq!(server.await?.len(), 5);
        drop(current);
        drop(session);
        assert_eq!(
            authority.governor().inspect()?.outstanding_reservations(),
            0
        );
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_lease_native_custody_revalidates_each_object_and_outage_revokes_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let authority =
        crate::data_protection::tests::providers::provider_governor_with_slots(400_000_000, 32)?
            .into_authority();
    let session = crate::RootRewrapSession::admit_provider(&authority)?;
    let instance = crate::InstanceId::new([1; 16])?;
    let anchor = crate::BootstrapKeyIdentity::from_parts([7; 16], [8; 32], 0)?;
    let context = session.system_context(instance, anchor)?;
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
        let plaintext = response(
            0x20,
            0,
            &[
                field(0x420094, 7, b"immutable-id"),
                field(0x4200c2, 8, payload.as_provider_plaintext()),
            ]
            .concat(),
        );
        let mut replies = Vec::new();
        for _ in 0..7 {
            replies.push(vec![discover(), metadata("immutable-id")]);
            replies.push(vec![
                discover(),
                metadata("immutable-id"),
                plaintext.clone(),
            ]);
        }
        replies
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
    let mut ciphertext = vec![0x55; 29 + payload.as_provider_plaintext().len()];
    *ciphertext
        .first_mut()
        .ok_or(KeyProviderFailure::ContextMismatch)? = 1;
    let envelope = KeyEnvelope::from_provider_response(
        identity.clone(),
        context,
        WrappingAlgorithm::Aes256Gcm,
        ciphertext,
    )?;
    let provider = session.native_provider(NativeRootConfiguration::Kmip {
        identity: identity.clone(),
        credentials: model(&root.path)?,
    })?;
    let custody = session
        .open_provider_system(
            provider,
            instance,
            anchor,
            2,
            &envelope.encode(),
            KeyCacheLease::new(std::time::Duration::ZERO)?,
        )
        .await?;
    let first = custody.protect(
        instance,
        crate::BootstrapObjectPurpose::Initialized,
        b"first object",
    )?;
    let second = custody.protect(
        instance,
        crate::BootstrapObjectPurpose::Pending,
        b"different object purpose",
    )?;
    assert_eq!(
        custody
            .open_object(instance, crate::BootstrapObjectPurpose::Initialized, &first)?
            .as_slice(),
        b"first object"
    );
    custody.invalidate_for_rotation()?;
    assert!(
        custody
            .protect(
                instance,
                crate::BootstrapObjectPurpose::Initialized,
                b"unconfirmed"
            )
            .is_err()
    );
    session.confirm_active_provider(&custody, custody.active_root_identity()?, 2)?;
    custody.protect(
        instance,
        crate::BootstrapObjectPurpose::Claim,
        b"confirmed object",
    )?;
    assert_eq!(
        custody
            .open_object(instance, crate::BootstrapObjectPurpose::Pending, &second)?
            .as_slice(),
        b"different object purpose"
    );
    assert_eq!(server.await?.len(), 35);
    assert!(
        custody
            .protect(
                instance,
                crate::BootstrapObjectPurpose::Initialized,
                b"provider unavailable"
            )
            .is_err()
    );
    drop(custody);
    drop(session);
    assert_eq!(
        authority.governor().inspect()?.outstanding_reservations(),
        0
    );
    Ok(())
}
#[tokio::test]
async fn native_system_custody_recovers_with_only_the_pinned_provider_and_wrapped_system_key()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = crate::RootRewrapSession::admit(&authority)?;
    let instance = crate::InstanceId::new([1; 16])?;
    let anchor = crate::BootstrapKeyIdentity::from_parts([7; 16], [8; 32], 0)?;
    let context = session.system_context(instance, anchor)?;
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
    let mut ciphertext = vec![0x55; 29 + payload.as_provider_plaintext().len()];
    *ciphertext
        .first_mut()
        .ok_or(KeyProviderFailure::ContextMismatch)? = 1;
    let envelope = KeyEnvelope::from_provider_response(
        identity.clone(),
        context,
        WrappingAlgorithm::Aes256Gcm,
        ciphertext,
    )?;
    let governor = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let native_grant = governor.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let provider =
        Kmip21KeyProvider::from_native(identity.clone(), model(&root.path)?, native_grant)?;
    let grant = governor.reserve(crate::WorkClaim::system_security(
        NativeRootProvider::required_resources(),
    )?)?;
    let provider = NativeRootProvider::kmip(provider, grant)?;
    let custody = session
        .open_provider_system(
            provider,
            instance,
            anchor,
            2,
            &envelope.encode(),
            KeyCacheLease::default(),
        )
        .await?;
    let encrypted = custody.protect(
        instance,
        crate::BootstrapObjectPurpose::Initialized,
        b"provider-only recovery",
    )?;
    assert_eq!(custody.bootstrap_identity(), anchor);
    assert_eq!(custody.active_provider_identity()?, identity);
    assert_eq!(
        custody
            .open_object(
                instance,
                crate::BootstrapObjectPurpose::Initialized,
                &encrypted
            )?
            .as_slice(),
        b"provider-only recovery"
    );
    assert_eq!(server.await?.len(), 5);
    drop(custody);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}
#[tokio::test]
async fn runtime_provider_dispatch_preserves_native_exact_identity_probe()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let (port, server) = transcript_sequence(vec![discover(), metadata("immutable-id")]).await?;
    let governor = crate::data_protection::tests::providers::provider_governor(200_000_000)?;
    let native_grant = governor.reserve(crate::WorkClaim::system_maintenance(
        Kmip21KeyProvider::required_resources(),
    )?)?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let grant = governor.reserve(crate::WorkClaim::system_security(
        NativeRootProvider::required_resources(),
    )?)?;
    let provider = NativeRootProvider::from_configuration(
        NativeRootConfiguration::Kmip {
            identity: identity.clone(),
            credentials: model(&root.path)?,
        },
        native_grant,
        grant,
    )?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let outcome = tokio::task::spawn_blocking(move || provider.probe_blocking(context)).await?;
    assert_eq!(outcome?.identity, identity);
    assert_eq!(server.await?.len(), 2);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}
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

#[tokio::test]
async fn verified_native_migration_cutover_preserves_existing_objects()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let source_root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let authority =
        crate::data_protection::tests::providers::provider_governor_with_slots(400_000_000, 32)?
            .into_authority();
    let session = crate::RootRewrapSession::admit(&authority)
        .map_err(|e| format!("session admission: {e}"))?;
    let instance = crate::InstanceId::new([1; 16])?;
    let current = session
        .lease_system(
            crate::BootstrapKeyCustody::initialize(&source_root.path)?,
            instance,
            KeyCacheLease::default(),
        )
        .map_err(|e| format!("local lease: {e}"))?;
    let existing = current.protect(
        instance,
        crate::BootstrapObjectPurpose::Initialized,
        b"existing immutable object",
    )?;
    let (port, server) = transcript_connections(|port| {
        let identity = ProviderKeyUri::new(
            ProviderFamily::Kmip21,
            &format!("kmip://localhost:{port}/objects/immutable-id"),
            PIN,
        )
        .expect("identity");
        session
            .with_native_fixture_system_payload(&current, instance, &identity, |payload| {
                let encrypted = response(
                    0x1f,
                    0,
                    &[
                        field(0x420094, 7, b"immutable-id"),
                        field(0x4200c2, 8, &vec![0x55; payload.len()]),
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
                        field(0x4200c2, 8, payload),
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
            .expect("bound payload fixture")
    })
    .await?;
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!("kmip://localhost:{port}/objects/immutable-id"),
        PIN,
    )?;
    let provider = session
        .native_provider(NativeRootConfiguration::Kmip {
            identity: identity.clone(),
            credentials: model(&root.path)?,
        })
        .map_err(|e| format!("native setup: {e:?}"))?;
    let migration = session
        .prepare_provider_migration(&current, provider, instance, 2)
        .await
        .map_err(|e| format!("migration preflight: {e}"))?;
    assert_eq!(migration.target_identity(), &identity);
    let activation = migration.into_activation();
    activation.activate(&current)?;
    assert_eq!(current.active_provider_identity()?, identity);
    assert_eq!(
        current
            .open_object(
                instance,
                crate::BootstrapObjectPurpose::Initialized,
                &existing
            )?
            .as_slice(),
        b"existing immutable object"
    );
    assert_eq!(server.await?.len(), 10);
    Ok(())
}

#[tokio::test]
async fn native_migration_cache_admission_refuses_before_provider_io_and_preserves_source()
-> Result<(), Box<dyn std::error::Error>> {
    let credentials = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let source_root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
    let authority =
        crate::data_protection::tests::providers::provider_governor_with_slots(400_000_000, 32)?
            .into_authority();
    let session = crate::RootRewrapSession::admit_provider(&authority)?;
    let instance = crate::InstanceId::new([1; 16])?;
    let current = session.lease_system(
        crate::BootstrapKeyCustody::initialize(&source_root.path)?,
        instance,
        KeyCacheLease::default(),
    )?;
    let original = current.active_provider_identity()?;
    let baseline = authority.governor().inspect()?.outstanding_total();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let target = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        &format!(
            "kmip://localhost:{}/objects/immutable-id",
            listener.local_addr()?.port()
        ),
        PIN,
    )?;
    let provider = session.native_provider(NativeRootConfiguration::Kmip {
        identity: target,
        credentials: model(&credentials.path)?,
    })?;
    let mut holds = Vec::new();
    for _ in 0..32 {
        match authority
            .governor()
            .reserve(crate::WorkClaim::system_security(
                crate::ResourceAmounts::new([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            )?) {
            Ok(grant) => holds.push(grant),
            Err(failure) => {
                assert_eq!(
                    failure.code(),
                    crate::AdmissionFailureCode::OutstandingReservationLimit
                );
                break;
            },
        }
    }
    tokio::select! {
        result = session.prepare_provider_migration(&current, provider, instance, 2) => {
            assert!(matches!(result, Err(KeyProviderFailure::LimitExceeded)));
        },
        accepted = listener.accept() => {
            accepted?;
            panic!("provider I/O preceded cache admission");
        },
    }
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        baseline + u32::try_from(holds.len())?
    );
    assert_eq!(current.active_provider_identity()?, original);
    let object = current.protect(
        instance,
        crate::BootstrapObjectPurpose::Initialized,
        b"source remains usable",
    )?;
    assert_eq!(
        current
            .open_object(
                instance,
                crate::BootstrapObjectPurpose::Initialized,
                &object
            )?
            .as_slice(),
        b"source remains usable"
    );
    drop(holds);
    drop(current);
    drop(session);
    assert_eq!(authority.governor().inspect()?.outstanding_total(), 0);
    Ok(())
}
