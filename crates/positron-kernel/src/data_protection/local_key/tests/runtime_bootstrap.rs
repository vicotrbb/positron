use super::{
    BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity, BootstrapObjectPurpose,
};
use crate::{InstanceId, SegmentScope};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::test_support::SecurityRoot;

#[test]
fn bootstrap_envelopes_reject_empty_and_substituted_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let key = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([1; 16])?;
    let other = InstanceId::new([2; 16])?;

    assert_eq!(format!("{key:?}"), "BootstrapKeyCustody { <redacted> }");
    assert_eq!(
        key.protect(instance, BootstrapObjectPurpose::Pending, b""),
        Err(BootstrapKeyFailure::InvalidInput)
    );
    let encoded = key.protect(instance, BootstrapObjectPurpose::Pending, b"pending")?;
    for opened in [
        key.open_object(other, BootstrapObjectPurpose::Pending, &encoded),
        key.open_object(instance, BootstrapObjectPurpose::Claim, &encoded),
    ] {
        assert_eq!(opened, Err(BootstrapKeyFailure::Authentication));
    }
    assert_eq!(
        BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Claim, &encoded),
        Err(BootstrapKeyFailure::Authentication)
    );
    let mut bad_length = encoded.clone();
    bad_length[48] ^= 1;
    assert_eq!(
        key.open_object(instance, BootstrapObjectPurpose::Pending, &bad_length),
        Err(BootstrapKeyFailure::Authentication)
    );
    Ok(())
}

#[test]
fn bootstrap_identity_and_failure_diagnostics_are_closed() {
    assert_eq!(
        BootstrapKeyIdentity::from_parts([0; 16], [1; 32], 1),
        Err(BootstrapKeyFailure::InvalidInput)
    );
    assert_eq!(
        BootstrapKeyFailure::Authentication.to_string(),
        "instance bootstrap key operation failed"
    );
}

#[test]
fn opening_missing_local_custody_is_a_closed_failure() -> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    assert_eq!(
        BootstrapKeyCustody::open(&root.path).map(|_| ()),
        Err(BootstrapKeyFailure::Custody)
    );
    Ok(())
}

#[test]
fn tenant_kek_envelope_round_trips_only_for_its_bound_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let instance = InstanceId::new([0x51; 16])?;
    let other_instance = InstanceId::new([0x52; 16])?;
    let tenant = TenantId::from_bytes([0x53; 16])?;
    let other_tenant = TenantId::from_bytes([0x54; 16])?;
    let key = BootstrapKeyCustody::initialize(&root.path)?;
    let envelope = key.provision_tenant_key_envelope(instance, tenant, [0x55; 16], 7)?;
    let distinct = key.provision_tenant_key_envelope(instance, tenant, [0x56; 16], 7)?;
    assert_ne!(
        envelope, distinct,
        "fresh tenant KEK provisions are opaque and distinct"
    );
    let opened = key.resolve_tenant_key_envelope(instance, tenant, &envelope)?;
    drop(key);

    let reopened = BootstrapKeyCustody::open(&root.path)?;
    let recovered = reopened.resolve_tenant_key_envelope(instance, tenant, &envelope)?;
    assert_eq!(opened.expose_to_backend(), recovered.expose_to_backend());
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(other_instance, tenant, &envelope),
        Err(BootstrapKeyFailure::Authentication)
    ));
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(instance, other_tenant, &envelope),
        Err(BootstrapKeyFailure::Authentication)
    ));
    let mut substituted_epoch = envelope.clone();
    substituted_epoch[31] ^= 1;
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(instance, tenant, &substituted_epoch),
        Err(BootstrapKeyFailure::Authentication)
    ));
    let mut substituted_key_id = envelope.clone();
    substituted_key_id[23] ^= 1;
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(instance, tenant, &substituted_key_id),
        Err(BootstrapKeyFailure::Authentication)
    ));
    Ok(())
}

#[test]
fn released_tenant_envelope_remains_authenticated_for_segment_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let instance = InstanceId::new([0x57; 16])?;
    let tenant = TenantId::from_bytes([0x58; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let key = BootstrapKeyCustody::initialize(&root.path)?;
    let envelope = key.tenant_key_envelope(instance, tenant)?;
    assert!(
        key.segment_key_from_tenant_envelope(instance, scope, &envelope)
            .is_ok(),
        "the released authenticated envelope must remain a supported format"
    );
    let mut corrupt = envelope.clone();
    corrupt[0] ^= 1;
    assert!(matches!(
        key.segment_key_from_tenant_envelope(instance, scope, &corrupt),
        Err(BootstrapKeyFailure::Authentication)
    ));
    drop(key);

    let reopened = BootstrapKeyCustody::open(&root.path)?;
    assert!(
        reopened
            .segment_key_from_tenant_envelope(instance, scope, &envelope)
            .is_ok(),
        "reopening custody must preserve released tenant envelope access"
    );
    Ok(())
}

#[test]
fn successor_root_recovers_existing_bootstrap_and_tenant_envelopes()
-> Result<(), Box<dyn std::error::Error>> {
    let original_root = SecurityRoot::create()?;
    let successor_root = SecurityRoot::create()?;
    let original = BootstrapKeyCustody::initialize(&original_root.path)?;
    let successor = BootstrapKeyCustody::initialize(&successor_root.path)?;
    let instance = InstanceId::new([0x61; 16])?;
    let tenant = TenantId::from_bytes([0x62; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let bootstrap = original.protect(
        instance,
        BootstrapObjectPurpose::Initialized,
        b"existing bootstrap",
    )?;
    let tenant_envelope =
        original.provision_tenant_key_envelope(instance, tenant, [0x63; 16], 1)?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = super::RootRewrapSession::admit(&authority)?;
    let envelope = session.wrap_system(&original, &successor, instance, 2)?;
    let anchor = original.identity();
    let active = successor.identity();
    drop(original);
    drop(successor);
    let successor = BootstrapKeyCustody::open(&successor_root.path)?;
    let recovered = session.open_system(successor, instance, anchor, 2, &envelope)?;
    assert_eq!(recovered.identity(), active);
    assert_eq!(recovered.bootstrap_identity(), anchor);
    assert_eq!(
        recovered
            .open_object(instance, BootstrapObjectPurpose::Initialized, &bootstrap)?
            .as_slice(),
        b"existing bootstrap"
    );
    assert!(
        recovered
            .segment_key_from_tenant_envelope(instance, scope, &tenant_envelope)
            .is_ok()
    );
    let wrong_instance = InstanceId::new([0x64; 16])?;
    assert!(
        session
            .open_system(
                BootstrapKeyCustody::open(&successor_root.path)?,
                wrong_instance,
                anchor,
                2,
                &envelope
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn live_successor_activation_preserves_hierarchy_and_replaces_provider_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let original_root = SecurityRoot::create()?;
    let successor_root = SecurityRoot::create()?;
    let original = BootstrapKeyCustody::initialize(&original_root.path)?;
    let successor = BootstrapKeyCustody::initialize(&successor_root.path)?;
    let anchor = original.identity();
    let active = successor.identity();
    let instance = InstanceId::new([0x71; 16])?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = super::RootRewrapSession::admit(&authority)?;
    let envelope = session.wrap_system(&original, &successor, instance, 2)?;
    let original = session.lease_system(
        original,
        instance,
        crate::key_provider::KeyCacheLease::default(),
    )?;
    let bootstrap = original.protect(
        instance,
        BootstrapObjectPurpose::Initialized,
        b"stable hierarchy",
    )?;
    let activation = session.prepare_activation(&original, successor, instance, 2, &envelope)?;
    let stale = session.prepare_activation(
        &original,
        BootstrapKeyCustody::open(&successor_root.path)?,
        instance,
        2,
        &envelope,
    )?;
    assert_eq!(original.active_root_identity()?, anchor);
    activation.activate(&original)?;
    assert_eq!(
        stale.activate(&original),
        Err(super::BootstrapKeyFailure::Authentication)
    );
    assert_eq!(original.active_root_identity()?, active);
    assert_eq!(original.active_root_epoch()?, 2);
    assert_eq!(original.bootstrap_identity(), anchor);
    assert!(original.provider_health()?.system_ready);
    assert_eq!(
        original
            .open_object(instance, BootstrapObjectPurpose::Initialized, &bootstrap)?
            .as_slice(),
        b"stable hierarchy"
    );
    let protected = original.protect_instance_integrity_key(instance, &[0x72; 32])?;
    let integrity = original.integrity_identity(&[0x72; 32])?;
    let recipient = age::x25519::Identity::generate();
    let recovery =
        super::RecoverySession::admit(&authority, super::RecoveryProtection::Recipients)?;
    let pin = super::RecoveryIdentity::new(instance, active, integrity)?;
    let bundle = recovery.create(
        &original,
        pin,
        &protected,
        &super::RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
        123,
    )?;
    recovery.verify(
        &original,
        &bundle,
        super::RecoveryUnlock::Identity(&recipient),
        pin,
    )?;
    Ok(())
}

#[test]
fn protected_successor_publication_retry_reuses_complete_key_without_entropy()
-> Result<(), Box<dyn std::error::Error>> {
    use super::initialization_io::{InitializationFault, with_initialization_fault};
    for fault in [
        InitializationFault::SynchronizeKeyFile,
        InitializationFault::SynchronizeSecurityDirectory,
    ] {
        let data = SecurityRoot::create()?;
        let secrets = SecurityRoot::create()?;
        let original = BootstrapKeyCustody::initialize(&secrets.path)?;
        let original_identity = original.identity();
        let storage = crate::InstanceBootstrapStorage::new(
            &data.path,
            &secrets.path,
            crate::MountQualification::LocalHost,
        )
        .map_err(|_| "fixture storage")?;
        let access = storage.inspect().map_err(|_| "fixture access")?;
        let authority = crate::data_protection::recovery_tests::authority()?;
        let session = super::RootRewrapSession::admit(&authority)?;
        assert!(
            with_initialization_fault(fault, || session.prepare_successor(&access, 2)).is_err()
        );
        let resumed = with_initialization_fault(InitializationFault::Entropy, || {
            session.prepare_successor(&access, 2)
        })?;
        let identity = resumed.identity();
        assert_ne!(identity, original_identity);
        assert_eq!(
            with_initialization_fault(InitializationFault::Entropy, || session
                .prepare_successor(&access, 2))?
            .identity(),
            identity
        );
        assert_eq!(session.open_successor(&access, 2)?.identity(), identity);
        assert_eq!(access.open_key()?.identity(), original_identity);
    }
    Ok(())
}

#[test]
fn successor_recovery_bundle_restores_the_original_system_hierarchy()
-> Result<(), Box<dyn std::error::Error>> {
    let original_root = SecurityRoot::create()?;
    let successor_root = SecurityRoot::create()?;
    let recovered_root = SecurityRoot::create()?;
    let data = SecurityRoot::create()?;
    let original = BootstrapKeyCustody::initialize(&original_root.path)?;
    let successor = BootstrapKeyCustody::initialize(&successor_root.path)?;
    let instance = InstanceId::new([0x71; 16])?;
    let protected = original.protect_instance_integrity_key(instance, &[0x72; 32])?;
    let object = original.protect(
        instance,
        BootstrapObjectPurpose::Initialized,
        b"acknowledged pre-rotation metadata",
    )?;
    let integrity = original.integrity_identity(&[0x72; 32])?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let rewrap = super::RootRewrapSession::admit(&authority)?;
    let envelope = rewrap.wrap_system(&original, &successor, instance, 2)?;
    let successor = rewrap.open_system(successor, instance, original.identity(), 2, &envelope)?;
    let pin = super::RecoveryIdentity::new(instance, successor.identity(), integrity)?;
    let recipient = age::x25519::Identity::generate();
    let recovery =
        super::RecoverySession::admit(&authority, super::RecoveryProtection::Recipients)?;
    let bundle = recovery
        .create(
            &successor,
            pin,
            &protected,
            &super::RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
            456,
        )
        .map_err(|failure| format!("bundle creation: {failure:?}"))?;
    let original_data = SecurityRoot::create()?;
    let original_storage = crate::InstanceBootstrapStorage::new(
        &original_data.path,
        &original_root.path,
        crate::MountQualification::LocalHost,
    )
    .map_err(|_| "original fixture storage")?;
    let original_access = original_storage
        .inspect()
        .map_err(|_| "original fixture access")?;
    let retained_original = recovery.import(
        &bundle,
        super::RecoveryUnlock::Identity(&recipient),
        pin,
        &original_access,
        |_| Ok(()),
    )?;
    assert_eq!(retained_original.root_epoch(), 2);
    assert_eq!(retained_original.identity(), successor.identity());
    assert_eq!(
        original_access.open_successor_key(2)?.identity(),
        retained_original.identity()
    );
    let still_original = BootstrapKeyCustody::open(&original_root.path)?;
    assert_eq!(still_original.identity(), original.identity());
    assert!(
        still_original
            .open_object(instance, BootstrapObjectPurpose::Initialized, &object)
            .is_ok(),
        "successor import preserves original custody and bootstrap authority"
    );
    assert!(
        retained_original
            .open_object(instance, BootstrapObjectPurpose::Initialized, &object)
            .is_ok(),
        "imported successor opens original bootstrap ciphertext"
    );
    let storage = crate::InstanceBootstrapStorage::new(
        &data.path,
        &recovered_root.path,
        crate::MountQualification::LocalHost,
    )
    .map_err(|_| "fixture storage")?;
    let access = storage.inspect().map_err(|_| "fixture access")?;
    drop(original);
    drop(successor);
    let restored = recovery
        .import(
            &bundle,
            super::RecoveryUnlock::Identity(&recipient),
            pin,
            &access,
            |custody| {
                custody
                    .open_object(instance, BootstrapObjectPurpose::Initialized, &object)
                    .map(|_| ())
                    .map_err(|_| super::RecoveryFailure::Authentication)
            },
        )
        .map_err(|failure| format!("bundle import: {failure:?}"))?;
    assert_eq!(
        restored
            .open_object(instance, BootstrapObjectPurpose::Initialized, &object)?
            .as_slice(),
        b"acknowledged pre-rotation metadata"
    );
    let anchor = restored.bootstrap_identity();
    drop(restored);
    let reopened = access.open_key()?;
    assert_eq!(reopened.bootstrap_identity(), anchor);
    assert_eq!(
        reopened
            .open_object(instance, BootstrapObjectPurpose::Initialized, &object)?
            .as_slice(),
        b"acknowledged pre-rotation metadata"
    );
    Ok(())
}

#[test]
fn interrupted_successor_recovery_publishes_only_complete_routes_and_resumes()
-> Result<(), Box<dyn std::error::Error>> {
    use super::initialization_io::{InitializationFault, with_initialization_fault};
    for fault in [
        InitializationFault::PartialWrite(17),
        InitializationFault::SynchronizeKeyFile,
        InitializationFault::SynchronizeSecurityDirectory,
    ] {
        let original_root = SecurityRoot::create()?;
        let successor_root = SecurityRoot::create()?;
        let target = SecurityRoot::create()?;
        let data = SecurityRoot::create()?;
        let original = BootstrapKeyCustody::initialize(&original_root.path)?;
        let successor = BootstrapKeyCustody::initialize(&successor_root.path)?;
        let instance = InstanceId::new([0x75; 16])?;
        let protected = original.protect_instance_integrity_key(instance, &[0x76; 32])?;
        let object = original.protect(
            instance,
            BootstrapObjectPurpose::Initialized,
            b"durable existing object",
        )?;
        let authority = crate::data_protection::recovery_tests::authority()?;
        let rewrap = super::RootRewrapSession::admit(&authority)?;
        let envelope = rewrap.wrap_system(&original, &successor, instance, 2)?;
        let successor =
            rewrap.open_system(successor, instance, original.identity(), 2, &envelope)?;
        let pin = super::RecoveryIdentity::new(
            instance,
            successor.identity(),
            original.integrity_identity(&[0x76; 32])?,
        )?;
        let recipient = age::x25519::Identity::generate();
        let recovery =
            super::RecoverySession::admit(&authority, super::RecoveryProtection::Recipients)?;
        let bundle = recovery.create(
            &successor,
            pin,
            &protected,
            &super::RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
            456,
        )?;
        let storage = crate::InstanceBootstrapStorage::new(
            &data.path,
            &target.path,
            crate::MountQualification::LocalHost,
        )
        .map_err(|_| "fixture storage")?;
        let access = storage.inspect().map_err(|_| "fixture access")?;
        let import = || {
            recovery.import(
                &bundle,
                super::RecoveryUnlock::Identity(&recipient),
                pin,
                &access,
                |key| {
                    key.open_object(instance, BootstrapObjectPurpose::Initialized, &object)
                        .map(|_| ())
                        .map_err(|_| super::RecoveryFailure::Authentication)
                },
            )
        };
        assert!(with_initialization_fault(fault, import).is_err());
        assert!(
            access.open_key().is_err(),
            "failed bridge publication cannot install root custody"
        );
        import()?;
        assert_eq!(
            access
                .open_key()?
                .open_object(instance, BootstrapObjectPurpose::Initialized, &object)?
                .as_slice(),
            b"durable existing object"
        );
    }
    Ok(())
}

#[test]
fn successor_routes_reject_wrong_epoch_identity_and_corrupted_payloads()
-> Result<(), Box<dyn std::error::Error>> {
    let original_root = SecurityRoot::create()?;
    let successor_root = SecurityRoot::create()?;
    let wrong_root = SecurityRoot::create()?;
    let original = BootstrapKeyCustody::initialize(&original_root.path)?;
    let successor = BootstrapKeyCustody::initialize(&successor_root.path)?;
    let wrong = BootstrapKeyCustody::initialize(&wrong_root.path)?;
    let instance = InstanceId::new([0x79; 16])?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = super::RootRewrapSession::admit(&authority)?;
    let envelope = session.wrap_system(&original, &successor, instance, 2)?;
    let anchor = original.identity();
    assert!(
        session
            .open_system(wrong, instance, anchor, 2, &envelope)
            .is_err()
    );
    assert!(
        session
            .open_system(
                BootstrapKeyCustody::open(&successor_root.path)?,
                instance,
                anchor,
                3,
                &envelope
            )
            .is_err()
    );
    let wrong_anchor = BootstrapKeyIdentity::from_parts([0x7a; 16], [0x7b; 32], 123)?;
    assert!(
        session
            .open_system(
                BootstrapKeyCustody::open(&successor_root.path)?,
                instance,
                wrong_anchor,
                2,
                &envelope
            )
            .is_err()
    );
    let mut corrupted = envelope.clone();
    if let Some(last) = corrupted.last_mut() {
        *last ^= 1;
    }
    for rejected in [
        corrupted.as_slice(),
        &envelope[..envelope.len() - 1],
        &[],
        &[0; 1025],
    ] {
        assert!(
            session
                .open_system(
                    BootstrapKeyCustody::open(&successor_root.path)?,
                    instance,
                    anchor,
                    2,
                    rejected
                )
                .is_err()
        );
    }
    assert!(
        session
            .wrap_system(&original, &successor, instance, 0)
            .is_err()
    );
    assert!(
        original
            .protect(
                instance,
                BootstrapObjectPurpose::Initialized,
                b"original custody remains usable"
            )
            .is_ok()
    );
    assert!(
        successor
            .protect(
                instance,
                BootstrapObjectPurpose::Initialized,
                b"successor custody remains unchanged"
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn canonical_successor_system_envelope_enters_the_owned_provider_cache()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::data_protection::key_provider::{
        CacheInvalidation, KeyCacheLease, KeyEnvelope, KeyProviderCache, KeyScope, LocalKeyProvider,
    };
    let source_root = SecurityRoot::create()?;
    let destination_root = SecurityRoot::create()?;
    let source = BootstrapKeyCustody::initialize(&source_root.path)?;
    let destination = BootstrapKeyCustody::initialize(&destination_root.path)?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = super::RootRewrapSession::admit(&authority)?;
    let instance = InstanceId::new([0x7c; 16])?;
    let encoded = session.wrap_system(&source, &destination, instance, 2)?;
    let context = session.system_context(instance, source.identity())?;
    let destination = session.open_system(destination, instance, source.identity(), 2, &encoded)?;
    let provider = LocalKeyProvider::from_custody(destination)?;
    let memory = KeyProviderCache::<LocalKeyProvider>::required_memory_bytes(1)?;
    let amounts =
        crate::ResourceAmounts::new(crate::ResourceDimension::ALL.map(
            |dimension| match dimension {
                crate::ResourceDimension::MemoryBytes => memory,
                crate::ResourceDimension::LeaseSlots => 1,
                _ => 0,
            },
        ));
    let reservation = authority
        .governor()
        .reserve(crate::WorkClaim::system_security(amounts)?)?;
    let mut cache: KeyProviderCache<'static, LocalKeyProvider> =
        KeyProviderCache::from_owned(provider, KeyCacheLease::default(), 1, reservation)?;
    let envelope = KeyEnvelope::decode(&encoded)?;
    {
        let mut future = std::pin::pin!(cache.load(&envelope, context));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        match std::future::Future::poll(future.as_mut(), &mut task) {
            std::task::Poll::Ready(outcome) => outcome?,
            std::task::Poll::Pending => return Err("native local provider deferred".into()),
        }
    }
    assert_eq!(cache.resident_keys(), 1);
    assert!(cache.health().system_ready);
    cache.invalidate(KeyScope::System, CacheInvalidation::Rotation);
    assert_eq!(cache.resident_keys(), 0);
    assert!(!cache.health().system_ready);
    Ok(())
}

#[test]
fn local_provider_custody_transfer_releases_the_uncached_system_secret()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::data_protection::{SecretKeyBytes, key_provider::LocalKeyProvider};
    use std::{cell::Cell, rc::Rc};
    let root = SecurityRoot::create()?;
    let mut custody = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([0x7d; 16])?;
    let anchor = custody.identity();
    let system = custody.system_kek(instance)?;
    let released = Rc::new(Cell::new(false));
    custody.system = Some((
        instance,
        SecretKeyBytes::from_owned_with_observer(
            Box::new(*system.expose_to_backend()),
            Rc::clone(&released),
        ),
        anchor,
    ));
    drop(system);
    let provider = LocalKeyProvider::from_custody(custody)?;
    assert!(
        released.get(),
        "provider must release uncached system custody after zeroization"
    );
    drop(provider);
    Ok(())
}

#[test]
fn leased_bootstrap_custody_preserves_child_access_and_independent_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::data_protection::key_provider::KeyCacheLease;
    for lease in [
        KeyCacheLease::default(),
        KeyCacheLease::new(std::time::Duration::ZERO)?,
    ] {
        let root = SecurityRoot::create()?;
        let custody = BootstrapKeyCustody::initialize(&root.path)?;
        let identity = custody.identity();
        let instance = InstanceId::new([0x7e; 16])?;
        let protected = custody.protect_instance_integrity_key(instance, &[0x7f; 32])?;
        let integrity = custody.integrity_identity(&[0x7f; 32])?;
        let before = custody.protect(
            instance,
            BootstrapObjectPurpose::Initialized,
            b"leased hierarchy",
        )?;
        let authority = crate::data_protection::recovery_tests::authority()?;
        let session = super::RootRewrapSession::admit(&authority)?;
        let custody = session.lease_system(custody, instance, lease)?;
        assert_eq!(custody.identity(), identity);
        assert_eq!(custody.bootstrap_identity(), identity);
        assert_eq!(
            custody
                .open_object(instance, BootstrapObjectPurpose::Initialized, &before)?
                .as_slice(),
            b"leased hierarchy"
        );
        let after = custody.protect(
            instance,
            BootstrapObjectPurpose::Initialized,
            b"fresh leased hierarchy",
        )?;
        assert_eq!(
            custody
                .open_object(instance, BootstrapObjectPurpose::Initialized, &after)?
                .as_slice(),
            b"fresh leased hierarchy"
        );
        let recipient = age::x25519::Identity::generate();
        let recovery =
            super::RecoverySession::admit(&authority, super::RecoveryProtection::Recipients)?;
        let pin = super::RecoveryIdentity::new(instance, identity, integrity)?;
        let bundle = recovery.create(
            &custody,
            pin,
            &protected,
            &super::RecoveryRecipients::parse(&[recipient.to_public().to_string()])?,
            789,
        )?;
        recovery.verify(
            &custody,
            &bundle,
            super::RecoveryUnlock::Identity(&recipient),
            pin,
        )?;
        assert_eq!(
            recovery
                .inspect(&bundle, super::RecoveryUnlock::Identity(&recipient), pin)?
                .payload_version(),
            2
        );
    }
    Ok(())
}

#[test]
fn tenant_epoch_set_advances_only_verified_context_and_retains_predecessor()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let key = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([0xd1; 16])?;
    let tenant = TenantId::from_bytes([0xd2; 16])?;
    let other = TenantId::from_bytes([0xd3; 16])?;
    let authority = crate::data_protection::recovery_tests::authority()?;
    let session = super::RootRewrapSession::admit(&authority)?;
    let first = key.provision_tenant_key_envelope(instance, tenant, [0xd4; 16], 1)?;
    let prepared = session.prepare_tenant_envelope(&key, instance, tenant, &first)?;
    assert_eq!(key.tenant_key_epoch(instance, tenant, &prepared)?, 1);
    assert_eq!(
        key.pending_tenant_key_epoch(instance, tenant, &prepared)?,
        Some(2)
    );
    assert_eq!(
        session.prepare_tenant_envelope(&key, instance, tenant, &prepared)?,
        prepared
    );
    let successor = session.activate_tenant_envelope(&key, instance, tenant, &prepared)?;
    assert_eq!(key.tenant_key_epoch(instance, tenant, &successor)?, 2);
    assert_eq!(
        key.tenant_key_epoch(instance, other, &successor),
        Err(BootstrapKeyFailure::Authentication)
    );
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    assert!(
        key.segment_key_from_tenant_envelope(instance, scope, &successor)
            .is_ok()
    );
    let mut corrupt = successor.clone();
    let last = corrupt.last_mut().ok_or("missing successor envelope")?;
    *last ^= 1;
    assert_eq!(
        key.tenant_key_epoch(instance, tenant, &corrupt),
        Err(BootstrapKeyFailure::Authentication)
    );
    assert!(
        session
            .prepare_tenant_envelope(&key, instance, tenant, &corrupt)
            .is_err()
    );
    assert_eq!(key.tenant_key_epoch(instance, tenant, &successor)?, 2);
    let prepared = session.prepare_tenant_envelope(&key, instance, tenant, &successor)?;
    let third = session.activate_tenant_envelope(&key, instance, tenant, &prepared)?;
    assert_eq!(key.tenant_key_epoch(instance, tenant, &third)?, 3);
    Ok(())
}

#[test]
fn tenant_key_capability_keeps_transferred_capacity_after_operation_and_releases_on_drop()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::ResourceDimension;
    let root = SecurityRoot::create()?;
    let key = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let tenant = TenantId::from_bytes([0xe2; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let authority = crate::data_protection::recovery_tests::authority()?;
    let before = authority.governor().inspect()?;
    let session = super::RootRewrapSession::admit(&authority)?;
    let first = key.provision_tenant_key_envelope(instance, tenant, [0xe3; 16], 1)?;
    let pending = session.prepare_tenant_envelope(&key, instance, tenant, &first)?;
    let successor = session.activate_tenant_envelope(&key, instance, tenant, &pending)?;
    let capability = session.tenant_segment_key(&key, instance, scope, &successor)?;
    drop(session);
    let retained = authority.governor().inspect()?;
    assert_eq!(
        retained.usage(ResourceDimension::MemoryBytes),
        before.usage(ResourceDimension::MemoryBytes) + 2048
    );
    assert_eq!(
        retained.usage(ResourceDimension::LeaseSlots),
        before.usage(ResourceDimension::LeaseSlots) + 1
    );
    drop(capability);
    let released = authority.governor().inspect()?;
    assert_eq!(
        released.usage(ResourceDimension::MemoryBytes),
        before.usage(ResourceDimension::MemoryBytes)
    );
    assert_eq!(
        released.usage(ResourceDimension::LeaseSlots),
        before.usage(ResourceDimension::LeaseSlots)
    );
    Ok(())
}
