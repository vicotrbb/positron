//! Successor import preserves authenticated epoch custody and rotation authority.
use super::super::*;
use super::support::Roots;
use std::os::unix::fs::PermissionsExt;

#[test]
fn successor_import_rejects_unknown_rotation_transaction_before_custody_or_audit_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{
        Catalog, CatalogObject, CatalogProposal, RootRewrapSession, TransactionId,
    };
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    initialized.begin_local_key_rotation()?;
    initialized.activate_local_key_rotation()?;
    let directory = roots.parent().join("recovery");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    let unlock = age::x25519::Identity::generate();
    let bundle = directory.join("successor.age");
    initialized.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let pin = initialized.recovery_identity()?;
    let instance_id = initialized.instance_id();
    let session = RootRewrapSession::admit(&initialized._authority)?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance_id(),
        session.rotation_catalog_secret(&initialized.key, initialized.instance_id())?,
    )?;
    let basis = catalog.pin()?;
    let _copy = catalog.reserve_catalog_proposal_copy(&basis)?;
    let mut objects = Vec::new();
    for identity in basis.object_identities() {
        let mut bytes = basis
            .object(identity)?
            .ok_or("authenticated object")?
            .to_vec();
        if bytes.starts_with(b"POSLROT1") {
            bytes
                .get_mut(24..40)
                .ok_or("rotation transaction")?
                .copy_from_slice(&[0x7b; 16]);
        }
        objects.push(CatalogObject::new(bytes)?);
    }
    let committed = catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x7c; 16])?,
            basis.format_epoch().ok_or("format")?,
            objects,
        )?,
        None,
    )?;
    let before = committed.identity();
    let audit_count = catalog.governance_audit_records()?.len();
    drop(_copy);
    drop(catalog);
    drop(session);
    let active = roots.parent().join("secrets/local-root-key.epoch-2.v1");
    std::fs::remove_file(&active)?;
    drop(initialized);
    assert!(
        InstanceBootstrap::import_recovery_bundle(
            &paths,
            &bundle,
            pin,
            positron_kernel::RecoveryUnlock::Identity(&unlock)
        )
        .is_err()
    );
    assert!(
        !active.exists(),
        "rejected transaction cannot publish recovered custody"
    );
    let (volume, access) = paths
        .storage
        .acquire()
        .map_err(|_| "exclusive fixture storage")?;
    let authority = super::super::resources::establish_system_diagnostics(
        volume,
        super::super::DEFAULT_MAX_REGISTERED_TENANTS,
    )?;
    let session = RootRewrapSession::admit(&authority)?;
    let custody = access.open_key()?;
    let catalog = Catalog::open(
        &authority,
        instance_id,
        session.rotation_catalog_secret(&custody, instance_id)?,
    )?;
    assert_eq!(catalog.pin()?.identity(), before);
    assert_eq!(catalog.governance_audit_records()?.len(), audit_count);
    Ok(())
}

#[test]
fn successor_recovery_import_preserves_epoch_custody_and_allows_subsequent_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    successor_recovery_lifecycle(false)
}

#[test]
fn successor_recovery_import_retains_original_custody_until_authenticated_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    successor_recovery_lifecycle(true)
}

fn successor_recovery_lifecycle(keep_original: bool) -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let instance = initialized.instance_id();
    let anchor = initialized.key.bootstrap_identity();
    let recovery = roots.parent().join("recovery");
    std::fs::create_dir(&recovery)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700))?;
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let first = recovery.join("epoch-1.age");
    initialized
        .create_recovery_bundle(&first, &recipients)
        .map_err(|error| format!("create epoch 1 recovery: {error:?}"))?;
    initialized
        .verify_recovery_bundle(&first, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    initialized.begin_local_key_rotation()?;
    initialized.activate_local_key_rotation()?;
    assert!(initialized.retire_local_key_predecessor().is_err());
    let second = recovery.join("epoch-2.age");
    initialized.create_recovery_bundle(&second, &recipients)?;
    initialized
        .verify_recovery_bundle(&second, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    assert!(
        initialized.retire_local_key_predecessor().is_err(),
        "old recovery reference remains managed"
    );
    initialized.retire_recovery_predecessor()?;
    if !keep_original {
        initialized.retire_local_key_predecessor()?;
    }
    assert_eq!(
        roots.parent().join("secrets/local-root-key.v1").exists(),
        keep_original
    );
    assert!(!first.exists());
    if !keep_original {
        initialized.retire_local_key_predecessor()?;
    }
    let pin = initialized.recovery_identity()?;
    drop(initialized);
    std::fs::remove_file(roots.parent().join("secrets/local-root-key.epoch-2.v1"))?;
    let recovered = InstanceBootstrap::import_recovery_bundle(
        &paths,
        &second,
        pin,
        positron_kernel::RecoveryUnlock::Identity(&unlock),
    )?;
    assert!(
        roots
            .parent()
            .join("secrets/local-root-key.epoch-2.v1")
            .exists()
    );
    assert_eq!(
        roots.parent().join("secrets/local-root-key.v1").exists(),
        keep_original
    );
    assert_eq!(recovered.recovery_identity()?, pin);
    if keep_original {
        recovered.retire_local_key_predecessor()?;
    }
    assert!(!roots.parent().join("secrets/local-root-key.v1").exists());
    drop(recovered);
    let initialized = InstanceBootstrap::reopen(&paths)
        .map_err(|error| format!("reopen after root 2 retirement: {error:?}"))?;
    assert_eq!(initialized.instance_id(), instance);
    assert_eq!(initialized.key.bootstrap_identity(), anchor);
    assert_eq!(initialized.local_key_rotation_status()?.active_epoch(), 2);
    assert_eq!(
        initialized.local_key_rotation_status()?.predecessor_epoch(),
        None
    );
    assert_eq!(
        initialized.begin_local_key_rotation()?.successor_epoch(),
        Some(3)
    );
    initialized.activate_local_key_rotation()?;
    let third = recovery.join("epoch-3.age");
    initialized.create_recovery_bundle(&third, &recipients)?;
    initialized
        .verify_recovery_bundle(&third, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    initialized.retire_recovery_predecessor()?;
    initialized.retire_local_key_predecessor()?;
    assert!(
        !roots
            .parent()
            .join("secrets/local-root-key.epoch-2.v1")
            .exists()
    );
    drop(initialized);
    let initialized = InstanceBootstrap::reopen(&paths)
        .map_err(|error| format!("reopen after root 3 retirement: {error:?}"))?;
    assert_eq!(initialized.instance_id(), instance);
    assert_eq!(initialized.key.bootstrap_identity(), anchor);
    assert_eq!(initialized.local_key_rotation_status()?.active_epoch(), 3);
    assert_eq!(
        initialized.backup_key_recovery_readiness()?,
        RecoveryReadiness::Verified
    );
    Ok(())
}

#[test]
fn successor_import_faults_preserve_exact_staging_and_original_custody()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{
        RecoveryRecipients, RecoveryUnlock, RootCustodyPublicationFault, RootRewrapSession,
    };
    for fault in [
        RootCustodyPublicationFault::RouteFileSync,
        RootCustodyPublicationFault::RoutePartialWrite,
        RootCustodyPublicationFault::PredecessorDirectorySync,
    ] {
        let roots = Roots::new()?;
        let paths = roots.paths();
        let instance =
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        instance.begin_local_key_rotation()?;
        instance.activate_local_key_rotation()?;
        let directory = roots.parent().join("recovery");
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let unlock = age::x25519::Identity::generate();
        let bundle = directory.join("successor.age");
        instance.create_recovery_bundle(
            &bundle,
            &RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
        )?;
        instance.verify_recovery_bundle(&bundle, RecoveryUnlock::Identity(&unlock))?;
        let pin = instance.recovery_identity()?;
        drop(instance);
        let target = roots.parent().join("secrets/local-root-key.epoch-2.v1");
        let staged = roots.parent().join("secrets/local-root-key.epoch-2.v1.new");
        std::fs::remove_file(&target)?;
        assert!(
            RootRewrapSession::with_custody_publication_fault(fault, || {
                InstanceBootstrap::import_recovery_bundle(
                    &paths,
                    &bundle,
                    pin,
                    RecoveryUnlock::Identity(&unlock),
                )
            })
            .is_err()
        );
        assert!(!target.exists());
        assert!(roots.parent().join("secrets/local-root-key.v1").exists());
        if matches!(fault, RootCustodyPublicationFault::RoutePartialWrite) {
            assert_eq!(std::fs::metadata(&staged)?.len(), 5);
            for _ in 0..2 {
                assert!(
                    InstanceBootstrap::import_recovery_bundle(
                        &paths,
                        &bundle,
                        pin,
                        RecoveryUnlock::Identity(&unlock)
                    )
                    .is_err()
                );
                assert_eq!(std::fs::metadata(&staged)?.len(), 5);
                assert!(!target.exists());
            }
        } else {
            let restored = InstanceBootstrap::import_recovery_bundle(
                &paths,
                &bundle,
                pin,
                RecoveryUnlock::Identity(&unlock),
            )?;
            assert_eq!(restored.recovery_identity()?, pin);
            assert_eq!(restored.local_key_rotation_status()?.active_epoch(), 2);
            assert!(target.exists());
            assert!(!staged.exists());
        }
    }
    Ok(())
}

#[test]
fn successor_import_rejects_existing_custody_and_foreign_or_corrupt_routes_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{RecoveryRecipients, RecoveryUnlock, RootRewrapSession};
    for case in 0..9 {
        let roots = Roots::new()?;
        let paths = roots.paths();
        let instance =
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        instance.begin_local_key_rotation()?;
        instance.activate_local_key_rotation()?;
        let directory = roots.parent().join("recovery");
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let unlock = age::x25519::Identity::generate();
        let bundle = directory.join("successor.age");
        instance.create_recovery_bundle(
            &bundle,
            &RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
        )?;
        instance.verify_recovery_bundle(&bundle, RecoveryUnlock::Identity(&unlock))?;
        let pin = instance.recovery_identity()?;
        let (catalog_identity, wrapped_length) = {
            let session = RootRewrapSession::admit(&instance._authority)?;
            let secret = session.rotation_catalog_secret(&instance.key, instance.instance_id())?;
            let catalog = positron_kernel::Catalog::open(
                &instance._authority,
                instance.instance_id(),
                secret,
            )?;
            let basis = catalog.pin()?;
            (
                basis.identity(),
                session
                    .wrap_system(&instance.key, &instance.key, instance.instance_id(), 2)?
                    .len(),
            )
        };
        drop(instance);
        let target = roots.parent().join("secrets/local-root-key.epoch-2.v1");
        let original = roots.parent().join("secrets/local-root-key.v1");
        let saved_target = directory.join("local-root-key.saved-successor.v1");
        let saved_original = directory.join("local-root-key.saved-original.v1");
        let route = roots
            .parent()
            .join("data/.positron-system-key-envelopes.v1");
        let original_route = std::fs::read(&route)?; // ciphertext only
        if case != 3 {
            std::fs::rename(&target, &saved_target)?;
        }
        if case < 3 {
            std::fs::rename(&original, &saved_original)?;
            match case {
                0 => {
                    std::fs::write(&original, b"corrupt custody")?;
                    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600))?;
                },
                1 => {
                    let foreign = Roots::new()?;
                    drop(InstanceBootstrap::initialize(
                        &foreign.paths(),
                        InitializationPlan::non_interactive(),
                    )?);
                    std::fs::rename(
                        foreign.parent().join("secrets/local-root-key.v1"),
                        &original,
                    )?;
                },
                2 => std::os::unix::fs::symlink(&saved_target, &original)?,
                _ => unreachable!("bounded fixture"),
            }
        }
        if case >= 4 {
            let mut corrupted = original_route.clone();
            match case {
                4 => *corrupted.get_mut(8).ok_or("instance byte")? ^= 1,
                5 => *corrupted.get_mut(24).ok_or("anchor byte")? ^= 1,
                6 => {
                    let offset = corrupted
                        .len()
                        .checked_sub(wrapped_length + 5)
                        .ok_or("epoch offset")?;
                    *corrupted.get_mut(offset).ok_or("epoch byte")? ^= 1;
                },
                7 => *corrupted.last_mut().ok_or("ciphertext byte")? ^= 1,
                8 => {
                    let start = corrupted
                        .len()
                        .checked_sub(wrapped_length + 68)
                        .ok_or("route start")?;
                    let duplicate = corrupted.get(start..).ok_or("route bytes")?.to_vec();
                    *corrupted.get_mut(81).ok_or("route count")? = 3;
                    corrupted.extend_from_slice(&duplicate);
                },
                _ => unreachable!("bounded fixture"),
            }
            std::fs::write(&route, &corrupted)?;
        }
        assert!(
            InstanceBootstrap::import_recovery_bundle(
                &paths,
                &bundle,
                pin,
                RecoveryUnlock::Identity(&unlock)
            )
            .is_err(),
            "case={case}"
        );
        assert_eq!(target.exists(), case == 3);
        if case < 3 {
            std::fs::remove_file(&original)?;
            std::fs::rename(&saved_original, &original)?;
        }
        if case >= 4 {
            std::fs::write(&route, &original_route)?;
        }
        if case != 3 {
            std::fs::rename(&saved_target, &target)?;
        }
        let reopened = InstanceBootstrap::reopen(&paths)?;
        {
            let session = RootRewrapSession::admit(&reopened._authority)?;
            let secret = session.rotation_catalog_secret(&reopened.key, reopened.instance_id())?;
            let catalog = positron_kernel::Catalog::open(
                &reopened._authority,
                reopened.instance_id(),
                secret,
            )?;
            assert_eq!(catalog.pin()?.identity(), catalog_identity, "case={case}");
        }
        assert_eq!(reopened.recovery_identity()?, pin);
        assert_eq!(reopened.local_key_rotation_status()?.active_epoch(), 2);
    }
    Ok(())
}
