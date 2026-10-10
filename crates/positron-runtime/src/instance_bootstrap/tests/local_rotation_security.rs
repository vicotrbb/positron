//! Security fixtures publish untrusted Catalog bytes through the public boundary.
use super::super::*;
use super::support::Roots;
use positron_kernel::{Catalog, CatalogObject, CatalogProposal, RootRewrapSession, TransactionId};

#[test]
fn root_retirement_requires_successor_recovery_and_reopens_without_predecessor_custody()
-> Result<(), Box<dyn std::error::Error>> {
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
    {
        let session = RootRewrapSession::admit(&initialized._authority)?;
        let catalog = Catalog::open(
            &initialized._authority,
            instance,
            session.rotation_catalog_secret(&initialized.key, instance)?,
        )?;
        let mut refused = 0;
        for record in catalog.governance_audit_records()? {
            let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
            if entry.action() == "catalog.root-rotation.retirement-refused" {
                refused += 1;
            }
        }
        assert_eq!(
            refused, 1,
            "verified successor with retained recovery must audit premature retirement"
        );
    }
    initialized.retire_recovery_predecessor()?;
    initialized.retire_local_key_predecessor()?;
    assert!(!roots.parent().join("secrets/local-root-key.v1").exists());
    assert!(!first.exists());
    initialized.retire_local_key_predecessor()?;
    drop(initialized);
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
fn invalid_rotation_authority_fences_provider_without_publishing_another_generation()
-> Result<(), Box<dyn std::error::Error>> {
    for substitution in 0..4 {
        let roots = Roots::new()?;
        let paths = roots.paths();
        let initialized =
            InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        initialized.begin_local_key_rotation()?;
        initialized.activate_local_key_rotation()?;
        let session = RootRewrapSession::admit(&initialized._authority)?;
        let catalog = Catalog::open(
            &initialized._authority,
            initialized.instance_id(),
            initialized.key.catalog_secret(initialized.instance_id())?,
        )?;
        let snapshot = catalog.pin()?;
        let _copy = catalog.reserve_catalog_proposal_copy(&snapshot)?;
        let unrelated = catalog
            .governance_audit_records()?
            .first()
            .ok_or("initial audit")?
            .transaction()
            .to_bytes();
        let missing = TransactionId::new([0x99; 16])?;
        assert!(catalog.confirm_committed_transaction(missing)?.is_none());
        let mut objects = Vec::new();
        for identity in snapshot.object_identities() {
            let mut bytes = snapshot.object(identity)?.ok_or("fixture object")?.to_vec();
            if bytes.starts_with(b"POSLROT1") {
                match substitution {
                    0 => bytes
                        .get_mut(24..40)
                        .ok_or("transaction field")?
                        .copy_from_slice(&missing.to_bytes()),
                    1 => bytes
                        .get_mut(24..40)
                        .ok_or("transaction field")?
                        .copy_from_slice(&unrelated),
                    2 => bytes
                        .get_mut(96..104)
                        .ok_or("active epoch field")?
                        .copy_from_slice(&3_u64.to_be_bytes()),
                    3 => {
                        let first_envelope = 104 + 56 + 2;
                        let length = u16::from_be_bytes(
                            bytes.get(160..162).ok_or("envelope length")?.try_into()?,
                        );
                        let tail = first_envelope + usize::from(length) - 1;
                        *bytes.get_mut(tail).ok_or("wrapped route")? ^= 1;
                    },
                    _ => return Err("unexpected fixture".into()),
                }
            }
            objects.push(CatalogObject::new(bytes)?);
        }
        let proposal = CatalogProposal::new(
            TransactionId::new([0x9a; 16])?,
            snapshot.format_epoch().ok_or("format")?,
            objects,
        )?;
        let committed = catalog.commit(snapshot.identity(), proposal, None)?;
        let generation = committed.number();
        drop(_copy);
        drop(snapshot);
        drop(catalog);
        drop(session);
        assert_eq!(
            initialized.activate_local_key_rotation(),
            Err(LocalKeyRotationFailure::Authentication)
        );
        assert!(!initialized.data_protection_health()?.system_ready);
        let session = RootRewrapSession::admit(&initialized._authority)?;
        let catalog = Catalog::open(
            &initialized._authority,
            initialized.instance_id(),
            session.rotation_catalog_secret(&initialized.key, initialized.instance_id())?,
        )?;
        assert_eq!(catalog.pin()?.number(), generation);
        drop(catalog);
        drop(session);
        drop(initialized);
        assert!(InstanceBootstrap::reopen(&paths).is_err());
    }
    Ok(())
}

#[test]
fn rotation_resource_refusal_precedes_successor_custody_and_catalog_work()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let generation = initialized.catalog_generation();
    let governor = initialized._authority.governor();
    let before = governor.inspect()?;
    let mut capacity = Vec::new();
    capacity.try_reserve_exact(usize::try_from(before.maximum_outstanding_reservations())?)?;
    for _ in 0..before.maximum_outstanding_reservations() {
        match RootRewrapSession::admit(&initialized._authority) {
            Ok(session) => capacity.push(session),
            Err(positron_kernel::BootstrapKeyFailure::LimitExceeded) => break,
            Err(failure) => return Err(failure.into()),
        }
    }
    assert_eq!(
        initialized.begin_local_key_rotation(),
        Err(LocalKeyRotationFailure::LimitExceeded)
    );
    assert_eq!(initialized.catalog_generation(), generation);
    assert!(initialized.data_protection_health()?.system_ready);
    drop(capacity);
    let access = initialized
        .bootstrap_storage
        .inspect()
        .map_err(|_| "fixture access")?;
    assert!(
        !access
            .layout()
            .map_err(|_| "fixture layout")?
            .contains(positron_kernel::BootstrapEntry::LocalKeyEpoch)
    );
    assert!(
        !access
            .layout()
            .map_err(|_| "fixture layout")?
            .contains(positron_kernel::BootstrapEntry::LocalKeyEpochStaging)
    );
    assert_eq!(initialized.local_key_rotation_status()?.active_epoch(), 1);
    assert_eq!(
        initialized.local_key_rotation_status()?.successor_epoch(),
        None
    );
    assert_eq!(
        initialized.begin_local_key_rotation()?.successor_epoch(),
        Some(2)
    );
    Ok(())
}
