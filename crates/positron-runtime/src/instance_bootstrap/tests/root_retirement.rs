//! Actual custody retirement refusals and crash-boundary recovery.
use super::super::*;
use super::support::Roots;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{Catalog, RootRewrapSession};
use std::os::unix::fs::PermissionsExt;

fn audit_count(
    initialized: &InitializedInstance,
    action: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let session = RootRewrapSession::admit(&initialized._authority)?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
    )?;
    let mut count = 0;
    for record in catalog.governance_audit_records()? {
        let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
        if entry.action() == action {
            count += 1;
        }
    }
    Ok(count)
}

fn verified_successor(roots: &Roots) -> Result<InitializedInstance, Box<dyn std::error::Error>> {
    let initialized =
        InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
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
    Ok(initialized)
}

#[test]
fn root_retirement_requires_intact_authenticated_successor_custody_before_unlink()
-> Result<(), Box<dyn std::error::Error>> {
    for kind in 0..4 {
        let roots = Roots::new()?;
        let initialized = verified_successor(&roots)?;
        let active = roots.parent().join("secrets/local-root-key.epoch-2.v1");
        let saved = std::fs::read(&active)?;
        let predecessor = roots.parent().join("secrets/local-root-key.v1");
        let predecessor_bytes = std::fs::read(&predecessor)?;
        let before = initialized.local_key_rotation_status()?;
        match kind {
            0 => std::fs::write(&active, [])?,
            1 => {
                std::fs::remove_file(&active)?;
                std::os::unix::fs::symlink(&predecessor, &active)?;
            },
            2 => std::fs::write(&active, &predecessor_bytes)?,
            3 => std::fs::remove_file(&active)?,
            _ => unreachable!("finite adversarial fixture"),
        }
        assert_eq!(
            initialized.retire_local_key_predecessor(),
            Err(LocalKeyRotationFailure::Custody)
        );
        assert_eq!(std::fs::read(&predecessor)?, predecessor_bytes);
        assert_eq!(initialized.local_key_rotation_status()?, before);
        assert_eq!(
            audit_count(&initialized, "catalog.root-rotation.verified")?,
            0
        );
        if active.symlink_metadata().is_ok() {
            std::fs::remove_file(&active)?;
        }
        std::fs::write(&active, &saved)?;
        std::fs::set_permissions(&active, std::fs::Permissions::from_mode(0o600))?;
        initialized.retire_local_key_predecessor()?;
        drop(initialized);
        assert_eq!(
            InstanceBootstrap::reopen(&roots.paths())?
                .local_key_rotation_status()?
                .active_epoch(),
            2
        );
    }
    Ok(())
}

#[test]
fn opaque_retained_operation_audits_root_retirement_refusal_without_custody_or_object_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let initialized = verified_successor(&roots)?;
    let session = RootRewrapSession::admit(&initialized._authority)?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
    )?;
    let coordinator = initialized.maintenance_coordinator();
    let identity =
        positron_kernel::MaintenanceTaskId::new([0x41; 16]).map_err(|_| "task identity")?;
    let task = positron_kernel::MaintenanceTask::with_contract(
        identity,
        positron_kernel::MaintenanceTaskClass::SchemaStatistics,
        positron_kernel::MaintenanceScope::System,
        positron_kernel::MaintenanceTrigger::Event,
        positron_kernel::MaintenancePreconditions::new(catalog.pin()?.number(), 1)
            .map_err(|_| "preconditions")?,
        vec![positron_kernel::MaintenanceObjectId::new([0x42; 32]).map_err(|_| "input identity")?],
        Vec::new(),
        positron_kernel::ResourceAmounts::new([1; 11]),
    )
    .map_err(|_| "task contract")?;
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .map_err(|_| "task publication")?;
    drop(catalog);
    drop(session);
    for cancelled in [false, true] {
        let basis = {
            let session = RootRewrapSession::admit(&initialized._authority)?;
            let catalog = Catalog::open(
                &initialized._authority,
                initialized.instance,
                session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
            )?;
            if cancelled {
                coordinator
                    .cancel_and_persist(&catalog, identity)
                    .map_err(|_| "task cancellation")?;
            }
            catalog.pin()?.object_identities().collect::<Vec<_>>()
        };
        assert_eq!(
            initialized.retire_local_key_predecessor(),
            Err(LocalKeyRotationFailure::Busy)
        );
        let session = RootRewrapSession::admit(&initialized._authority)?;
        let catalog = Catalog::open(
            &initialized._authority,
            initialized.instance,
            session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
        )?;
        assert_eq!(
            catalog.pin()?.object_identities().collect::<Vec<_>>(),
            basis
        );
        let mut refusals = 0;
        for record in catalog.governance_audit_records()? {
            let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
            if entry.action() == "catalog.root-rotation.retirement-refused" {
                refusals += 1;
            }
        }
        assert_eq!(refusals, if cancelled { 2 } else { 1 });
        assert!(roots.parent().join("secrets/local-root-key.v1").exists());
    }
    Ok(())
}

#[test]
fn root_retirement_durably_audits_verified_once_across_completion_replay_and_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let initialized = verified_successor(&roots)?;
    initialized.retire_local_key_predecessor()?;
    initialized.retire_local_key_predecessor()?;
    drop(initialized);
    let reopened = InstanceBootstrap::reopen(&roots.paths())?;
    reopened.retire_local_key_predecessor()?;
    let session = RootRewrapSession::admit(&reopened._authority)?;
    let catalog = Catalog::open(
        &reopened._authority,
        reopened.instance,
        session.rotation_catalog_secret(&reopened.key, reopened.instance)?,
    )?;
    let mut verified = 0;
    for record in catalog.governance_audit_records()? {
        let entry = positron_governance::GovernanceAuditEntry::decode(&record)?;
        if entry.action() == "catalog.root-rotation.verified" {
            verified += 1;
        }
    }
    assert_eq!(
        verified, 1,
        "exact root reference verification must be durably audited once"
    );
    Ok(())
}

#[test]
fn root_reference_guard_refuses_new_task_acquisition_and_releases_ordinary_submission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let initialized = verified_successor(&roots)?;
    let session = RootRewrapSession::admit(&initialized._authority)?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
    )?;
    let basis = catalog.pin()?;
    let coordinator = initialized.maintenance_coordinator();
    let guard = coordinator
        .guard_root_retirement_references(&session, &catalog, &basis)
        .map_err(|_| "reference guard")?;
    let task = positron_kernel::MaintenanceTask::new(
        positron_kernel::MaintenanceTaskId::new([0x51; 16]).map_err(|_| "task identity")?,
        positron_kernel::MaintenanceTaskClass::SchemaStatistics,
    );
    assert_eq!(
        coordinator.submit_and_persist(&catalog, task.clone(), 1),
        Err(positron_kernel::MaintenanceFailure::ConcurrentAccess)
    );
    assert!(matches!(
        coordinator.guard_root_retirement_references(&session, &catalog, &basis),
        Err(positron_kernel::MaintenanceFailure::ConcurrentAccess)
    ));
    assert_eq!(catalog.pin()?.identity(), basis.identity());
    drop(guard);
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .map_err(|_| "ordinary submission after release")?;
    assert_ne!(catalog.pin()?.identity(), basis.identity());
    Ok(())
}

#[test]
fn custody_retirement_faults_resume_exact_prepared_state_and_sync_absent_parent()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::RootCustodyPublicationFault;
    for fault in [
        RootCustodyPublicationFault::PredecessorDirectorySync,
        RootCustodyPublicationFault::RoutePartialWrite,
        RootCustodyPublicationFault::RouteFileSync,
        RootCustodyPublicationFault::RouteDirectorySync,
    ] {
        let roots = Roots::new()?;
        let initialized = verified_successor(&roots)?;
        let failed = RootRewrapSession::with_custody_publication_fault(fault, || {
            initialized.retire_local_key_predecessor()
        });
        assert_eq!(
            failed,
            Err(LocalKeyRotationFailure::Custody),
            "fault={fault:?}"
        );
        assert!(!roots.parent().join("secrets/local-root-key.v1").exists());
        assert_eq!(
            initialized.local_key_rotation_status()?.phase(),
            LocalKeyRotationPhase::Retiring
        );
        drop(initialized);
        let reopened = InstanceBootstrap::reopen(&roots.paths())?;
        assert_eq!(
            reopened.local_key_rotation_status()?.phase(),
            LocalKeyRotationPhase::Retiring
        );
        assert_eq!(
            RootRewrapSession::with_custody_publication_fault(
                RootCustodyPublicationFault::PredecessorDirectorySync,
                || reopened.retire_local_key_predecessor()
            ),
            Err(LocalKeyRotationFailure::Custody)
        );
        reopened.retire_local_key_predecessor()?;
        assert_eq!(
            reopened.local_key_rotation_status()?.phase(),
            LocalKeyRotationPhase::Active
        );
        drop(reopened);
        assert_eq!(
            InstanceBootstrap::reopen(&roots.paths())?
                .local_key_rotation_status()?
                .active_epoch(),
            2
        );
    }
    Ok(())
}

#[test]
fn malformed_or_substituted_root_route_refuses_retirement_without_publication()
-> Result<(), Box<dyn std::error::Error>> {
    for substitution in 0..4 {
        let roots = Roots::new()?;
        let initialized = verified_successor(&roots)?;
        let route = roots
            .parent()
            .join("data/.positron-system-key-envelopes.v1");
        let basis = {
            let session = RootRewrapSession::admit(&initialized._authority)?;
            let catalog = Catalog::open(
                &initialized._authority,
                initialized.instance,
                session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
            )?;
            catalog.pin()?.identity()
        };
        match substitution {
            0 => std::fs::write(&route, [])?,
            1 => {
                let mut bytes = std::fs::read(&route)?;
                *bytes.last_mut().ok_or("route ciphertext")? ^= 1;
                std::fs::write(&route, bytes)?;
            },
            2 => {
                std::fs::remove_file(&route)?;
                std::os::unix::fs::symlink(roots.parent().join("missing"), &route)?;
            },
            3 => {
                let mut bytes = std::fs::read(&route)?;
                *bytes.get_mut(8).ok_or("route instance")? ^= 1;
                std::fs::write(&route, bytes)?;
            },
            _ => return Err("unknown substitution".into()),
        }
        assert!(initialized.retire_local_key_predecessor().is_err());
        assert!(roots.parent().join("secrets/local-root-key.v1").exists());
        let session = RootRewrapSession::admit(&initialized._authority)?;
        let catalog = Catalog::open(
            &initialized._authority,
            initialized.instance,
            session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
        )?;
        assert_eq!(catalog.pin()?.identity(), basis);
    }
    Ok(())
}

#[test]
fn root_retirement_prepared_publication_fault_preserves_custody_and_resumes()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_sequence_after};
    let roots = Roots::new()?;
    let initialized = verified_successor(&roots)?;
    let before = initialized.local_key_rotation_status()?;
    let failed = with_catalog_publication_fault_sequence_after(
        &[(CatalogPublicationFault::RenameMarker, 0)],
        || initialized.retire_local_key_predecessor(),
    );
    assert_eq!(failed, Err(LocalKeyRotationFailure::Storage));
    assert!(roots.parent().join("secrets/local-root-key.v1").exists());
    assert_eq!(initialized.local_key_rotation_status()?, before);
    drop(initialized);
    let reopened = InstanceBootstrap::reopen(&roots.paths())?;
    reopened.retire_local_key_predecessor()?;
    assert!(!roots.parent().join("secrets/local-root-key.v1").exists());
    drop(reopened);
    assert_eq!(
        InstanceBootstrap::reopen(&roots.paths())?
            .local_key_rotation_status()?
            .active_epoch(),
        2
    );
    Ok(())
}

#[test]
fn root_retirement_post_marker_sync_failure_resumes_exact_visible_stage()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_sequence_after};
    // Recovery readiness and exact active-state confirmation each synchronize one
    // existing marker. Verified audit, preparation and completion each publish
    // their own marker, in that order, before any later retry confirmation.
    for (preceding, phase, predecessor_present) in [
        (2, LocalKeyRotationPhase::Verifying, true),
        (3, LocalKeyRotationPhase::Retiring, true),
        (4, LocalKeyRotationPhase::Active, false),
    ] {
        let roots = Roots::new()?;
        let initialized = verified_successor(&roots)?;
        let failed = with_catalog_publication_fault_sequence_after(
            &[(
                CatalogPublicationFault::SynchronizeGenerationDirectory,
                preceding,
            )],
            || initialized.retire_local_key_predecessor(),
        );
        assert_eq!(failed, Err(LocalKeyRotationFailure::Storage));
        assert_eq!(
            roots.parent().join("secrets/local-root-key.v1").exists(),
            predecessor_present
        );
        assert_eq!(initialized.local_key_rotation_status()?.phase(), phase);
        drop(initialized);
        let reopened = InstanceBootstrap::reopen(&roots.paths())?;
        assert_eq!(reopened.local_key_rotation_status()?.phase(), phase);
        assert!(
            with_catalog_publication_fault_sequence_after(
                &[(CatalogPublicationFault::SynchronizeGenerationDirectory, 0)],
                || reopened.retire_local_key_predecessor()
            )
            .is_err()
        );
        assert_eq!(reopened.local_key_rotation_status()?.phase(), phase);
        reopened.retire_local_key_predecessor()?;
        assert!(!roots.parent().join("secrets/local-root-key.v1").exists());
        assert_eq!(
            audit_count(&reopened, "catalog.root-rotation.verified")?,
            1,
            "ambiguous verified audit must be confirmed rather than duplicated"
        );
        drop(reopened);
        assert_eq!(
            InstanceBootstrap::reopen(&roots.paths())?
                .local_key_rotation_status()?
                .phase(),
            LocalKeyRotationPhase::Active
        );
    }
    Ok(())
}

#[test]
fn root_verified_audit_cannot_be_reused_for_a_changed_authenticated_source()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_sequence_after};
    let roots = Roots::new()?;
    let initialized = verified_successor(&roots)?;
    assert_eq!(
        with_catalog_publication_fault_sequence_after(
            &[(CatalogPublicationFault::SynchronizeGenerationDirectory, 2)],
            || initialized.retire_local_key_predecessor()
        ),
        Err(LocalKeyRotationFailure::Storage)
    );
    assert_eq!(
        initialized.local_key_rotation_status()?.phase(),
        LocalKeyRotationPhase::Verifying
    );
    assert_eq!(
        audit_count(&initialized, "catalog.root-rotation.verified")?,
        1
    );
    drop(initialized);
    let claim = InstanceBootstrap::claim(&roots.paths())?;
    let initialized = InstanceBootstrap::reopen(&roots.paths())?;
    let administrator = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_tenant_display_name(
        administrator,
        initialized.default_tenant_id(),
        ResourceGeneration::new(1)?,
        "Verified source successor",
        AdministrativeIdempotencyKey::new([0x7a; 16])?,
    )?;
    initialized.retire_local_key_predecessor()?;
    assert_eq!(
        audit_count(&initialized, "catalog.root-rotation.verified")?,
        2,
        "changed managed object set requires a newly audited verification"
    );
    assert!(!roots.parent().join("secrets/local-root-key.v1").exists());
    Ok(())
}

#[test]
fn malformed_or_foreign_predecessor_custody_never_authorizes_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    for substitution in 0..3 {
        let roots = Roots::new()?;
        let initialized = verified_successor(&roots)?;
        let predecessor = roots.parent().join("secrets/local-root-key.v1");
        let basis = {
            let session = RootRewrapSession::admit(&initialized._authority)?;
            let catalog = Catalog::open(
                &initialized._authority,
                initialized.instance,
                session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
            )?;
            catalog.pin()?.identity()
        };
        let foreign = Roots::new()?;
        match substitution {
            0 => std::fs::OpenOptions::new()
                .write(true)
                .open(&predecessor)?
                .set_len(0)?,
            1 => {
                std::fs::remove_file(&predecessor)?;
                std::os::unix::fs::symlink(
                    roots.parent().join("secrets/local-root-key.epoch-2.v1"),
                    &predecessor,
                )?;
            },
            2 => {
                let other = InstanceBootstrap::initialize(
                    &foreign.paths(),
                    InitializationPlan::non_interactive(),
                )?;
                drop(other);
                std::fs::rename(
                    foreign.parent().join("secrets/local-root-key.v1"),
                    &predecessor,
                )?;
            },
            _ => return Err("unknown custody substitution".into()),
        }
        assert!(initialized.retire_local_key_predecessor().is_err());
        assert!(std::fs::symlink_metadata(&predecessor).is_ok());
        let session = RootRewrapSession::admit(&initialized._authority)?;
        let catalog = Catalog::open(
            &initialized._authority,
            initialized.instance,
            session.rotation_catalog_secret(&initialized.key, initialized.instance)?,
        )?;
        assert_eq!(catalog.pin()?.identity(), basis);
    }
    Ok(())
}
