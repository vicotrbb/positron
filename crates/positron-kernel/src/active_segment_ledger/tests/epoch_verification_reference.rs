//! Typed verifier metadata and reset use the existing public reference gate.
use super::support::{TemporaryRoot, successor_protection as successor};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, InstanceId,
    LedgerFailureCode, MountQualification, PrimaryDataVolume, TransactionId,
};
use positron_domain::identity::TenantId;
use std::error::Error;
#[test]
fn authenticated_verification_metadata_does_not_retain_a_predecessor_key()
-> Result<(), Box<dyn Error>> {
    use crate::{
        EnvelopeVerificationCheckpoint, FormatEpoch, MaintenanceCoordinator,
        MaintenancePreconditions, MaintenanceScope, MaintenanceTask, MaintenanceTaskClass,
        MaintenanceTaskId, MaintenanceTrigger,
    };
    let root = TemporaryRoot::new()?;
    let authority = super::support::establish_integrity_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa1; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"actual source authority".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0xa2; 16]).expect("task"),
        MaintenanceTaskClass::EnvelopeVerification,
        MaintenanceScope::tenant(tenant),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        crate::integrity_scrub_resource_claim(),
    )
    .expect("bounded verification");
    coordinator
        .submit_and_persist(&catalog, task.clone(), 1)
        .expect("durable task");
    let execution = coordinator
        .start_envelope_verification_task_with_reservation_and_persist(
            &catalog,
            &authority,
            2,
            false,
            task.identity(),
        )
        .expect("admitted verification")
        .expect("queued");
    let basis = catalog.pin()?;
    let source = basis.envelope_verification_source_identity(instance, &task)?;
    execution
        .checkpoint_envelope_verification_at_basis(
            &coordinator,
            &catalog,
            &basis,
            crate::EnvelopeVerificationPublication::new(2, TransactionId::new([0xb8; 16])?, None),
            EnvelopeVerificationCheckpoint::new(instance, tenant, 2, source, None, None)
                .expect("complete metadata")
                .checkpoint(1)
                .expect("canonical checkpoint"),
        )
        .expect("atomic completion");
    drop(execution);
    let guard = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        tenant,
        &successor()?,
    )?;
    assert_eq!(guard.catalog_basis().identity(), catalog.pin()?.identity());
    drop(guard);
    let basis = catalog.pin()?;
    let mut objects = Vec::new();
    for id in basis.object_identities() {
        objects.push(CatalogObject::new(
            basis.object(id)?.ok_or("source object")?.to_vec(),
        )?);
    }
    objects.push(CatalogObject::new(
        b"new actual managed reference".to_vec(),
    )?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa3; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let changed = catalog.pin()?.identity();
    let failure = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        tenant,
        &successor()?,
    )
    .err()
    .ok_or("stale proof allowed reference gate")?;
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    assert_eq!(catalog.pin()?.identity(), changed);
    let fresh = catalog.pin()?;
    assert_eq!(
        coordinator.restart_envelope_verification_at_basis(&catalog, &fresh, task.identity(), 3),
        Err(crate::MaintenanceFailure::InvalidInput)
    );
    assert_eq!(catalog.pin()?.identity(), changed);
    assert_eq!(
        coordinator
            .status(task.identity())
            .expect("unchanged owner")
            .phase(),
        crate::MaintenanceTaskPhase::Succeeded
    );
    coordinator
        .restart_envelope_verification_at_basis(&catalog, &fresh, task.identity(), 2)
        .expect("requeue same authenticated owner");
    let reset = coordinator.status(task.identity()).expect("reset owner");
    assert_eq!(reset.task(), &task);
    assert_eq!(reset.phase(), crate::MaintenanceTaskPhase::Queued);
    assert!(reset.checkpoint().is_none());
    Ok(())
}

#[test]
fn verifier_reset_rejects_foreign_malformed_and_false_completed_checkpoint_without_mutation()
-> Result<(), Box<dyn Error>> {
    use crate::{
        EnvelopeVerificationCheckpoint, FormatEpoch, MaintenanceCheckpoint, MaintenanceCoordinator,
        MaintenancePreconditions, MaintenanceScope, MaintenanceTask, MaintenanceTaskClass,
        MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger, SegmentScope,
    };
    use positron_domain::routing::{SignalKind, VirtualShardId};
    for case in 0..5 {
        let root = TemporaryRoot::new()?;
        let authority = super::support::establish_integrity_authority(PrimaryDataVolume::acquire(
            root.path(),
            MountQualification::LocalHost,
        )?)?;
        let instance = InstanceId::new([0xe1; 16])?;
        let tenant = TenantId::from_bytes([0x64; 16])?;
        let catalog = Catalog::open(
            &authority,
            instance,
            CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
        )?;
        catalog.commit(
            catalog.pin()?.identity(),
            CatalogProposal::new(
                TransactionId::new([0xc1; 16])?,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(b"actual source authority".to_vec())?],
            )?,
            None,
        )?;
        let coordinator = MaintenanceCoordinator::new();
        let task = MaintenanceTask::with_contract(
            MaintenanceTaskId::new([0xc2; 16]).expect("task"),
            MaintenanceTaskClass::EnvelopeVerification,
            MaintenanceScope::tenant(tenant),
            MaintenanceTrigger::Event,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            Vec::new(),
            Vec::new(),
            crate::integrity_scrub_resource_claim(),
        )
        .expect("bounded task");
        coordinator
            .submit_and_persist(&catalog, task.clone(), 1)
            .expect("owner");
        let execution = coordinator
            .start_envelope_verification_task_with_reservation_and_persist(
                &catalog,
                &authority,
                2,
                false,
                task.identity(),
            )
            .expect("admit")
            .expect("queued");
        let bound_instance = if case == 0 {
            InstanceId::new([0xd1; 16])?
        } else {
            instance
        };
        let bound_tenant = if case == 1 {
            TenantId::from_bytes([0xd2; 16])?
        } else {
            tenant
        };
        let bound_epoch = if case == 2 { 3 } else { 2 };
        let scope = if case == 4 {
            Some(SegmentScope::new(
                tenant,
                SignalKind::Logs,
                VirtualShardId::new(1)?,
            ))
        } else {
            None
        };
        let mut checkpoint = EnvelopeVerificationCheckpoint::new(
            bound_instance,
            bound_tenant,
            bound_epoch,
            [0xd3; 32],
            scope,
            None,
        )
        .expect("bounded adversarial metadata")
        .checkpoint(1)
        .expect("encoding");
        if case == 3 {
            checkpoint =
                MaintenanceCheckpoint::new(1, 0, b"PEVCKP01".to_vec()).expect("malformed fixture");
        }
        // Existing cfg(test) transition seams construct an authenticated but
        // adversarial Catalog owner. Production generic paths reject this.
        coordinator
            .checkpoint(task.identity(), checkpoint)
            .expect("adversarial test state");
        coordinator
            .complete(task.identity(), true)
            .expect("false completion fixture");
        drop(execution);
        let basis = catalog.pin()?;
        let records = coordinator.durable_records().expect("fixture owner");
        let mut objects = Vec::new();
        for id in basis.object_identities() {
            let bytes = basis.object(id)?.ok_or("object")?;
            if !bytes.starts_with(b"PMTC0006") {
                objects.push(CatalogObject::new(bytes.to_vec())?);
            }
        }
        for record in records {
            objects.push(record.catalog_object().expect("fixture record"));
        }
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([0xc3; 16])?,
                FormatEpoch::CATALOG_V1,
                objects,
            )?,
            None,
        )?;
        let basis = catalog.pin()?;
        assert_eq!(
            coordinator.restart_envelope_verification_at_basis(
                &catalog,
                &basis,
                task.identity(),
                2
            ),
            Err(crate::MaintenanceFailure::InvalidInput)
        );
        assert_eq!(catalog.pin()?.identity(), basis.identity());
        let status = coordinator
            .status(task.identity())
            .expect("unchanged owner");
        assert_eq!(status.phase(), MaintenanceTaskPhase::Succeeded);
        assert!(status.checkpoint().is_some());
    }
    Ok(())
}

#[test]
fn failed_verifier_reset_accepts_only_stale_incomplete_context_and_preserves_refusals()
-> Result<(), Box<dyn Error>> {
    use crate::{
        EnvelopeVerificationCheckpoint, FormatEpoch, MaintenanceCheckpoint, MaintenanceCoordinator,
        MaintenancePreconditions, MaintenanceScope, MaintenanceTask, MaintenanceTaskClass,
        MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger, SegmentScope,
    };
    use positron_domain::routing::{SignalKind, VirtualShardId};
    for case in 0..7 {
        let root = TemporaryRoot::new()?;
        let authority = super::support::establish_integrity_authority(PrimaryDataVolume::acquire(
            root.path(),
            MountQualification::LocalHost,
        )?)?;
        let instance = InstanceId::new([0xe1; 16])?;
        let tenant = TenantId::from_bytes([0x64; 16])?;
        let catalog = Catalog::open(
            &authority,
            instance,
            CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
        )?;
        catalog.commit(
            catalog.pin()?.identity(),
            CatalogProposal::new(
                TransactionId::new([0xc1; 16])?,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(b"actual source authority".to_vec())?],
            )?,
            None,
        )?;
        let coordinator = MaintenanceCoordinator::new();
        let task = MaintenanceTask::with_contract(
            MaintenanceTaskId::new([0xc2; 16]).expect("task"),
            MaintenanceTaskClass::EnvelopeVerification,
            MaintenanceScope::tenant(tenant),
            MaintenanceTrigger::Event,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            Vec::new(),
            Vec::new(),
            crate::integrity_scrub_resource_claim(),
        )
        .expect("bounded task");
        coordinator
            .submit_and_persist(&catalog, task.clone(), 1)
            .expect("owner");
        let execution = coordinator
            .start_envelope_verification_task_with_reservation_and_persist(
                &catalog,
                &authority,
                2,
                false,
                task.identity(),
            )
            .expect("admit")
            .expect("queued");
        let bound_instance = if case == 0 {
            InstanceId::new([0xd1; 16])?
        } else {
            instance
        };
        let bound_tenant = if case == 1 {
            TenantId::from_bytes([0xd2; 16])?
        } else {
            tenant
        };
        let bound_epoch = if case == 2 { 3 } else { 2 };
        let scope = if case != 4 {
            Some(SegmentScope::new(
                bound_tenant,
                SignalKind::Logs,
                VirtualShardId::new(1)?,
            ))
        } else {
            None
        };
        let mut checkpoint = EnvelopeVerificationCheckpoint::new(
            bound_instance,
            bound_tenant,
            bound_epoch,
            [0xd3; 32],
            scope,
            None,
        )
        .expect("bounded adversarial metadata")
        .checkpoint(1)
        .expect("encoding");
        if case == 3 {
            checkpoint =
                MaintenanceCheckpoint::new(1, 0, b"PEVCKP01".to_vec()).expect("malformed fixture");
        }
        // Existing cfg(test) transition seams construct an authenticated but
        // adversarial Catalog owner. Production generic paths reject this.
        coordinator
            .checkpoint(task.identity(), checkpoint)
            .expect("adversarial test state");
        execution
            .fail_and_persist(
                &coordinator,
                &catalog,
                if case == 6 {
                    crate::MaintenanceTerminalFailure::Unclassified
                } else {
                    crate::MaintenanceTerminalFailure::StaleGeneration
                },
            )
            .expect("canonical durable failure");
        drop(execution);
        let basis = catalog.pin()?;
        let result = coordinator.restart_envelope_verification_at_basis(
            &catalog,
            &basis,
            task.identity(),
            2,
        );
        if case == 5 {
            result.expect("same failed owner requeued");
            let status = coordinator.status(task.identity()).expect("reset owner");
            assert_eq!(status.task(), &task);
            assert_eq!(status.phase(), MaintenanceTaskPhase::Queued);
            assert!(status.checkpoint().is_none());
            assert!(status.terminal_failure().is_none());
        } else {
            assert!(result.is_err());
            assert_eq!(catalog.pin()?.identity(), basis.identity());
            let status = coordinator
                .status(task.identity())
                .expect("unchanged failed owner");
            assert_eq!(status.phase(), MaintenanceTaskPhase::Failed);
            assert!(status.checkpoint().is_some());
        }
    }
    Ok(())
}
