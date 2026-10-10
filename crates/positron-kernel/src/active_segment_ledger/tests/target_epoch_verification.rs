//! Target-only verification traverses immutable objects on one exact basis.
use super::support::{TemporaryRoot, establish_authority};
use super::support::{predecessor_protection as old, successor_protection as successor};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, IntegrityCancellation,
    IntegrityScrubBudget, IntegrityVerificationOutcome, IntegrityVerificationRequest,
    MountQualification, PreparedStoreBlock, PrimaryDataVolume, SegmentScope, StoreBlockIdentity,
    TransactionId,
};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};

#[test]
fn target_only_integrity_passes_authenticate_one_immutable_segment_and_resume()
-> Result<(), Box<dyn std::error::Error>> {
    for signal in [SignalKind::Logs, SignalKind::Traces] {
        let root = TemporaryRoot::new()?;
        let authority = establish_authority(PrimaryDataVolume::acquire(
            root.path(),
            MountQualification::LocalHost,
        )?)?;
        let instance = InstanceId::new([0xe1; 16])?;
        let catalog = Catalog::open(
            &authority,
            instance,
            CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
        )?;
        let scope = SegmentScope::new(
            TenantId::from_bytes([0x64; 16])?,
            signal,
            VirtualShardId::new(1)?,
        );
        for identity in [0xf1, 0xf2] {
            let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, old())?;
            ledger.append(PreparedStoreBlock::new(
                scope,
                StoreBlockIdentity::new([identity; 16])?,
                vec![identity; 1024],
            )?)?;
            ledger.seal()?;
        }
        let before = catalog.pin()?;
        let cancellation = IntegrityCancellation::new();
        let verify = |basis: &crate::CatalogSnapshot, continuation| {
            ActiveSegmentLedger::verify_snapshot_integrity(
                &authority,
                basis,
                instance,
                IntegrityVerificationRequest::new(
                    scope,
                    successor().expect("valid target route"),
                    IntegrityScrubBudget::new(1).expect("bounded pass"),
                    &cancellation,
                    TransactionId::new([0xf3; 16]).expect("fixture transaction"),
                    continuation,
                ),
            )
        };
        let rejected = verify(&before, None)?;
        assert!(
            !rejected.is_success(),
            "target-only keys cannot verify unmigrated frames"
        );
        assert_eq!(catalog.pin()?.identity(), before.identity());
        for identity in [0xf4, 0xf5] {
            assert!(ActiveSegmentLedger::migrate_next_envelope(
                &authority,
                &catalog,
                scope,
                successor()?.retain_predecessor(old())?,
                TransactionId::new([identity; 16])?,
                None
            )?);
        }
        let migrated = catalog.pin()?;
        let first = verify(&migrated, None)?;
        assert_eq!(first.outcome(), IntegrityVerificationOutcome::Incomplete);
        assert_eq!(first.examined_segments(), 1);
        let continuation = first.continuation().ok_or("bounded continuation")?;
        let second = verify(&migrated, Some(continuation))?;
        assert_eq!(second.outcome(), IntegrityVerificationOutcome::Verified);
        assert_eq!(second.examined_segments(), 1);
        assert_eq!(catalog.pin()?.identity(), migrated.identity());
    }
    Ok(())
}

#[test]
fn stale_verification_basis_cannot_publish_progress_or_completion()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{
        CatalogObject, CatalogProposal, EnvelopeVerificationCheckpoint, FormatEpoch,
        MaintenanceCoordinator, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
        MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger,
    };
    let root = TemporaryRoot::new()?;
    let authority = super::support::establish_integrity_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xd1; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"source fixture".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0xd2; 16]).map_err(|_| "task")?,
        MaintenanceTaskClass::EnvelopeVerification,
        MaintenanceScope::tenant(tenant),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).map_err(|_| "preconditions")?,
        Vec::new(),
        Vec::new(),
        crate::integrity_scrub_resource_claim(),
    )
    .map_err(|_| "bounded task")?;
    coordinator
        .submit_and_persist(&catalog, task.clone(), 1)
        .map_err(|_| "persist task")?;
    let execution = coordinator
        .start_envelope_verification_task_with_reservation_and_persist(
            &catalog,
            &authority,
            2,
            false,
            task.identity(),
        )
        .map_err(|failure| format!("admit task: {failure:?}"))?
        .ok_or("execution")?;
    let basis = catalog.pin()?;
    let source = basis.envelope_verification_source_identity(instance, &task)?;
    // Canonical v1 source vector: domain, instance e1, format u32(1),
    // task d2, tenant 64, two u64(1) preconditions, and SHA-256("source fixture").
    // The exact owning task record is excluded; its Running publication does
    // not change the source vector or authorize arbitrary object exclusion.
    assert_eq!(
        source,
        [
            0x29, 0xda, 0x1c, 0x8f, 0xc9, 0xca, 0x13, 0xd0, 0x1a, 0xeb, 0xab, 0x90, 0x3e, 0x1c,
            0x2c, 0xed, 0x46, 0x95, 0xea, 0x74, 0x5d, 0xac, 0x93, 0xb5, 0x3b, 0x8e, 0xb6, 0x33,
            0x1e, 0x2f, 0xe7, 0x40,
        ]
    );
    let mut objects = Vec::new();
    for identity in basis.object_identities() {
        objects.push(CatalogObject::new(
            basis.object(identity)?.ok_or("source object")?.to_vec(),
        )?);
    }
    objects.push(CatalogObject::new(b"changed managed reference".to_vec())?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xd3; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let changed = catalog.pin()?.identity();
    for next_scope in [Some(scope), None] {
        let checkpoint =
            EnvelopeVerificationCheckpoint::new(instance, tenant, 2, source, next_scope, None)
                .map_err(|_| "typed progress")?
                .checkpoint(1)
                .map_err(|_| "checkpoint")?;
        assert_eq!(
            execution.checkpoint_envelope_verification_at_basis(
                &coordinator,
                &catalog,
                &basis,
                crate::EnvelopeVerificationPublication::new(
                    2,
                    TransactionId::new([0xb6; 16])?,
                    None
                ),
                checkpoint,
            ),
            Err(crate::MaintenanceFailure::CatalogUnavailable),
        );
        assert_eq!(catalog.pin()?.identity(), changed);
        let status = coordinator.status(task.identity()).map_err(|_| "status")?;
        assert_eq!(status.phase(), MaintenanceTaskPhase::Running);
        assert!(status.checkpoint().is_none());
    }
    let current = catalog.pin()?;
    let source = current.envelope_verification_source_identity(instance, &task)?;
    execution
        .checkpoint_envelope_verification_at_basis(
            &coordinator,
            &catalog,
            &current,
            crate::EnvelopeVerificationPublication::new(2, TransactionId::new([0xb7; 16])?, None),
            EnvelopeVerificationCheckpoint::new(instance, tenant, 2, source, Some(scope), None)
                .map_err(|_| "progress")?
                .checkpoint(1)
                .map_err(|_| "checkpoint")?,
        )
        .map_err(|_| "publish exact progress")?;
    assert_eq!(
        coordinator
            .status(task.identity())
            .map_err(|_| "queued")?
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    Ok(())
}

#[test]
fn owning_verification_refuses_wrong_and_retained_capabilities_before_checkpoint_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{
        MaintenanceCoordinator, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
        MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger,
        SegmentProtectionKey,
    };
    let root = TemporaryRoot::new()?;
    let authority = super::support::establish_integrity_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, old())?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xb1; 16])?,
        b"actual immutable object".to_vec(),
    )?)?;
    ledger.seal()?;
    assert!(ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        TransactionId::new([0xb2; 16])?,
        None
    )?);
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0xb3; 16]).expect("task"),
        MaintenanceTaskClass::EnvelopeVerification,
        MaintenanceScope::tenant(tenant),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        crate::integrity_scrub_resource_claim(),
    )
    .expect("bounded task");
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
        .expect("admit")
        .expect("queued");
    let basis = catalog.pin()?;
    assert_eq!(
        execution
            .next_envelope_verification_scope(&basis, instance, 2)
            .expect("scope"),
        Some(scope)
    );
    for protection in [
        old(),
        successor()?.retain_predecessor(old())?,
        SegmentProtectionKey::from_owned_with_route(Box::new([0x91; 32]), [0xe7; 16], 2)?,
        SegmentProtectionKey::from_owned_with_route(Box::new([0xe6; 32]), [0x92; 16], 2)?,
    ] {
        assert!(
            execution
                .verify_and_checkpoint_envelope_at_basis(
                    &coordinator,
                    &catalog,
                    &basis,
                    Some(protection),
                    crate::EnvelopeVerificationPublication::new(
                        2,
                        TransactionId::new([0xb4; 16])?,
                        None
                    )
                )
                .is_err()
        );
        assert_eq!(catalog.pin()?.identity(), basis.identity());
        let status = coordinator.status(task.identity()).expect("status");
        assert_eq!(status.phase(), MaintenanceTaskPhase::Running);
        assert!(status.checkpoint().is_none());
    }
    let progress = execution
        .verify_and_checkpoint_envelope_at_basis(
            &coordinator,
            &catalog,
            &basis,
            Some(successor()?),
            crate::EnvelopeVerificationPublication::new(2, TransactionId::new([0xb5; 16])?, None),
        )
        .expect("actual target-only traversal");
    assert!(progress.is_complete());
    assert_eq!(progress.examined_segments(), 1);
    assert_eq!(
        coordinator
            .status(task.identity())
            .expect("verified")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}
