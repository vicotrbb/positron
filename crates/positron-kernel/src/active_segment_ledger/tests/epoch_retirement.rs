//! Public managed reference refusal and bounded proof admission outcomes.
use super::support::{TemporaryRoot, establish_authority};
use super::support::{predecessor_protection as old, successor_protection as successor};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, InstanceId,
    LedgerFailureCode, MountQualification, PreparedStoreBlock, PrimaryDataVolume, SegmentScope,
    StoreBlockIdentity, TransactionId,
};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
use std::error::Error;

#[test]
fn contended_reference_registry_refuses_retirement_without_waiting_or_mutation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let protection = successor()?;
    let before = catalog.pin()?;
    let resources = authority.governor().inspect()?;
    let (ready, acquired) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (observed, lock_release) = std::thread::scope(|threads| {
        let held_authority = &authority;
        let worker = threads.spawn(move || {
            let registry = held_authority.snapshot_protection();
            let bindings = registry.lock().expect("registry");
            ready.send(()).expect("lock acquisition observation");
            // The original blocking implementation can finish after this
            // ceiling; the fixture never leaves a stuck worker or grant.
            let outcome = released.recv_timeout(std::time::Duration::from_secs(1));
            drop(bindings);
            outcome
        });
        acquired.recv().expect("registry owner started");
        let observed = ActiveSegmentLedger::guard_tenant_epoch_retirement(
            &authority,
            &catalog,
            tenant,
            &protection,
        )
        .map(|_| ())
        .map_err(|failure| failure.code());
        drop(release);
        (observed, worker.join().expect("registry owner"))
    });
    assert_eq!(observed, Err(LedgerFailureCode::ConcurrentWriter));
    assert_eq!(
        lock_release,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    );
    let after = catalog.pin()?;
    assert_eq!(after.number(), before.number());
    assert_eq!(
        after.object_identities().collect::<Vec<_>>(),
        before.object_identities().collect::<Vec<_>>()
    );
    let released = authority.governor().inspect()?;
    assert_eq!(
        released.outstanding_reservations(),
        resources.outstanding_reservations()
    );
    for dimension in crate::ResourceDimension::ALL {
        assert_eq!(released.usage(dimension), resources.usage(dimension));
    }
    assert!(
        ActiveSegmentLedger::guard_tenant_epoch_retirement(
            &authority,
            &catalog,
            tenant,
            &protection,
        )
        .is_ok(),
        "ordinary proof admission resumes after the existing owner releases its lock"
    );
    Ok(())
}

#[test]
fn valid_historical_snapshot_lease_retains_its_original_generation_across_migration()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, old())?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xf1; 16])?,
        b"historically-pinned".to_vec(),
    )?)?;
    let original_snapshot = ledger.snapshot()?;
    let lease = ledger.create_snapshot_lease(100, 200)?;
    let identity = lease.identity();
    let original_identity = lease.snapshot().catalog_identity();
    let original_generation = lease.snapshot().catalog_generation();
    drop(lease);
    ledger.seal()?;
    assert!(ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        TransactionId::new([0xf2; 16])?,
        None
    )?);
    let clock = crate::LifecycleClock::new(crate::FixedLifecycleClockSource::new(
        positron_domain::time::UnixNanoseconds::new(101_000_000_000),
    ));
    let ledger = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        &clock,
    )?;
    let resumed = ledger.resume_snapshot_lease(identity, 101)?;
    assert_eq!(resumed.snapshot().catalog_identity(), original_identity);
    assert_eq!(resumed.snapshot().catalog_generation(), original_generation);
    assert_eq!(resumed.snapshot().blocks().len(), 1);
    assert_eq!(
        resumed
            .snapshot()
            .blocks()
            .first()
            .ok_or("pinned block")?
            .payload(),
        b"historically-pinned"
    );
    let failure = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        scope.tenant_id(),
        &successor()?,
    )
    .err()
    .ok_or("historical lease permitted retirement")?;
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    drop(resumed);
    let failure = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        scope.tenant_id(),
        &successor()?,
    )
    .err()
    .ok_or("durable lease permitted retirement")?;
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    drop(ledger);
    let clock = crate::LifecycleClock::new(crate::FixedLifecycleClockSource::new(
        positron_domain::time::UnixNanoseconds::new(102_000_000_000),
    ));
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        &clock,
    )?;
    let resumed = reopened.resume_snapshot_lease(identity, 102)?;
    assert_eq!(resumed.snapshot().catalog_identity(), original_identity);
    assert_eq!(
        resumed
            .snapshot()
            .blocks()
            .first()
            .ok_or("reopened pinned block")?
            .payload(),
        b"historically-pinned"
    );
    drop(resumed);
    reopened.release_snapshot_lease(identity)?;
    let failure = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        scope.tenant_id(),
        &successor()?,
    )
    .err()
    .ok_or("live historical snapshot permitted retirement")?;
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    drop(original_snapshot);
    // The two reopen calls produced a sealed and an active successor segment.
    // Bounded maintenance authenticates both and publishes their Catalog routes;
    // false means no predecessor key was migrated, not absence of publication.
    assert_eq!(
        catalog
            .pin()?
            .next_unmigrated_ledger_scope(scope.tenant_id(), 2)?,
        Some(scope)
    );
    let before = catalog.pin()?.number();
    assert!(!ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        TransactionId::new([0xf3; 16])?,
        None,
    )?);
    assert_eq!(catalog.pin()?.number(), before + 1);
    assert_eq!(
        catalog
            .pin()?
            .next_unmigrated_ledger_scope(scope.tenant_id(), 2)?,
        Some(scope)
    );
    assert!(!ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        TransactionId::new([0xf5; 16])?,
        None,
    )?);
    assert_eq!(catalog.pin()?.number(), before + 2);
    assert_eq!(
        catalog
            .pin()?
            .next_unmigrated_ledger_scope(scope.tenant_id(), 2)?,
        None
    );
    assert!(!ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        TransactionId::new([0xf4; 16])?,
        None,
    )?);
    assert_eq!(catalog.pin()?.number(), before + 2);
    let _guard = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        scope.tenant_id(),
        &successor()?,
    )
    .map_err(|failure| format!("final historical-reference guard: {failure:?}"))?;
    Ok(())
}

#[test]
fn encrypted_predecessor_capabilities_block_proof_and_successor_only_capabilities_do_not()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let secrets = root.path().join("secrets");
    std::fs::create_dir(&secrets)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
    let custody = crate::BootstrapKeyCustody::initialize(&secrets)?;
    let session = crate::RootRewrapSession::admit(&authority)?;
    let first = custody.provision_tenant_key_envelope(instance, tenant, [0xe3; 16], 1)?;
    let custody = session.lease_system(
        custody,
        instance,
        crate::key_provider::KeyCacheLease::default(),
    )?;
    let catalog = Catalog::open(&authority, instance, custody.catalog_secret(instance)?)?;
    let prepared = session.prepare_tenant_envelope(&custody, instance, tenant, &first)?;
    let active = session.activate_tenant_envelope(&custody, instance, tenant, &prepared)?;
    let retained = session.tenant_segment_key(&custody, instance, scope, &active)?;
    assert_eq!(ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority, &catalog, tenant, &retained,
    ).err().ok_or("retained predecessor capability permitted proof")?.code(), LedgerFailureCode::ConcurrentWriter);
    let only_active = session.retain_active_tenant_envelope(&custody, instance, tenant, &active)?;
    let successor = session.tenant_segment_key(&custody, instance, scope, &only_active)?;
    drop(retained);
    let pending = session.prepare_tenant_envelope(&custody, instance, tenant, &only_active)?;
    let future = session.tenant_segment_key(&custody, instance, scope, &pending)?;
    assert_eq!(
        ActiveSegmentLedger::guard_tenant_epoch_retirement(
            &authority, &catalog, tenant, &successor,
        )
        .err()
        .ok_or("unproved future epoch permitted retirement")?
        .code(),
        LedgerFailureCode::ConcurrentWriter
    );
    drop(future);
    let guard = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority, &catalog, tenant, &successor,
    )?;
    assert!(
        session
            .tenant_segment_key(&custody, instance, scope, &active)
            .is_err()
    );
    assert!(
        session
            .tenant_segment_key(&custody, instance, scope, &only_active)
            .is_err()
    );
    drop(guard);
    let _reacquired = session.tenant_segment_key(&custody, instance, scope, &only_active)?;
    Ok(())
}

#[test]
fn durable_operation_with_unproved_input_refuses_epoch_retirement_after_reopen()
-> Result<(), Box<dyn Error>> {
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
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa3; 16])?,
            crate::FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                b"retirement-reference-fixture".to_vec(),
            )?],
        )?,
        None,
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let coordinator = crate::MaintenanceCoordinator::new();
    let task = crate::MaintenanceTask::with_contract(
        crate::MaintenanceTaskId::new([0xa1; 16]).map_err(|_| "task identity")?,
        crate::MaintenanceTaskClass::SchemaStatistics,
        crate::MaintenanceScope::tenant(tenant),
        crate::MaintenanceTrigger::Event,
        crate::MaintenancePreconditions::new(catalog.pin()?.number(), 1)
            .map_err(|_| "preconditions")?,
        vec![crate::MaintenanceObjectId::new([0xa2; 32]).map_err(|_| "input identity")?],
        Vec::new(),
        crate::ResourceAmounts::new([1; 11]),
    )
    .map_err(|_| "task contract")?;
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .map_err(|failure| format!("task publication {failure:?}"))?;
    let before = catalog.pin()?.identity();
    let failure = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        tenant,
        &successor()?,
    )
    .err()
    .ok_or("unproved retained operation allowed retirement")?;
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    assert_eq!(catalog.pin()?.identity(), before);
    drop(catalog);
    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let failure = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &reopened,
        tenant,
        &successor()?,
    )
    .err()
    .ok_or("reopened unproved operation allowed retirement")?;
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    assert_eq!(reopened.pin()?.identity(), before);
    let original_task = crate::MaintenanceTaskId::new([0xa1; 16]).map_err(|_| "task identity")?;
    coordinator
        .cancel_and_persist(&reopened, original_task)
        .map_err(|_| "durable cancellation")?;
    assert!(
        ActiveSegmentLedger::guard_tenant_epoch_retirement(
            &authority,
            &reopened,
            tenant,
            &successor()?
        )
        .is_err()
    );
    // The existing coordinator has exactly 128 durable slots. Populate its
    // remaining 127 slots with explicitly cancelled records, then let ordinary
    // submission reclaim the oldest terminal record through its public path.
    for index in 0_u8..127 {
        let mut bytes = [0xb0; 16];
        bytes[15] = index;
        let identity =
            crate::MaintenanceTaskId::new(bytes).map_err(|_| "bounded fixture task identity")?;
        coordinator
            .submit_and_persist(
                &reopened,
                crate::MaintenanceTask::new(
                    identity,
                    crate::MaintenanceTaskClass::SchemaStatistics,
                ),
                u64::from(index) + 2,
            )
            .map_err(|_| "bounded task submission")?;
        coordinator
            .cancel_and_persist(&reopened, identity)
            .map_err(|_| "bounded task cancellation")?;
    }
    assert_eq!(
        coordinator
            .durable_records()
            .map_err(|_| "bounded inventory")?
            .len(),
        128
    );
    let replacement =
        crate::MaintenanceTaskId::new([0xb1; 16]).map_err(|_| "replacement task identity")?;
    coordinator
        .submit_and_persist(
            &reopened,
            crate::MaintenanceTask::new(replacement, crate::MaintenanceTaskClass::SchemaStatistics),
            129,
        )
        .map_err(|_| "terminal reference reclamation")?;
    assert!(coordinator.status(original_task).is_err());
    assert_eq!(
        coordinator
            .durable_records()
            .map_err(|_| "bounded inventory")?
            .len(),
        128
    );
    let _guard = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &reopened,
        tenant,
        &successor()?,
    )?;
    Ok(())
}
