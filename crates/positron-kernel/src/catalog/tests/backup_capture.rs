use super::support::establish_catalog_authority_with_pool_units;
use crate::*;

#[test]
fn backup_capture_is_encrypted_bound_to_one_generation_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-backup-capture-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&path)?;
    let authority = establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&path, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let instance = InstanceId::new([1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([4; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(b"metadata without secrets".to_vec())?],
        )?,
        Some(AuditIntent::new(b"capture fixture".to_vec())?),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([5; 16]).expect("task ID"),
        MaintenanceTaskClass::BackupSnapshot,
        MaintenanceScope::System,
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        vec![],
        vec![],
        ResourceAmounts::new([25_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, 25_000_000]),
    )
    .expect("task");
    coordinator.submit(task).expect("submit");
    let execution = coordinator
        .start_next_with_reservation(&authority, 1, false)
        .expect("admit")
        .ok_or("execution")?;
    let estimate = catalog.backup_capture_resource_estimate(32)?;
    assert!(estimate.resources().get(ResourceDimension::MemoryBytes) < 25_000_000);
    assert_eq!(
        estimate.retained_memory_bytes() + estimate.copy_buffer_bytes(),
        estimate.resources().get(ResourceDimension::MemoryBytes)
    );
    assert_eq!(estimate.copy_buffer_bytes(), 4 * 1024 * 1024);
    assert!(
        estimate
            .resources()
            .get(ResourceDimension::DiskHeadroomBytes)
            >= 1420
    );
    let basis = catalog.pin()?;
    let capture = finish(
        catalog.prepare_backup_capture(
            &execution,
            [6; 16],
            [7; 32],
            &basis,
            &[BackupCatalogObject::new(
                basis.object_identities().next().ok_or("object identity")?,
                CatalogObject::new(b"metadata without secrets".to_vec())?,
            )],
            custody(instance, None)?
                .with_registry_checkpoint(b"exact protected envelope state".to_vec())?,
        )?,
    )?;
    assert_eq!(
        catalog.backup_capture_registry_checkpoint(&capture)?,
        b"exact protected envelope state"
    );
    assert!(catalog.has_backup_capture_references()?);
    assert!(catalog.release_backup_capture([9; 16], [7; 32])?);
    assert!(catalog.release_backup_capture([6; 16], [8; 32]).is_err());
    assert!(ActiveSegmentLedger::guard_local_root_retirement(&authority, &catalog).is_err());
    assert_eq!(capture.catalog_generation(), 1);
    assert_eq!(capture.catalog_identity(), basis.identity().to_bytes());
    assert!(capture.files().len() >= 2);
    let file = *capture.files().first().ok_or("catalog file")?;
    let encrypted = capture.read(file.identity(), 0, file.size())?;
    assert!(
        !encrypted
            .windows(24)
            .any(|bytes| bytes == b"metadata without secrets")
    );
    let index = capture.index_file()?;
    let index_bytes = capture.read(index.identity(), 0, index.size())?;
    // Offline restore authenticates the portable capture before opening a
    // writable target Catalog. Source custody is the only decryption authority.
    let secret = CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32]));
    let mut detached =
        BackupCaptureVerification::open(instance, &secret, [6; 16], [7; 32], &index_bytes)?;
    assert!(
        BackupCaptureVerification::open(
            InstanceId::new([99; 16])?,
            &secret,
            [6; 16],
            [7; 32],
            &index_bytes
        )
        .is_err()
    );
    // The marker MAC key is independent of capture envelope wrapping custody.
    let marker_only = CatalogSecret::from_owned(Box::new([99; 32]), Box::new([3; 32]));
    assert!(
        BackupCaptureVerification::open(instance, &marker_only, [6; 16], [7; 32], &index_bytes)
            .is_ok()
    );
    let wrong = CatalogSecret::from_owned(Box::new([2; 32]), Box::new([99; 32]));
    assert!(
        BackupCaptureVerification::open(instance, &wrong, [6; 16], [7; 32], &index_bytes).is_err()
    );
    for file in capture.files().iter().filter(|file| {
        matches!(
            file.kind(),
            BackupCaptureFileKind::CatalogObject
                | BackupCaptureFileKind::GovernanceAudit
                | BackupCaptureFileKind::AuditCheckpoint
        )
    }) {
        detached.verify_protected_file(
            &secret,
            file.identity(),
            &capture.read(file.identity(), 0, file.size())?,
        )?;
    }
    let origin = detached.finish_restore_origin([0x41; 32], [0x43; 32])?;
    assert_eq!(origin.snapshot().identity(), basis.identity());
    let objects = origin
        .snapshot()
        .object_identities()
        .map(|id| {
            CatalogObject::new(
                origin
                    .snapshot()
                    .object(id)?
                    .ok_or("source object")?
                    .to_vec(),
            )
            .map_err(Box::<dyn std::error::Error>::from)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let origin = origin.with_restored_objects(objects)?;

    let target = path.join("target");
    std::fs::create_dir(&target)?;
    let target_authority = establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&target, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let restored = Catalog::open(
        &target_authority,
        instance,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    let restored_origin = restored.install_restore_origin(origin)?;
    assert_eq!(restored.restore_origin_intent()?, Some([0x43; 32]));
    assert_ne!(restored.pin()?.identity(), basis.identity());
    assert_eq!(restored.governance_audit_records()?.len(), 1);
    assert_eq!(
        restored
            .governance_audit_records()?
            .first()
            .ok_or("imported audit")?
            .intent(),
        b"capture fixture"
    );
    drop(restored);
    let restored = Catalog::open(
        &target_authority,
        instance,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    assert_eq!(restored.pin()?.identity(), restored_origin.identity());
    assert_eq!(restored.restore_origin_intent()?, Some([0x43; 32]));
    restored.commit(
        restored.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0x42; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(b"restored metadata successor".to_vec())?],
        )?,
        Some(AuditIntent::new(b"restore successor".to_vec())?),
    )?;
    drop(restored);
    let restored = Catalog::open(
        &target_authority,
        instance,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    assert_eq!(restored.governance_audit_records()?.len(), 2);
    assert_eq!(restored.pin()?.governance_audit_frontier(), 2);
    restored.rewrap(
        TransactionId::new([0x43; 16])?,
        CatalogWrappingKey::from_owned_at_epoch(Box::new([9; 32]), [9; 16], 2)?,
        AuditIntent::new(b"restored instance root rewrap".to_vec())?,
    )?;
    drop(restored);
    let read_only = Catalog::read_current_view(
        &target_authority,
        instance,
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([9; 32]), [9; 16], 2)?,
    )?;
    assert_eq!(read_only.governance_audit_records().len(), 5);
    assert_eq!(
        read_only
            .governance_audit_records()
            .first()
            .ok_or("original source audit")?
            .intent(),
        b"capture fixture"
    );
    drop(read_only);
    assert!(
        Catalog::read_current_view(
            &target_authority,
            instance,
            CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32]))
        )
        .is_err()
    );
    drop(target_authority);
    let mut verification =
        catalog.begin_backup_capture_verification([6; 16], [7; 32], &index_bytes)?;
    let prospective = verification.prospective_memory_bytes()?;
    assert!(prospective < BackupCaptureVerification::required_memory_bytes()?);
    let initial_retained = verification.retained_memory_bytes()?;
    assert!(initial_retained > 0);
    assert!(initial_retained <= prospective);
    assert!(initial_retained <= BackupCaptureVerification::required_memory_bytes()?);
    let metadata = verification
        .files()
        .iter()
        .filter(|file| {
            matches!(
                file.kind(),
                BackupCaptureFileKind::CatalogObject
                    | BackupCaptureFileKind::GovernanceAudit
                    | BackupCaptureFileKind::AuditCheckpoint
            )
        })
        .copied()
        .collect::<Vec<_>>();
    assert!(
        catalog
            .begin_backup_capture_verification([6; 16], [8; 32], &index_bytes)
            .is_err()
    );
    let incomplete = catalog.begin_backup_capture_verification([6; 16], [7; 32], &index_bytes)?;
    assert!(incomplete.finish().is_err());
    for file in metadata {
        let bytes = capture.read(file.identity(), 0, file.size())?;
        let mut corrupted = bytes.clone();
        if let Some(byte) = corrupted.last_mut() {
            *byte ^= 1;
        }
        assert!(
            verification
                .verify_file(&catalog, file.identity(), &corrupted)
                .is_err()
        );
        verification.verify_file(&catalog, file.identity(), &bytes)?;
        assert!(
            verification
                .verify_file(&catalog, file.identity(), &bytes)
                .is_err()
        );
    }
    assert!(verification.retained_memory_bytes()? > initial_retained);
    assert!(verification.retained_memory_bytes()? <= prospective);
    assert_eq!(verification.prospective_memory_bytes()?, prospective);
    assert!(
        verification.retained_memory_bytes()?
            <= BackupCaptureVerification::required_memory_bytes()?
    );
    let verified = verification.finish()?;
    assert_eq!(verified.identity(), basis.identity());
    assert_eq!(verified.object_count(), basis.object_count());
    assert_eq!(
        verified.governance_audit_frontier(),
        basis.governance_audit_frontier()
    );
    drop(capture);
    let reopened = catalog.open_backup_capture([6; 16], [7; 32])?;
    assert_eq!(reopened.catalog_identity(), basis.identity().to_bytes());
    assert_eq!(
        catalog.backup_capture_registry_checkpoint(&reopened)?,
        b"exact protected envelope state"
    );
    assert_eq!(reopened.read(file.identity(), 0, file.size())?, encrypted);
    assert!(catalog.open_backup_capture([6; 16], [8; 32]).is_err());
    drop(reopened);
    while !catalog.release_backup_capture([6; 16], [7; 32])? {}
    assert!(!catalog.has_backup_capture_references()?);
    assert!(ActiveSegmentLedger::guard_local_root_retirement(&authority, &catalog).is_ok());
    assert!(catalog.release_backup_capture([6; 16], [7; 32])?);
    drop(execution);
    drop(catalog);
    drop(authority);
    std::fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn backup_capture_rejects_active_files_and_retains_sealed_ciphertext_after_live_unlink()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::{
        identity::TenantId,
        routing::{SignalKind, VirtualShardId},
    };
    let path = std::env::temp_dir().join(format!(
        "positron-backup-segments-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&path)?;
    let authority = establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&path, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([1; 16])?,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x43; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([4; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([5; 16])?,
        b"committed telemetry".to_vec(),
    )?)?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([6; 16]).expect("id"),
        MaintenanceTaskClass::BackupSnapshot,
        MaintenanceScope::System,
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        vec![],
        vec![],
        ResourceAmounts::new([25_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, 25_000_000]),
    )
    .expect("task");
    coordinator.submit(task).expect("submit");
    let execution = coordinator
        .start_next_with_reservation(&authority, 1, false)
        .expect("admit")
        .ok_or("execution")?;
    let objects =
        |basis: &CatalogSnapshot| -> Result<Vec<BackupCatalogObject>, Box<dyn std::error::Error>> {
            basis
                .object_identities()
                .map(|id| {
                    Ok(BackupCatalogObject::new(
                        id,
                        CatalogObject::new(basis.object(id)?.ok_or("object")?.to_vec())?,
                    ))
                })
                .collect()
        };
    let active = catalog.pin()?;
    assert!(
        catalog
            .prepare_backup_capture(
                &execution,
                [7; 16],
                [8; 32],
                &active,
                &objects(&active)?,
                custody(InstanceId::new([1; 16])?, Some(scope))?
            )
            .is_err()
    );
    ledger.seal()?;
    let sealed = catalog.pin()?;
    // Authenticated ciphertext and a complete inventory are insufficient when
    // the captured metadata is malformed or leaves segment files unreachable.
    for (operation, replacement) in [
        ([0x71; 16], b"PSEGMET1".as_slice()),
        ([0x72; 16], b"ordinary opaque metadata".as_slice()),
    ] {
        let sanitized = sealed
            .object_identities()
            .map(|identity| {
                Ok(BackupCatalogObject::new(
                    identity,
                    CatalogObject::new(replacement.to_vec())?,
                ))
            })
            .collect::<Result<Vec<_>, CatalogFailure>>()?;
        let invalid = finish(catalog.prepare_backup_capture(
            &execution,
            operation,
            [8; 32],
            &sealed,
            &sanitized,
            custody(InstanceId::new([1; 16])?, Some(scope))?,
        )?)?;
        let index = invalid.index_file()?;
        let mut verification = catalog.begin_backup_capture_verification(
            operation,
            [8; 32],
            &invalid.read(index.identity(), 0, index.size())?,
        )?;
        let metadata = verification
            .files()
            .iter()
            .filter(|file| {
                matches!(
                    file.kind(),
                    BackupCaptureFileKind::CatalogObject
                        | BackupCaptureFileKind::GovernanceAudit
                        | BackupCaptureFileKind::AuditCheckpoint
                )
            })
            .copied()
            .collect::<Vec<_>>();
        for file in metadata {
            verification.verify_file(
                &catalog,
                file.identity(),
                &invalid.read(file.identity(), 0, file.size())?,
            )?;
        }
        assert!(verification.finish().is_err());
        drop(invalid);
        while !catalog.release_backup_capture(operation, [8; 32])? {}
    }
    let mut preparation = catalog.prepare_backup_capture(
        &execution,
        [7; 16],
        [8; 32],
        &sealed,
        &objects(&sealed)?,
        custody(InstanceId::new([1; 16])?, Some(scope))?,
    )?;
    assert!(preparation.copy_step(1)?.is_none());
    // The prepared capture owns immutable source handles, so live ingest and
    // snapshots continue while its bounded copy is between worker turns.
    let live = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([4; 32])),
    )?;
    live.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([9; 16])?,
        b"later telemetry".to_vec(),
    )?)?;
    assert_eq!(live.snapshot()?.blocks().len(), 2);
    drop(live);
    for entry in std::fs::read_dir(path.join("segments/sealed"))? {
        std::fs::remove_file(entry?.path())?;
    }
    let capture = finish(preparation)?;
    assert_eq!(capture.catalog_identity(), sealed.identity().to_bytes());
    let index = capture.index_file()?;
    let mut verification = catalog.begin_backup_capture_verification(
        [7; 16],
        [8; 32],
        &capture.read(index.identity(), 0, index.size())?,
    )?;
    let metadata = verification
        .files()
        .iter()
        .filter(|file| {
            matches!(
                file.kind(),
                BackupCaptureFileKind::CatalogObject
                    | BackupCaptureFileKind::GovernanceAudit
                    | BackupCaptureFileKind::AuditCheckpoint
            )
        })
        .copied()
        .collect::<Vec<_>>();
    for file in metadata {
        verification.verify_file(
            &catalog,
            file.identity(),
            &capture.read(file.identity(), 0, file.size())?,
        )?;
    }
    let origin = verification.finish_restore_origin([0x75; 32], [0x76; 32])?;
    assert_eq!(origin.snapshot().identity(), sealed.identity());
    let target = path.join("restored");
    std::fs::create_dir(&target)?;
    let target_authority = establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&target, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let restored = Catalog::open(
        &target_authority,
        InstanceId::new([1; 16])?,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    restored.install_restore_origin(origin)?;
    for file in capture
        .files()
        .iter()
        .filter(|file| {
            matches!(
                file.kind(),
                BackupCaptureFileKind::Segment | BackupCaptureFileKind::SegmentFrontier
            )
        })
        .copied()
    {
        let ciphertext = capture.read(file.identity(), 0, file.size())?;
        let split = ciphertext.len() / 2;
        assert!(!restored.restore_segment_range(file, 0, &ciphertext[..split])?);
        assert!(!restored.restore_segment_range(file, 0, &ciphertext[..split])?);
        let mut wrong = ciphertext[..split].to_vec();
        *wrong.first_mut().ok_or("nonempty range")? ^= 1;
        assert!(restored.restore_segment_range(file, 0, &wrong).is_err());
        assert!(restored.restore_segment_range(file, split as u64, &ciphertext[split..])?);
        assert!(restored.restore_segment_range(file, 0, &ciphertext)?);
    }
    let reopened = ActiveSegmentLedger::open(
        &target_authority,
        &restored,
        scope,
        SegmentProtectionKey::from_owned(Box::new([4; 32])),
    )?;
    assert_eq!(reopened.snapshot()?.blocks().len(), 1);
    drop(reopened);
    drop(restored);
    drop(target_authority);

    let file = *capture
        .files()
        .iter()
        .find(|file| file.kind() == BackupCaptureFileKind::Segment)
        .ok_or("captured segment")?;
    let encrypted = capture.read(file.identity(), 0, file.size())?;
    assert!(
        !encrypted
            .windows(19)
            .any(|bytes| bytes == b"committed telemetry")
    );
    drop(capture);
    let recovered = catalog.open_backup_capture([7; 16], [8; 32])?;
    assert_eq!(recovered.read(file.identity(), 0, file.size())?, encrypted);
    assert!(recovered.read(file.identity(), file.size(), 1).is_err());
    drop(recovered);
    drop(execution);
    drop(catalog);
    drop(authority);
    std::fs::remove_dir_all(path)?;
    Ok(())
}

fn finish(mut preparation: BackupCapturePreparation) -> Result<BackupCapture, CatalogFailure> {
    loop {
        if let Some(capture) = preparation.copy_step(4 * 1024 * 1024)? {
            return Ok(capture);
        }
    }
}

fn custody(
    instance: InstanceId,
    scope: Option<SegmentScope>,
) -> Result<BackupCaptureCustody, CatalogFailure> {
    let keys = scope
        .into_iter()
        .map(|scope| (scope, SegmentProtectionKey::from_owned(Box::new([4; 32]))))
        .collect();
    BackupCaptureCustody::new(
        instance,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
        keys,
    )
}

#[test]
fn backup_capture_refuses_one_byte_short_before_writing_and_accepts_exact_protected_footprint()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-backup-budget-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&path)?;
    let authority = establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&path, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let instance = InstanceId::new([1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([4; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(b"metadata without secrets".to_vec())?],
        )?,
        Some(AuditIntent::new(b"capture fixture".to_vec())?),
    )?;
    let basis = catalog.pin()?;
    let objects = [BackupCatalogObject::new(
        basis.object_identities().next().ok_or("object identity")?,
        CatalogObject::new(b"metadata without secrets".to_vec())?,
    )];
    let insufficient = capture_execution(&authority, 1419)?;
    let failure = catalog
        .prepare_backup_capture(
            &insufficient,
            [0xa1; 16],
            [0xa2; 32],
            &basis,
            &objects,
            custody(instance, None)?,
        )
        .expect_err("one byte short");
    assert_eq!(failure.code(), CatalogFailureCode::ResourceAdmissionRefused);
    assert!(
        !path.join("backup-captures").exists(),
        "admission must precede capture filesystem mutation"
    );
    drop(insufficient);
    let exact = capture_execution(&authority, 1420)?;
    let preparation = catalog.prepare_backup_capture(
        &exact,
        [0xa1; 16],
        [0xa2; 32],
        &basis,
        &objects,
        custody(instance, None)?,
    )?;
    let capture = finish(preparation)?;
    assert_eq!(
        capture.files().iter().map(|file| file.size()).sum::<u64>(),
        1420
    );
    drop(capture);
    drop(exact);
    drop(catalog);
    drop(authority);
    std::fs::remove_dir_all(path)?;
    Ok(())
}
fn capture_execution(
    authority: &StorageKernelResourceAuthority,
    disk: u64,
) -> Result<MaintenanceExecution<'_>, Box<dyn std::error::Error>> {
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0xa3; 16]).expect("ID"),
        MaintenanceTaskClass::BackupSnapshot,
        MaintenanceScope::System,
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        vec![],
        vec![],
        ResourceAmounts::new([25_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, disk]),
    )
    .expect("task");
    coordinator.submit(task).expect("submit");
    coordinator
        .start_next_with_reservation(authority, 1, false)
        .expect("admit")
        .ok_or_else(|| "execution".into())
}
#[test]
fn backup_capture_refuses_corrupted_segment_or_frontier_before_index_publication()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::{
        identity::TenantId,
        routing::{SignalKind, VirtualShardId},
    };
    for extension in ["segment", "frontier"] {
        let path = std::env::temp_dir().join(format!(
            "positron-backup-corrupt-{}-{extension}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir(&path)?;
        let authority = establish_catalog_authority_with_pool_units(
            PrimaryDataVolume::acquire(&path, MountQualification::LocalHost)?,
            70_000_001,
            30_000_000,
        )?;
        let instance = InstanceId::new([1; 16])?;
        let catalog = Catalog::open(
            &authority,
            instance,
            CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
        )?;
        let scope = SegmentScope::new(
            TenantId::from_bytes([0x43; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(1)?,
        );
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([4; 32])),
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([5; 16])?,
            b"authenticated telemetry".to_vec(),
        )?)?;
        ledger.seal()?;
        let original_path = std::fs::read_dir(path.join("segments/sealed"))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|path| path.extension().is_some_and(|value| value == extension))
            .ok_or("source file")?;
        let original = std::fs::read(&original_path)?;
        let mut corrupted = original.clone();
        *corrupted.last_mut().ok_or("ciphertext")? ^= 1;
        std::fs::write(&original_path, &corrupted)?;
        let basis = catalog.pin()?;
        let objects = basis
            .object_identities()
            .map(|id| {
                Ok(BackupCatalogObject::new(
                    id,
                    CatalogObject::new(basis.object(id)?.ok_or("object")?.to_vec())?,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let execution = capture_execution(&authority, 25_000_000)?;
        let preparation = catalog.prepare_backup_capture(
            &execution,
            [0xa4; 16],
            [0xa5; 32],
            &basis,
            &objects,
            custody(instance, Some(scope))?,
        )?;
        let failure = finish(preparation).expect_err("AEAD or authenticated frontier corruption");
        assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
        assert!(
            catalog.open_backup_capture([0xa4; 16], [0xa5; 32]).is_err(),
            "corruption cannot publish a capture index"
        );
        std::fs::write(&original_path, original)?;
        let retry = finish(catalog.prepare_backup_capture(
            &execution,
            [0xa4; 16],
            [0xa5; 32],
            &basis,
            &objects,
            custody(instance, Some(scope))?,
        )?)?;
        assert!(retry.files().iter().all(|file| file.checksum() != [0; 32]));
        drop(retry);
        drop(execution);
        drop(catalog);
        drop(authority);
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}
