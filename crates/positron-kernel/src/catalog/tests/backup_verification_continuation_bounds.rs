//! Legal native capture limits survive authenticated continuation publication.
use super::*;
use sha2::{Digest, Sha256};

#[test]
fn initial_continuation_admission_covers_every_native_prefix_and_completed_catalog()
-> Result<(), Box<dyn std::error::Error>> {
    round_trip(8, 32, 2, 64)
}

#[test]
fn continuation_preserves_the_full_native_audit_intent_limit()
-> Result<(), Box<dyn std::error::Error>> {
    round_trip(256, 65_536, 1, 32)
}

#[test]
fn continuation_preserves_high_cardinality_audit_and_catalog_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    round_trip(32_768, 512, 16, 1_048_576)
}

fn round_trip(
    records: u64,
    intent_bytes: usize,
    object_count: usize,
    object_bytes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!(
        "positron-continuation-bounds-{records}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&directory)?;
    let instance = InstanceId::new([1; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32]));
    let capture_operation = [6; 16];
    let capture_request = [7; 32];
    let epoch = FormatEpoch::CATALOG_V2;
    let source_catalog = [8; 32];
    let mut files = Vec::new();
    let mut protect = |kind, address, plaintext: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
        let ciphertext = crate::catalog::storage::artifact::protect_backup_capture(
            &secret(),
            instance,
            address,
            epoch,
            plaintext,
        )?;
        let descriptor = BackupCaptureFile::new(kind, address, u64::try_from(ciphertext.len())?)?;
        files.push((descriptor, ciphertext));
        Ok(())
    };
    for number in 0..object_count {
        let mut plaintext = vec![b'x'; object_bytes];
        plaintext
            .get_mut(..8)
            .ok_or("object counter")?
            .copy_from_slice(&u64::try_from(number)?.to_be_bytes());
        let object = CatalogObject::new(plaintext.clone())?;
        protect(
            BackupCaptureFileKind::CatalogObject,
            object.identity().to_bytes(),
            &plaintext,
        )?;
    }
    let mut frontier = crate::catalog::types::AuditFrontier::ORIGIN;
    let intent = vec![b'a'; intent_bytes];
    for number in 1..=records {
        let mut transaction = [0; 16];
        transaction
            .get_mut(..8)
            .ok_or("transaction counter")?
            .copy_from_slice(&number.to_be_bytes());
        let (record, plaintext) = crate::catalog::codec::prepare_audit(
            frontier,
            TransactionId::new(transaction)?,
            &intent,
        )?;
        protect(
            BackupCaptureFileKind::GovernanceAudit,
            record.record_hash(),
            &plaintext,
        )?;
        frontier = crate::catalog::types::AuditFrontier {
            position: record.position(),
            hash: record.record_hash(),
        };
    }
    files.sort_by_key(|(descriptor, _)| descriptor.identity());
    let mut inventory = b"POSBCP01".to_vec();
    inventory.extend_from_slice(&capture_operation);
    inventory.extend_from_slice(&capture_request);
    inventory.extend_from_slice(&1_u64.to_be_bytes());
    inventory.extend_from_slice(&source_catalog);
    inventory.extend_from_slice(&epoch.value().to_be_bytes());
    inventory.extend_from_slice(&records.to_be_bytes());
    inventory.extend_from_slice(&u32::try_from(files.len())?.to_be_bytes());
    for (descriptor, ciphertext) in &files {
        inventory.extend_from_slice(&descriptor.identity());
        inventory.push(match descriptor.kind() {
            BackupCaptureFileKind::CatalogObject => 1,
            BackupCaptureFileKind::GovernanceAudit => 2,
            _ => return Err("unexpected fixture file".into()),
        });
        inventory.extend_from_slice(&descriptor.address());
        inventory.extend_from_slice(&descriptor.size().to_be_bytes());
        inventory.extend_from_slice(&Sha256::digest(ciphertext));
    }
    let mut identity = Sha256::new();
    identity.update(b"positron-backup-capture-index-v1\0");
    identity.update(capture_operation);
    identity.update(capture_request);
    let encrypted_index = crate::catalog::storage::artifact::protect_backup_capture(
        &secret(),
        instance,
        identity.finalize().into(),
        epoch,
        &inventory,
    )?;
    drop(inventory);
    let mut index = b"POSBCI01".to_vec();
    index.extend_from_slice(&epoch.value().to_be_bytes());
    index.extend_from_slice(&encrypted_index);
    drop(encrypted_index);
    let native = BackupCaptureVerification::open(
        instance,
        &secret(),
        capture_operation,
        capture_request,
        &index,
    )?;
    let mut progress = BackupVerificationProgress {
        native: BackupVerificationNativeState::Metadata(Box::new(native)),
        semantic: Vec::new(),
    };
    let resources = progress.prospective_continuation_resources(&index)?;
    let file_count = files.len();
    for (offset, (descriptor, ciphertext)) in files.into_iter().enumerate() {
        let BackupVerificationNativeState::Metadata(native) = &mut progress.native else {
            return Err("native metadata phase".into());
        };
        native.verify_protected_file(&secret(), descriptor.identity(), &ciphertext)?;
        // The small regression checks every prefix; legal-limit fixtures sample
        // prefixes without adding quadratic estimator work to the test itself.
        if file_count <= 64 || offset % 1024 == 0 || offset + 1 == file_count {
            let required = progress.continuation_resources(&index)?;
            for dimension in ResourceDimension::ALL {
                assert!(
                    resources.get(dimension) >= required.get(dimension),
                    "initial admission must cover native prefix {offset}: {dimension:?}"
                );
            }
        }
    }
    progress.semantic = vec![0; 65_536];
    let required = progress.continuation_resources(&index)?;
    for dimension in ResourceDimension::ALL {
        assert!(
            resources.get(dimension) >= required.get(dimension),
            "initial admission must cover maximum semantic progress: {dimension:?}"
        );
    }
    progress.semantic.push(0);
    assert!(progress.prospective_continuation_resources(&index).is_err());
    assert!(progress.continuation_resources(&index).is_err());
    assert_eq!(progress.semantic.pop(), Some(0));
    let unit = resources
        .get(ResourceDimension::MemoryBytes)
        .max(resources.get(ResourceDimension::DiskHeadroomBytes))
        .max(70_000_001);
    let authority = establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&directory, MountQualification::LocalHost)?,
        70_000_001,
        unit,
    )?;
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([9; 16])?,
            epoch,
            vec![CatalogObject::new(b"continuation boundary owner".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let owner = RepositoryOperationBinding::new([0x41; 16], [0x42; 32])
        .map_err(|failure| format!("binding: {failure:?}"))?;
    let reservation = ResourceAmounts::new([
        resources
            .get(ResourceDimension::MemoryBytes)
            .max(4 * 1024 * 1024),
        1,
        1,
        0,
        1,
        0,
        1,
        1,
        1,
        8,
        resources
            .get(ResourceDimension::DiskHeadroomBytes)
            .max(16_384),
    ]);
    let task = coordinator
        .submit_backup_operation_with_resources_and_persist(
            &catalog,
            owner,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .map_err(|failure| format!("preconditions: {failure:?}"))?,
            reservation,
            7,
        )
        .map_err(|failure| format!("submit: {failure:?}"))?;
    let mut execution = coordinator
        .start_backup_operation_with_reservation_and_persist(
            &catalog,
            &authority,
            8,
            false,
            task.identity(),
        )
        .map_err(|failure| format!("dispatch: {failure:?}"))?
        .ok_or("execution")?;
    let binding = BackupVerificationBinding {
        operation: owner.operation_id(),
        intent: owner.intent_digest(),
        capture_operation,
        capture_request,
        manifest: [0x51; 32],
        index: Sha256::digest(&index).into(),
        registry: [0x52; 32],
    };
    let reference = catalog.persist_backup_verification_continuation(
        &coordinator,
        &mut execution,
        binding,
        None,
        &index,
        &progress,
    )?;
    execution
        .checkpoint_and_persist(
            &coordinator,
            &catalog,
            owner
                .backup_verification_checkpoint(2, b"boundary verification", reference)
                .map_err(|failure| format!("checkpoint: {failure:?}"))?,
        )
        .map_err(|failure| format!("publish: {failure:?}"))?;
    drop((progress, catalog));
    let catalog = Catalog::open(&authority, instance, secret())?;
    let restored = catalog.resume_backup_verification_continuation(
        binding,
        reference,
        &index,
        execution.task().reservations(),
    )?;
    let BackupVerificationNativeState::Metadata(native) = restored.native else {
        return Err("native metadata continuation phase".into());
    };
    let snapshot = native.finish()?;
    let completed = BackupVerificationProgress {
        native: BackupVerificationNativeState::Catalog(snapshot.clone()),
        semantic: vec![0; 65_536],
    };
    let required = completed.continuation_resources(&index)?;
    for dimension in ResourceDimension::ALL {
        assert!(
            resources.get(dimension) >= required.get(dimension),
            "initial admission must cover completed Catalog: {dimension:?}"
        );
    }
    assert_eq!(snapshot.object_count(), object_count);
    assert_eq!(snapshot.governance_audit_frontier(), records);
    assert_eq!(snapshot.identity().to_bytes(), source_catalog);
    execution
        .checkpoint_and_persist(
            &coordinator,
            &catalog,
            owner
                .backup_checkpoint(3, b"boundary verification complete")
                .map_err(|failure| format!("clear checkpoint: {failure:?}"))?,
        )
        .map_err(|failure| format!("clear: {failure:?}"))?;
    while !catalog.release_backup_verification_continuation(&coordinator, &mut execution, owner)? {}
    execution
        .complete_and_persist(&coordinator, &catalog, true)
        .map_err(|failure| format!("complete: {failure:?}"))?;
    drop((snapshot, execution, catalog));
    drop(authority);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
