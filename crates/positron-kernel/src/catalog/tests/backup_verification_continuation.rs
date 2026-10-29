//! Public Capture continuation outcomes, including independent cold readers.
use super::*;
use sha2::{Digest, Sha256};

#[path = "backup_verification_continuation_faults.rs"]
mod faults;
#[path = "backup_verification_continuation_lifecycle.rs"]
mod lifecycle;

#[test]
fn partial_and_finished_verification_continuations_reopen_exact_authenticated_state()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-verification-continuation-{}",
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
    let secret = || CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([4; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(vec![b'm'; 1024 * 1024])?],
        )?,
        Some(AuditIntent::new(b"continuation audit".to_vec())?),
    )?;
    let basis = catalog.pin()?;
    let capture_execution = capture_execution(&authority, 25_000_000)?;
    let objects = basis
        .object_identities()
        .map(|identity| {
            Ok(BackupCatalogObject::new(
                identity,
                CatalogObject::new(basis.object(identity)?.ok_or("captured object")?.to_vec())?,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let capture = finish(catalog.prepare_backup_capture(
        &capture_execution,
        [6; 16],
        [7; 32],
        &basis,
        &objects,
        custody(instance, None)?,
    )?)?;
    drop(capture_execution);
    let index = capture.index_file()?;
    let index = capture.read(index.identity(), 0, index.size())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0x61; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(
                b"unrelated catalog generation".to_vec(),
            )?],
        )?,
        None,
    )?;
    let unrelated = catalog.pin()?;
    assert_eq!(
        unrelated.governance_audit_frontier(),
        basis.governance_audit_frontier()
    );
    let native_files = capture
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
    assert!(native_files.len() >= 2);
    let first = *native_files.first().ok_or("first native file")?;
    let coordinator = MaintenanceCoordinator::new();
    let owner = RepositoryOperationBinding::new([0x41; 16], [0x42; 32])
        .map_err(|failure| format!("owner: {failure:?}"))?;
    coordinator
        .submit_backup_operation_with_resources_and_persist(
            &catalog,
            owner,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .map_err(|failure| format!("preconditions: {failure:?}"))?,
            ResourceAmounts::new([25_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, 25_000_000]),
            7,
        )
        .map_err(|failure| format!("submit: {failure:?}"))?;
    let mut execution = coordinator
        .start_backup_operation_with_reservation_and_persist(
            &catalog,
            &authority,
            8,
            false,
            MaintenanceTaskId::new(owner.operation_id())
                .map_err(|failure| format!("task: {failure:?}"))?,
        )
        .map_err(|failure| format!("dispatch: {failure:?}"))?
        .ok_or("execution")?;
    let binding = BackupVerificationBinding {
        operation: owner.operation_id(),
        intent: owner.intent_digest(),
        capture_operation: [6; 16],
        capture_request: [7; 32],
        manifest: [0x51; 32],
        index: Sha256::digest(&index).into(),
        registry: [0x52; 32],
    };
    let empty = BackupVerificationProgress {
        native: BackupVerificationNativeState::Metadata(Box::new(
            catalog.begin_backup_capture_verification([6; 16], [7; 32], &index)?,
        )),
        semantic: Vec::new(),
    };
    faults::incomplete_owner_index(&catalog, binding.operation)?;
    let empty_reference = catalog
        .persist_backup_verification_continuation(
            &coordinator,
            &mut execution,
            binding,
            None,
            &index,
            &empty,
        )
        .map_err(|failure| {
            format!(
                "an uncommitted index.partial must recover without a new operation: {failure:?}"
            )
        })?;
    let mut ciphertext = Vec::new();
    std::io::Read::read_to_end(
        &mut continuation_file(&catalog, binding.operation, empty_reference.identity, false)?,
        &mut ciphertext,
    )?;
    let mut malformed = crate::catalog::storage::artifact::open_backup_capture(
        &secret(),
        instance,
        empty_reference.identity,
        FormatEpoch::CATALOG_V2,
        &ciphertext,
    )?;
    malformed.push(0);
    let malformed_identity: [u8; 32] = Sha256::digest(&malformed).into();
    let malformed_ciphertext = crate::catalog::storage::artifact::protect_backup_capture(
        &secret(),
        instance,
        malformed_identity,
        FormatEpoch::CATALOG_V2,
        &malformed,
    )?;
    std::io::Write::write_all(
        &mut continuation_file(&catalog, binding.operation, malformed_identity, true)?,
        &malformed_ciphertext,
    )?;
    let malformed_reference = BackupVerificationReference {
        identity: malformed_identity,
        ..empty_reference
    };
    let constrained = ResourceAmounts::new([16 * 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let failure = match catalog.resume_backup_verification_continuation(
        binding,
        malformed_reference,
        &index,
        constrained,
    ) {
        Ok(_) => return Err("underfunded native state was decoded".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.code(),
        CatalogFailureCode::ResourceAdmissionRefused,
        "large authenticated inventory must be admitted before the malformed native codec is decoded"
    );
    let failure = match catalog.resume_backup_verification_continuation(
        binding,
        malformed_reference,
        &index,
        execution.task().reservations(),
    ) {
        Ok(_) => return Err("trailing native codec byte accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.code(),
        CatalogFailureCode::IntegrityCorruption,
        "the full grant reaches the actual trailing-byte integrity rejection"
    );
    drop((empty, malformed, ciphertext, malformed_ciphertext));
    let mut native = catalog.begin_backup_capture_verification([6; 16], [7; 32], &index)?;
    native.verify_protected_file(
        &secret(),
        first.identity(),
        &capture.read(first.identity(), 0, first.size())?,
    )?;
    let partial = BackupVerificationProgress {
        native: BackupVerificationNativeState::Metadata(Box::new(native)),
        semantic: b"partial semantics".to_vec(),
    };
    let reference = catalog.persist_backup_verification_continuation(
        &coordinator,
        &mut execution,
        binding,
        None,
        &index,
        &partial,
    )?;
    assert_eq!(
        catalog.persist_backup_verification_continuation(
            &coordinator,
            &mut execution,
            binding,
            None,
            &index,
            &partial
        )?,
        reference,
        "a retry reuses the exact authenticated unpublished proposal"
    );
    let unrelated = BackupVerificationProgress {
        native: BackupVerificationNativeState::Catalog(unrelated),
        semantic: Vec::new(),
    };
    assert!(
        catalog
            .persist_backup_verification_continuation(
                &coordinator,
                &mut execution,
                binding,
                None,
                &index,
                &unrelated
            )
            .is_err(),
        "a valid unrelated Catalog generation cannot be relabeled as this signed capture"
    );
    drop((partial, catalog));
    let catalog = Catalog::open(&authority, instance, secret())?;
    let reopened = catalog.resume_backup_verification_continuation(
        binding,
        reference,
        &index,
        execution.task().reservations(),
    )?;
    assert_eq!(reopened.semantic, b"partial semantics");
    let BackupVerificationNativeState::Metadata(mut native) = reopened.native else {
        return Err("partial native phase".into());
    };
    for file in native_files
        .iter()
        .filter(|file| file.identity() != first.identity())
    {
        native.verify_protected_file(
            &secret(),
            file.identity(),
            &capture.read(file.identity(), 0, file.size())?,
        )?;
    }
    let snapshot = native.finish()?;
    assert_eq!(snapshot.identity(), basis.identity());
    let finished = BackupVerificationProgress {
        native: BackupVerificationNativeState::Catalog(snapshot),
        semantic: b"verified schema/key prefix".to_vec(),
    };
    let (sequence, _) = owner
        .current_backup_progress(&coordinator, &execution)
        .map_err(|failure| format!("current checkpoint: {failure:?}"))?;
    execution
        .checkpoint_and_persist(
            &coordinator,
            &catalog,
            owner
                .backup_verification_checkpoint(
                    sequence.checked_add(1).ok_or("checkpoint sequence")?,
                    b"existing handler progress",
                    reference,
                )
                .map_err(|failure| format!("checkpoint: {failure:?}"))?,
        )
        .map_err(|failure| format!("publish: {failure:?}"))?;
    assert!(
        catalog
            .persist_backup_verification_continuation(
                &coordinator,
                &mut execution,
                binding,
                None,
                &index,
                &finished
            )
            .is_err(),
        "a same-owner missing predecessor cannot reclaim the authenticated current artifact"
    );
    assert!(
        catalog
            .resume_backup_verification_continuation(
                binding,
                reference,
                &index,
                execution.task().reservations()
            )
            .is_ok()
    );
    let next = catalog.persist_backup_verification_continuation(
        &coordinator,
        &mut execution,
        binding,
        Some(reference),
        &index,
        &finished,
    )?;
    faults::reference_rejections(
        &catalog,
        binding,
        next,
        &index,
        execution.task().reservations(),
    )?;
    assert!(
        catalog
            .release_backup_verification_continuation(&coordinator, &mut execution, owner)
            .is_err(),
        "terminal cleanup cannot unlink the current authenticated Maintenance reference"
    );
    continuation_file(&catalog, binding.operation, next.identity, false)?.set_len(17)?;
    assert_eq!(
        catalog.persist_backup_verification_continuation(
            &coordinator,
            &mut execution,
            binding,
            Some(reference),
            &index,
            &finished
        )?,
        next,
        "an interrupted unpublished proposal is recomputed while the exact predecessor remains intact"
    );
    let old = catalog.resume_backup_verification_continuation(
        binding,
        reference,
        &index,
        execution.task().reservations(),
    )?;
    assert_eq!(
        old.semantic, b"partial semantics",
        "a candidate cannot replace its unpublished predecessor"
    );
    let exact = finished.continuation_resources(&index)?;
    assert!(
        catalog
            .resume_backup_verification_continuation(
                binding,
                next,
                &index,
                ResourceAmounts::new([
                    exact
                        .get(ResourceDimension::MemoryBytes)
                        .checked_sub(1)
                        .ok_or("one-byte-short")?,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    exact.get(ResourceDimension::DiskHeadroomBytes)
                ])
            )
            .is_err(),
        "an underfunded continuation must refuse before allocating its decoded state"
    );
    assert!(
        catalog
            .resume_backup_verification_continuation(binding, next, &index, exact)
            .is_ok(),
        "the exact advertised continuation admission must fund authenticated reopen"
    );
    let complete = catalog.resume_backup_verification_continuation(
        binding,
        next,
        &index,
        execution.task().reservations(),
    )?;
    let BackupVerificationNativeState::Catalog(snapshot) = complete.native else {
        return Err("finished native phase".into());
    };
    assert_eq!(snapshot.identity(), basis.identity());
    assert_eq!(
        snapshot.governance_audit_frontier(),
        basis.governance_audit_frontier()
    );
    drop((snapshot, old));
    let catalog = lifecycle::check(
        lifecycle::Fixture {
            catalog,
            authority: &authority,
            instance,
            coordinator: &coordinator,
            execution: &mut execution,
            owner,
            binding,
            index: &index,
            progress: &finished,
        },
        next,
    )?;
    drop(capture);
    while !catalog.release_backup_capture([6; 16], [7; 32])? {}
    assert!(!catalog.has_backup_capture_references()?);
    drop(execution);
    assert!(
        ActiveSegmentLedger::guard_local_root_retirement(&authority, &catalog).is_err(),
        "the terminal opaque record is still retained until its existing authenticated reclamation"
    );
    let session = RootRewrapSession::admit(&authority)?;
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .map_err(|failure| format!("terminal record reclamation: {failure:?}"))?,
        1
    );
    drop(session);
    assert!(ActiveSegmentLedger::guard_local_root_retirement(&authority, &catalog).is_ok());
    drop((finished, basis, catalog));
    drop(authority);
    std::fs::remove_dir_all(path)?;
    Ok(())
}

fn continuation_file(
    catalog: &Catalog<'_>,
    operation: [u8; 16],
    identity: [u8; 32],
    create: bool,
) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    let name = |value: &[u8]| {
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let path = format!("backup-captures/{}/f-{}", name(&operation), name(&identity));
    let mut flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    if create {
        flags |= rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL;
    }
    Ok(std::fs::File::from(rustix::fs::openat(
        catalog.export_output_root()?,
        path.as_str(),
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?))
}
