use snapshot_resources::native_authority;
#[path = "support/snapshot_resources.rs"]
mod snapshot_resources;
use positron_backup::{
    BackupKeyEnvelope, BackupManifestBuilder, BackupPublisher, BackupRetention, LocalRepository,
    Repository, RepositoryFailure, RepositoryIdentity,
};
use positron_kernel::*;

#[tokio::test]
async fn cold_capture_corruption_cannot_be_signed_as_a_fresh_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-manifest-capture-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&path)?;
    let resources = ResourceAmounts::new([25_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, 25_000_000]);
    let authority = native_authority::authority(&path, resources)?;
    let instance = InstanceId::new([1; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([4; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(b"captured metadata".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    coordinator
        .submit(
            MaintenanceTask::with_contract(
                MaintenanceTaskId::new([5; 16]).expect("task ID"),
                MaintenanceTaskClass::BackupSnapshot,
                MaintenanceScope::System,
                MaintenanceTrigger::Event,
                MaintenancePreconditions::new(1, 1).expect("preconditions"),
                vec![],
                vec![],
                resources,
            )
            .expect("task"),
        )
        .expect("submit");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 1, false)
        .expect("admit")
        .ok_or("execution")?;
    let basis = catalog.pin()?;
    let sanitized = basis
        .object_identities()
        .map(|id| {
            Ok(BackupCatalogObject::new(
                id,
                CatalogObject::new(basis.object(id)?.ok_or("object")?.to_vec())?,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let mut pending = catalog.prepare_backup_capture(
        &execution,
        [6; 16],
        [7; 32],
        &basis,
        &sanitized,
        BackupCaptureCustody::new(instance, secret(), vec![])?,
    )?;
    let capture = loop {
        if let Some(capture) = pending.copy_step(4 * 1024 * 1024)? {
            break capture;
        }
    };
    let secrets = path.join("secrets");
    std::fs::create_dir(&secrets)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
    }
    let custody = BootstrapKeyCustody::initialize(&secrets)?;
    let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
    let signer = custody.backup_control_signer(instance, &protected)?;
    let repository_path = path.join("repository");
    std::fs::create_dir(&repository_path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&repository_path, std::fs::Permissions::from_mode(0o700))?;
    }
    let repository = RepositoryIdentity::local(
        [8; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        &repository_path,
    )?;
    let port = LocalRepository::initialize(&repository_path, repository.clone()).await?;
    let build = |capture: &BackupCapture| -> Result<_, RepositoryFailure> {
        let mut builder = BackupManifestBuilder::new(
            capture,
            [6; 16],
            repository.clone(),
            BackupRetention::new(1000, 2000)?,
            BackupPublisher::key_context(&[BackupKeyEnvelope::new(
                [9; 16],
                1,
                [10; 32],
                vec![0x62; 128],
            )?])?,
        )?;
        loop {
            if let Some(manifest) = builder.step(capture, 17)? {
                break Ok(manifest);
            }
        }
    };
    let expected = build(&capture)?;
    assert_eq!(expected.capture_binding(), Some(([6; 16], [7; 32])));
    let signed = expected.signed_bytes(&signer)?;
    assert_eq!(&signed[..8], b"POSBKM02");
    assert_eq!(
        positron_backup::BackupManifest::verify(&signed, &repository, signer.identity())?,
        expected
    );
    snapshot_resources::admitted(96 * 1024 * 1024, |resources| {
        let (port, repository, signer, capture, catalog, expected) =
            (&port, &repository, &signer, &capture, &catalog, &expected);
        async move {
            let publisher = BackupPublisher::new(port, repository, signer).with_control_resources(
                &resources,
                capture.retained_memory_bytes()? + expected.retained_memory_bytes()?,
            )?;
            let keys = [BackupKeyEnvelope::new(
                [9; 16],
                1,
                [10; 32],
                vec![0x62; 128],
            )?];
            publisher.reserve(expected, &keys).await?;
            let mut transfer = positron_backup::BackupTransfer::start(expected)?;
            while !transfer.complete() {
                transfer = publisher.transfer_step(expected, capture, transfer).await?;
            }
            let publication = publisher.publish(expected, &keys).await?;
            let mut verification = publisher
                .begin_snapshot_verification(expected.snapshot_id(), [44; 16], [45; 32])
                .await?;
            let index_bytes = publisher
                .read_snapshot_file(expected, expected.capture_index(), 8 * 1024 * 1024)
                .await?;
            let mut native =
                catalog.begin_backup_capture_verification([6; 16], [7; 32], &index_bytes)?;
            let files = native.files().to_vec();
            publisher.validate_snapshot_inventory(&mut verification, &files)?;
            assert!(
                publisher
                    .validate_snapshot_inventory(&mut verification, &[])
                    .is_err()
            );
            for file in files {
                if matches!(
                    file.kind(),
                    BackupCaptureFileKind::CatalogObject
                        | BackupCaptureFileKind::GovernanceAudit
                        | BackupCaptureFileKind::AuditCheckpoint
                ) {
                    let bytes = publisher
                        .read_snapshot_file(expected, file.identity(), 2 * 1024 * 1024)
                        .await?;
                    native.verify_file(catalog, file.identity(), &bytes)?;
                }
            }
            let detached = native.finish()?;
            assert!(
                publisher
                    .snapshot_verification_report(&verification, &detached, 1)
                    .await
                    .is_err()
            );
            while !publisher
                .snapshot_verification_step(&mut verification)
                .await?
            {}
            assert!(
                publisher
                    .snapshot_verification_report(&verification, &detached, 0)
                    .await
                    .is_err()
            );
            assert_eq!(publisher.verification_key_count(&verification), 1);
            let key = publisher.read_verification_key(&verification, 0).await?;
            assert_eq!(
                (key.tenant(), key.epoch(), key.fingerprint()),
                ([9; 16], 1, [10; 32])
            );
            assert!(
                publisher
                    .read_verification_key(&verification, 1)
                    .await
                    .is_err()
            );
            let report = publisher
                .snapshot_verification_report(&verification, &detached, 1)
                .await?;
            assert_eq!(report.bytes().len(), 413);
            assert_eq!(
                positron_backup::BackupVerificationReport::verify(
                    report.bytes(),
                    repository,
                    signer.identity()
                )?,
                report
            );
            let mut bad = report.bytes().to_vec();
            if let Some(byte) = bad.last_mut() {
                *byte ^= 1;
            }
            assert!(
                positron_backup::BackupVerificationReport::verify(
                    &bad,
                    repository,
                    signer.identity()
                )
                .is_err()
            );
            let changed = RepositoryIdentity::local(
                [99; 16],
                instance.to_bytes(),
                signer.identity().fingerprint(),
                &repository_path,
            )?;
            assert!(
                positron_backup::BackupVerificationReport::verify(
                    report.bytes(),
                    &changed,
                    signer.identity()
                )
                .is_err()
            );
            assert_eq!(
                verification.registry_generation(),
                publication.registry_generation()
            );
            // The signed index names complete files even when immutable transfer
            // objects split a file into independently addressed extents.
            let split_file = expected.objects().first().ok_or("split file")?;
            let midpoint = split_file.length() / 2;
            let mut chunks = Vec::new();
            for object in expected.objects() {
                if object.file() == split_file.file() {
                    for (offset, length) in [(0, midpoint), (midpoint, object.length() - midpoint)]
                    {
                        let bytes = capture.read(object.file(), offset, length)?;
                        use sha2::{Digest, Sha256};
                        chunks.push(positron_backup::BackupObject::new(
                            object.file(),
                            object.file_size(),
                            offset,
                            Sha256::digest(bytes).into(),
                            length,
                        )?);
                    }
                } else {
                    chunks.push(*object);
                }
            }
            let chunked = positron_backup::BackupManifest::new(
                [66; 16],
                repository.clone(),
                positron_backup::BackupCatalogIdentity::new(
                    expected.catalog_generation(),
                    expected.catalog_identity(),
                    expected.format_epoch(),
                    expected.audit_frontier(),
                    expected.capture_index(),
                )?
                .with_capture_binding([6; 16], [7; 32])?,
                BackupRetention::new(1000, 2000)?,
                expected.key_context(),
                chunks,
            )?;
            publisher.reserve(&chunked, &keys).await?;
            let mut transfer = positron_backup::BackupTransfer::start(&chunked)?;
            while !transfer.complete() {
                transfer = publisher.transfer_step(&chunked, capture, transfer).await?;
            }
            publisher.publish(&chunked, &keys).await?;
            let mut state = publisher
                .begin_snapshot_verification([66; 16], [67; 16], [68; 32])
                .await?;
            let mut native =
                catalog.begin_backup_capture_verification([6; 16], [7; 32], &index_bytes)?;
            let files = native.files().to_vec();
            publisher.validate_snapshot_inventory(&mut state, &files)?;
            for file in files {
                if matches!(
                    file.kind(),
                    BackupCaptureFileKind::CatalogObject
                        | BackupCaptureFileKind::GovernanceAudit
                        | BackupCaptureFileKind::AuditCheckpoint
                ) {
                    let bytes = publisher
                        .read_snapshot_file(&chunked, file.identity(), 2 * 1024 * 1024)
                        .await?;
                    native.verify_file(catalog, file.identity(), &bytes)?;
                }
            }
            let detached = native.finish()?;
            while !publisher.snapshot_verification_step(&mut state).await? {}
            publisher
                .snapshot_verification_report(&state, &detached, 1)
                .await?;

            Ok(())
        }
    })
    .await?;

    let file = *capture
        .files()
        .iter()
        .find(|file| file.kind() == BackupCaptureFileKind::CatalogObject)
        .ok_or("metadata")?;
    drop(capture);
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, secret())?;
    let capture = catalog.open_backup_capture([6; 16], [7; 32])?;
    assert_eq!(build(&capture)?, expected);
    let name: String = file
        .identity()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let file_path = path
        .join("backup-captures")
        .join("06".repeat(16))
        .join(format!("f-{name}"));
    let original = std::fs::read(&file_path)?;
    let mut changed = original.clone();
    *changed.last_mut().ok_or("ciphertext")? ^= 1;
    std::fs::write(&file_path, changed)?;
    drop(capture);
    let capture = catalog.open_backup_capture([6; 16], [7; 32])?;
    let envelopes = [BackupKeyEnvelope::new(
        [9; 16],
        1,
        [10; 32],
        vec![0x62; 128],
    )?];
    let builder = BackupManifestBuilder::new(
        &capture,
        [6; 16],
        repository.clone(),
        BackupRetention::new(1000, 2000)?,
        [10; 32],
    )?;
    snapshot_resources::admitted(8 * 1024 * 1024, |resources| {
        let (builder, port, repository, signer, envelopes) =
            (&builder, &port, &repository, &signer, &envelopes);
        async move {
            let publisher = BackupPublisher::new(port, repository, signer)
                .with_control_resources(&resources, 0)?;
            assert!(matches!(builder.preflight(&publisher, envelopes),
                Err(RepositoryFailure::ControlMemoryRequired { memory_bytes }) if memory_bytes > 8 * 1024 * 1024));
            Ok(())
        }
    }).await?;
    snapshot_resources::admitted(25_000_000, |resources| {
        let (port, repository, signer, envelopes, capture) =
            (&port, &repository, &signer, &envelopes, &capture);
        async move {
            let publisher = BackupPublisher::new(port, repository, signer)
                .with_control_resources(&resources, 0)?;
            let mut builder = builder;
            builder.preflight(&publisher, envelopes)?;
            loop {
                match builder.step(capture, 17) {
                    Ok(None) => {},
                    Ok(Some(_)) => return Err("corrupt capture exposed a manifest".into()),
                    Err(failure) => {
                        assert_eq!(failure, RepositoryFailure::ChecksumMismatch);
                        break;
                    },
                }
            }
            assert!(
                port.registry_head_at(positron_backup::HeadSlot::registry())
                    .await?
                    .is_some()
            );
            Ok(())
        }
    })
    .await?;
    assert_eq!(build(&capture), Err(RepositoryFailure::ChecksumMismatch));
    std::fs::write(file_path, original)?;
    assert_eq!(build(&capture)?, expected);
    drop(capture);
    drop(catalog);
    drop(execution);
    drop(authority);
    std::fs::remove_dir_all(path)?;
    Ok(())
}
