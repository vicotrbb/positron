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
            [10; 32],
        )?;
        loop {
            if let Some(manifest) = builder.step(capture, 17)? {
                break Ok(manifest);
            }
        }
    };
    let expected = build(&capture)?;
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
                    .is_none()
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
