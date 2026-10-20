use super::*;

#[test]
fn warm_snapshot_reauthorizes_before_its_next_advance() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-backup-snapshot-revocation-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&repository_path)?;
    fs::set_permissions(&repository_path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        initialized.instance.to_bytes(),
        initialized.integrity_key_fingerprint(),
        &repository_path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(
        &repository_path,
        identity.clone(),
    ))?);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(
        &ingest,
        request("cold publication telemetry").encode_to_vec(),
    )?;
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = fixture.recovery_export_directory()?.join("publication.age");
    initialized.create_recovery_bundle(&bundle, &recipients)?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let accepted = services
        .manage_backup(
            &administrator,
            &create(
                &services,
                &repository_path,
                "77777777-7777-4777-8777-777777777777",
            )?
            .encode()?,
        )
        .map_err(|failure| format!("accept backup: {failure:?}"))?;
    let id = positron_governance::OperationId::from_bytes(
        crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
            .ok_or("snapshot operation ID")?,
    )?;
    let task =
        positron_kernel::MaintenanceTaskId::new(id.to_bytes()).map_err(|e| format!("{e:?}"))?;
    let coordinator = initialized.maintenance_coordinator();
    let mut execution = {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|e| format!("{e:?}"))?;
        coordinator
            .start_backup_operation_with_reservation_and_persist(
                &catalog,
                &initialized._authority,
                services
                    .maintenance_status_now()
                    .map_err(|e| format!("{e:?}"))?,
                false,
                task,
            )
            .map_err(|e| format!("{e:?}"))?
            .ok_or("snapshot start")?
    };
    let mut work = None;
    assert!(!crate::services::backup_administration::complete(
        &services,
        &mut execution,
        &mut work,
        None,
    )?);
    assert!(matches!(
        work.as_ref(),
        Some(crate::services::backup_administration::BackupWork::Snapshot(_))
    ));
    // Change the canonical persistent grant between advances. There is no
    // operator API for rotating the bootstrap system credential.
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|e| format!("{e:?}"))?;
    let basis = catalog.pin()?;
    let (source, governance) = basis.governance_object()?;
    let credentials = governance
        .credentials()
        .iter()
        .map(|credential| {
            if credential.scope_code() == 4 {
                credential.with_active(false)
            } else {
                *credential
            }
        })
        .collect::<Vec<_>>();
    let changed = positron_kernel::CatalogObject::new(
        governance.with_credentials(governance.credential_generation() + 1, &credentials)?,
    )?;
    let mut objects = basis
        .object_identities()
        .map(|identity| -> Result<_, Box<dyn std::error::Error>> {
            let bytes = basis.object(identity)?.ok_or("fixture object")?;
            Ok(positron_kernel::CatalogObject::new(bytes.to_vec())?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    objects.retain(|object| object.identity() != source);
    objects.push(changed);
    catalog.commit(
        basis.identity(),
        positron_kernel::CatalogProposal::new(
            positron_kernel::TransactionId::new([0xd4; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    drop(basis);
    drop(catalog);
    drop(_gate);
    assert_eq!(
        crate::services::backup_administration::complete(
            &services,
            &mut execution,
            &mut work,
            None,
        ),
        Err(crate::ServiceFailure::Unauthorized)
    );
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|e| format!("{e:?}"))?;
    let refused = positron_governance::DurableOperationAdministration::inspect(&catalog, id)?
        .ok_or("snapshot outcome")?;
    assert_eq!(
        refused.status(),
        positron_governance::DurableOperationStatus::Running
    );
    assert!(refused.backup_receipt().is_none());
    assert!(refused.backup_verification_report().is_none());
    drop(catalog);
    drop(work);
    drop(execution);
    drop(runtime);
    drop(services);
    drop(initialized);
    fs::remove_dir_all(repository_path)?;
    Ok(())
}
