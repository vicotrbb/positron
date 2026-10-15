use super::*;

#[test]
fn published_backup_reconciles_after_cold_restart_without_new_recovery_readiness()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-backup-cas-restart-{}",
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
    let stop = crate::services::backup_administration::stop_after(
        crate::services::backup_administration::StopPoint::RegistryPublished,
    )?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !stop.observed() && !worker.is_finished() {
        if std::time::Instant::now() >= deadline {
            cancellation.cancel();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(worker.join().map_err(|_| "worker panic")?, Ok(()));
    assert!(
        stop.observed(),
        "worker did not reach Registry publication boundary"
    );
    let snapshot =
        crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
            .ok_or("snapshot identity")?;
    assert!(positron_kernel::BackupCapture::exists(
        &initialized._authority,
        snapshot
    )?);
    let published = {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&initialized)?;
        let operation = positron_governance::DurableOperationAdministration::inspect(
            &catalog,
            positron_governance::OperationId::from_bytes(snapshot)?,
        )?
        .ok_or("published operation")?;
        assert_eq!(
            operation.status(),
            positron_governance::DurableOperationStatus::Running
        );
        assert_eq!(
            operation.phase(),
            positron_governance::DurableOperationPhase::BackupPublication
        );
        assert!(operation.backup_receipt().is_none());
        let basis = catalog.pin()?;
        let (_, governance) = basis.governance_object()?;
        let signer = initialized
            .key
            .backup_control_signer(initialized.instance, governance.protected_integrity_key())?;
        let repository = runtime.block_on(LocalRepository::attach(&repository_path, &identity))?;
        let resources = backup_read_resources(&services)?;
        let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 0)?;
        let proof = backup_inspection_proof(&runtime, &publisher, snapshot)?;
        let publisher = publisher.with_registry_verification(&proof)?;
        let manifest = runtime.block_on(publisher.verify(snapshot))?;
        assert_eq!(manifest.snapshot_id(), snapshot);
        let receipt = runtime
            .block_on(publisher.reconcile_publication(&manifest))?
            .ok_or("published receipt")?;
        (receipt.manifest().checksum(), receipt.registry_generation())
    };
    initialized.begin_local_key_rotation()?;
    initialized.activate_local_key_rotation()?;
    assert_eq!(
        initialized.checked_backup_key_recovery_readiness()?,
        crate::RecoveryReadiness::IndependentRecoveryRequired
    );
    drop(runtime);
    drop(services);
    drop(initialized);
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or_else(|| {
        format!(
            "cold services: phase {:?}, integrity {:?}",
            process.health().phase(),
            process.health().integrity_fence_reason()
        )
    })?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("cold API endpoint")?;
    let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
    let completed = finish(&client, &services, &administrator, &accepted.operation.id)?;
    assert_eq!(completed.operation.status, "succeeded");
    let receipt = completed.receipt.ok_or("reconciled receipt")?;
    assert_eq!(
        receipt.manifest_checksum,
        published
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_eq!(
        receipt.registry_generation_checksum,
        published
            .1
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert!(!completed.cleanup_pending);
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    fs::remove_dir_all(repository_path)?;
    Ok(())
}

#[test]
fn cancellation_cleaning_restarts_without_the_removed_private_registry_sidecar()
-> Result<(), Box<dyn std::error::Error>> {
    cancellation_restart_at(crate::services::backup_administration::StopPoint::CaptureCleanupBatch)
}
#[test]
fn cancelled_backup_keeps_its_cold_claim_acknowledgement_owner()
-> Result<(), Box<dyn std::error::Error>> {
    cancellation_restart_at(
        crate::services::backup_administration::StopPoint::CancellationCommitted,
    )
}
fn cancellation_restart_at(
    point: crate::services::backup_administration::StopPoint,
) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-backup-cleaning-restart-{}",
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
    services.ingest_otlp_logs(&ingest, request("cold cleanup telemetry").encode_to_vec())?;
    for batch in 0..8 {
        services.ingest_otlp_logs(
            &ingest,
            request(&format!("cleanup sealed telemetry {batch}")).encode_to_vec(),
        )?;
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&initialized)?;
        let basis = catalog.pin()?;
        let identity = positron_governance::Identity::open(&basis)?;
        let scope = SegmentScope::new(
            initialized.tenant,
            positron_domain::routing::SignalKind::Logs,
            initialized.logs_shard,
        );
        let protection = crate::services::tenant_segment_key(&initialized, &identity, scope)?;
        drop(basis);
        ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            protection,
        )?
        .seal()?;
    }
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = fixture.recovery_export_directory()?.join("cleanup.age");
    initialized.create_recovery_bundle(&bundle, &recipients)?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let accepted = services
        .manage_backup(
            &administrator,
            &create(
                &services,
                &repository_path,
                "88888888-8888-4888-8888-888888888888",
            )?
            .encode()?,
        )
        .map_err(|failure| format!("accept backup: {failure:?}"))?;
    let stop = crate::services::backup_administration::stop_after(point)?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    wait_for_signed_reservation(
        &services,
        &repository_path,
        &identity,
        &accepted.operation.id,
        &administrator,
    )?;
    let status_request = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status","operation_id":accepted.operation.id}),
    )?)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = services
            .manage_backup(&administrator, &status_request.encode()?)
            .map_err(|failure| format!("inspect active backup: {failure:?}"))?;
        let request = BackupRequest::decode(&serde_json::to_vec(
            &serde_json::json!({"action":"cancel","operation_id":accepted.operation.id,"idempotency_key":"99999999-9999-4999-8999-999999999999","expected_operation_revision":status.operation_revision}),
        )?)?;
        match services.manage_backup(&administrator, &request.encode()?) {
            Ok(response) => {
                assert!(response.cleanup_pending);
                break;
            },
            Err(MaintenanceServiceFailure::PreconditionFailed)
                if std::time::Instant::now() < deadline => {},
            Err(failure) => {
                cancellation.cancel();
                return Err(format!("cancel backup: {failure:?}").into());
            },
        }
    }
    while !stop.observed() && !worker.is_finished() {
        if std::time::Instant::now() >= deadline {
            cancellation.cancel();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(worker.join().map_err(|_| "cleanup worker panic")?, Ok(()));
    assert!(
        stop.observed(),
        "cleanup worker did not stop at the requested durable boundary: {:?}",
        initialized.maintenance_coordinator().statuses()
    );
    let snapshot =
        crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
            .ok_or("snapshot identity")?;
    {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&initialized)?;
        let operation = positron_governance::DurableOperationAdministration::inspect(
            &catalog,
            positron_governance::OperationId::from_bytes(snapshot)?,
        )?
        .ok_or("cancelling operation")?;
        if point == crate::services::backup_administration::StopPoint::CaptureCleanupBatch {
            assert_eq!(
                operation.phase(),
                positron_governance::DurableOperationPhase::BackupCancellation
            );
            assert_eq!(
                operation.status(),
                positron_governance::DurableOperationStatus::Running
            );
            assert!(catalog.has_backup_capture_references()?);
            let capture = catalog
                .resume_backup_capture(
                    snapshot,
                    operation
                        .backup_parameters()
                        .ok_or("backup parameters")?
                        .intent_digest(),
                )?
                .ok_or("remaining authenticated capture index")?;
            assert!(
                catalog
                    .backup_capture_registry_checkpoint(&capture)
                    .is_err(),
                "cleanup fault must follow private sidecar removal"
            );
        } else {
            assert_eq!(
                operation.status(),
                positron_governance::DurableOperationStatus::Cancelled
            );
            assert!(operation.backup_cleanup_receipt().is_some());
            assert!(!catalog.has_backup_capture_references()?);
            let basis = catalog.pin()?;
            let (_, governance) = basis.governance_object()?;
            let signer = initialized.key.backup_control_signer(
                initialized.instance,
                governance.protected_integrity_key(),
            )?;
            let repository =
                runtime.block_on(LocalRepository::attach(&repository_path, &identity))?;
            let resources = backup_read_resources(&services)?;
            let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
                .with_control_resources(&resources, 0)?;
            let proof = backup_inspection_proof(&runtime, &publisher, snapshot)?;
            let publisher = publisher.with_registry_verification(&proof)?;
            assert!(
                runtime
                    .block_on(publisher.cleanup_for_owner(snapshot))?
                    .is_some_and(|progress| progress.complete())
            );
        }
    }
    drop(runtime);
    drop(services);
    drop(initialized);
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or("cold cleanup services")?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("cold cleanup API")?;
    let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
    let completed = finish(&client, &services, &administrator, &accepted.operation.id)?;
    assert_eq!(completed.operation.status, "cancelled");
    assert!(!completed.cleanup_pending);
    let _gate = services.catalog_operation()?;
    let catalog = open_catalog(&services.instance)?;
    assert!(!catalog.has_backup_capture_references()?);
    let operation = positron_governance::DurableOperationAdministration::inspect(
        &catalog,
        positron_governance::OperationId::from_bytes(snapshot)?,
    )?
    .ok_or("cancelled operation")?;
    assert!(operation.backup_cleanup_receipt().is_some());
    let basis = catalog.pin()?;
    let (_, governance) = basis.governance_object()?;
    let signer = services.instance.key.backup_control_signer(
        services.instance.instance,
        governance.protected_integrity_key(),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let repository = runtime.block_on(LocalRepository::attach(&repository_path, &identity))?;
    let resources = backup_read_resources(&services)?;
    {
        let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 0)?;
        let proof = backup_inspection_proof(&runtime, &publisher, snapshot)?;
        let publisher = publisher.with_registry_verification(&proof)?;
        assert_eq!(
            runtime.block_on(publisher.cleanup_for_owner(snapshot))?,
            None
        );
    }
    drop(resources);
    drop(repository);
    drop(runtime);
    drop(basis);
    drop(catalog);
    drop(_gate);
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    fs::remove_dir_all(repository_path)?;
    Ok(())
}
