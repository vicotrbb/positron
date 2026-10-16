use super::*;

#[test]
fn runtime_backup_expiry_waits_for_retention_and_finishes_signed_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (mut initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let (clock, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole instance")?
        .install_retention_time_for_test(clock)?;
    let path = std::env::temp_dir().join(format!(
        "positron-backup-expiry-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        initialized.instance.to_bytes(),
        initialized.integrity_key_fingerprint(),
        &path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(&path, identity.clone()))?);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(
        &ingest,
        request("expiry retains encrypted telemetry").encode_to_vec(),
    )?;
    let unlock = age::x25519::Identity::generate();
    let bundle = fixture.recovery_export_directory()?.join("expiry.age");
    initialized.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let mut creation = create(&services, &path, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?;
    creation.retention_seconds = Some(60);
    let accepted = services
        .manage_backup(&administrator, &creation.encode()?)
        .map_err(|failure| format!("accept backup: {failure:?}"))?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), Box<dyn std::error::Error>> {
            let published = finish_direct(&services, &administrator, &accepted.operation.id)?;
            let receipt = published.receipt.ok_or("published receipt")?;
            let second_request = create(&services, &path, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")?;
            let second = services
                .manage_backup(&administrator, &second_request.encode()?)
                .map_err(|failure| format!("second backup: {failure:?}"))?;
            let second = finish_direct(&services, &administrator, &second.operation.id)?;
            assert!(
                second
                    .receipt
                    .as_ref()
                    .ok_or("second receipt")?
                    .reused_bytes
                    > 0
            );
            let generation = {
                let _gate = services.catalog_operation()?;
                open_catalog(&initialized)?.pin()?.number()
            };
            let expiry_request = BackupRequest::decode(&serde_json::to_vec(
                &serde_json::json!({"action":"expire","repository_id":"5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b","snapshot_id":accepted.operation.id,"expected_manifest_checksum":receipt.manifest_checksum,"expected_catalog_generation":generation,"idempotency_key":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}),
            )?)?;
            let expiry = services
                .manage_backup(&administrator, &expiry_request.encode()?)
                .map_err(|failure| format!("accept expiry: {failure:?}"))?;
            expiry.encode()?;
            assert_eq!(expiry.kind, "retention");
            assert!(expiry.retention_receipt.is_none());
            let status_request = BackupRequest::decode(&serde_json::to_vec(
                &serde_json::json!({"action":"status","operation_id":expiry.operation.id}),
            )?)?;
            let expiry_task = positron_kernel::MaintenanceTaskId::new(
                crate::services::maintenance_verification::decode_fixed_hex(&expiry.operation.id)
                    .ok_or("expiry task")?,
            )
            .map_err(|failure| format!("expiry task: {failure:?}"))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let status = services
                    .manage_backup(&administrator, &status_request.encode()?)
                    .map_err(|failure| format!("expiry status: {failure:?}"))?;
                status.encode()?;
                if status.operation.status == "failed"
                    && initialized
                        .maintenance_coordinator()
                        .status(expiry_task)
                        .map_err(|failure| format!("expiry task: {failure:?}"))?
                        .phase()
                        == MaintenanceTaskPhase::Failed
                {
                    assert_eq!(
                        status.terminal_error_code.as_deref(),
                        Some("backup_retention_not_due")
                    );
                    assert_eq!(status.operation.irreversible_boundary, "not_crossed");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(format!("expiry scan deadline: {status:?}").into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let before_due = positron_api::backup::BackupListRequest {
                repository_id: "5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b".into(),
                limit: 128,
                cursor: None,
            };
            assert_eq!(
                services
                    .list_backups(&administrator, &before_due.encode()?)
                    .map_err(|failure| format!("retained inventory: {failure:?}"))?
                    .entries
                    .len(),
                2
            );
            assert_eq!(receipt.retain_until_unix_seconds, 70);
            elapsed.advance(60_000_000_000)?;
            let replay = services
                .manage_backup(&administrator, &expiry_request.encode()?)
                .map_err(|failure| format!("early refusal replay: {failure:?}"))?;
            assert_eq!(replay.operation.id, expiry.operation.id);
            assert_eq!(replay.operation.status, "failed");
            let mut due_request = expiry_request.clone();
            due_request.idempotency_key = Some("dddddddd-dddd-4ddd-8ddd-dddddddddddd".into());
            due_request.expected_catalog_generation = Some({
                let _gate = services.catalog_operation()?;
                open_catalog(&initialized)?.pin()?.number()
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let due = loop {
                match services.manage_backup(&administrator, &due_request.encode()?) {
                    Ok(response) => break response,
                    Err(MaintenanceServiceFailure::PreconditionFailed) => {
                        let generation = {
                            let _gate = services.catalog_operation()?;
                            open_catalog(&initialized)?.pin()?.number()
                        };
                        if due_request.expected_catalog_generation == Some(generation)
                            || std::time::Instant::now() >= deadline
                        {
                            return Err("accept due expiry: Catalog precondition refused".into());
                        }
                        // Rejection precedes acceptance; refresh only the stale
                        // generation while preserving the exact expiry intent and key.
                        due_request.expected_catalog_generation = Some(generation);
                    },
                    Err(failure) => {
                        return Err(format!("accept due expiry: {failure:?}").into());
                    },
                }
            };
            due.encode()?;
            let completed = finish_direct(&services, &administrator, &due.operation.id)?;
            assert_eq!(completed.operation.status, "succeeded");
            assert!(!completed.cleanup_pending);
            assert_eq!(
                completed
                    .retention_receipt
                    .ok_or("retention receipt")?
                    .snapshot_id,
                accepted.operation.id
            );
            let list = positron_api::backup::BackupListRequest {
                repository_id: "5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b".into(),
                limit: 128,
                cursor: None,
            };
            let inventory = services
                .list_backups(&administrator, &list.encode()?)
                .map_err(|failure| format!("expired inventory: {failure:?}"))?;
            assert_eq!(inventory.entries.len(), 1);
            assert_eq!(
                inventory
                    .entries
                    .first()
                    .ok_or("retained second snapshot")?
                    .snapshot_id,
                second.operation.id
            );
            let signer = {
                let _gate = services.catalog_operation()?;
                let catalog = open_catalog(&initialized)?;
                let basis = catalog.pin()?;
                let (_, governance) = basis.governance_object()?;
                initialized.key.backup_control_signer(
                    initialized.instance,
                    governance.protected_integrity_key(),
                )?
            };
            let repository = runtime.block_on(LocalRepository::attach(&path, &identity))?;
            let resources = backup_read_resources(&services)?;
            let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
                .with_control_resources(&resources, 0)?;
            let proof = backup_inspection_proof(
                &runtime,
                &publisher,
                crate::services::maintenance_verification::decode_fixed_hex(&second.operation.id)
                    .ok_or("retained snapshot")?,
            )?;
            let publisher = publisher.with_registry_verification(&proof)?;
            assert_eq!(
                runtime
                    .block_on(
                        publisher.verify(
                            crate::services::maintenance_verification::decode_fixed_hex(
                                &second.operation.id
                            )
                            .ok_or("retained snapshot")?
                        )
                    )?
                    .snapshot_id(),
                crate::services::maintenance_verification::decode_fixed_hex(&second.operation.id)
                    .ok_or("retained snapshot")?
            );
            Ok(())
        },
    ));
    cancellation.cancel();
    let worker_result = worker.join().map_err(|_| "worker panic")?;
    match result {
        Ok(Err(error)) => Err(format!("{error}; worker result: {worker_result:?}").into()),
        Ok(Ok(())) => worker_result.map_err(|failure| format!("worker result: {failure:?}").into()),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
pub(super) fn finish_direct(
    services: &ServiceHandle,
    bearer: &str,
    id: &str,
) -> Result<BackupResponse, Box<dyn std::error::Error>> {
    let request = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status","operation_id":id}),
    )?)?;
    let task = positron_kernel::MaintenanceTaskId::new(
        crate::services::maintenance_verification::decode_fixed_hex(id).ok_or("task identity")?,
    )
    .map_err(|failure| format!("task identity: {failure:?}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = services
            .manage_backup(bearer, &request.encode()?)
            .map_err(|failure| format!("backup status: {failure:?}"))?;
        status.encode()?;
        if status.operation.status == "failed" {
            return Err(format!("backup failed: {status:?}").into());
        }
        if status.operation.status == "succeeded"
            && !status.cleanup_pending
            && services
                .instance
                .maintenance_coordinator()
                .status(task)
                .map_err(|failure| format!("task status: {failure:?}"))?
                .phase()
                == MaintenanceTaskPhase::Succeeded
        {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("backup deadline: {status:?}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
