use super::*;
use crate::ServiceFailure;
use positron_backup::Repository;

#[test]
fn remote_object_corruption_fails_backup_without_fencing_and_retains_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-backup-failure-{}",
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
    services.ingest_otlp_logs(&ingest, request("remote failure telemetry").encode_to_vec())?;
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

    let snapshot =
        crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
            .ok_or("snapshot")?;
    let stop = crate::services::backup_administration::stop_after(
        services.instance.instance.to_bytes(),
        crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
            .ok_or("stop operation identity")?,
        crate::services::backup_administration::StopPoint::ReservationRegistered,
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
    let result = worker.join().map_err(|_| "worker panic")?;
    assert!(stop.observed(), "reservation boundary: {result:?}");
    assert_eq!(result, Ok(()));
    drop(stop);
    let (object, original) = {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&initialized)?;
        let operation = positron_governance::DurableOperationAdministration::inspect(
            &catalog,
            positron_governance::OperationId::from_bytes(snapshot)?,
        )?
        .ok_or("reserved operation")?;
        let basis = catalog.pin()?;
        let (_, governance) = basis.governance_object()?;
        let signer = initialized
            .key
            .backup_control_signer(initialized.instance, governance.protected_integrity_key())?;
        let repository = runtime.block_on(LocalRepository::attach(&repository_path, &identity))?;
        let resources = backup_read_resources(&services)?;
        let publisher = positron_backup::BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 0)?;
        let candidate = runtime
            .block_on(publisher.cancellation_candidate(snapshot))?
            .ok_or("signed reservation")?;
        let metadata = runtime.block_on(repository.head(candidate.manifest()))?;
        let bytes = runtime.block_on(repository.read_range(positron_backup::ObjectRange::new(
            candidate.manifest(),
            0,
            metadata.size(),
        )?))?;
        let manifest =
            positron_backup::BackupManifest::verify(bytes.bytes(), &identity, signer.identity())?;
        let object = *manifest.objects().first().ok_or("captured object")?;
        let capture = catalog
            .resume_backup_capture(
                snapshot,
                operation
                    .backup_parameters()
                    .ok_or("capture parameters")?
                    .intent_digest(),
            )?
            .ok_or("capture")?;
        let original = capture.read(object.file(), object.offset(), object.length())?;
        (object, original)
    };
    let corrupted = repository_path.join(format!(
        "o-{}",
        object
            .object()
            .checksum()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    fs::write(&corrupted, vec![0xa5; original.len()])?;
    fs::set_permissions(&corrupted, fs::Permissions::from_mode(0o600))?;
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
    let services = process.services().ok_or("cold services")?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), Box<dyn std::error::Error>> {
            let status_request = BackupRequest::decode(&serde_json::to_vec(
                &serde_json::json!({"action":"status","operation_id":accepted.operation.id}),
            )?)?;
            let task = positron_kernel::MaintenanceTaskId::new(snapshot)
                .map_err(|failure| format!("task: {failure:?}"))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let status = services
                    .manage_backup(&administrator, &status_request.encode()?)
                    .map_err(|failure| format!("status: {failure:?}"))?;
                status.encode()?;
                if status.operation.status == "failed" {
                    assert_eq!(
                        status.terminal_error_code.as_deref(),
                        Some("handler_rejected")
                    );
                    assert!(status.cleanup_pending);
                    assert_eq!(status.operation.irreversible_boundary, "not_crossed");
                    break;
                }
                if process.health().phase() != crate::ProcessPhase::Serving {
                    return Err(format!(
                        "instance fenced after remote corruption: {:?}",
                        process.health().phase()
                    )
                    .into());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(format!("failure deadline: {status:?}").into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            // Outer receiver capacity refusal precedes every admission group and
            // is canonical retryable backpressure. Never replay an Ok partial
            // outcome or a failure with unknown acceptance.
            let foreground = "healthy foreground after remote corruption";
            let foreground_deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                assert_eq!(process.health().phase(), crate::ProcessPhase::Serving);
                let status = services
                    .manage_backup(&administrator, &status_request.encode()?)
                    .map_err(|failure| format!("foreground failure status: {failure:?}"))?;
                assert_eq!(status.operation.status, "failed");
                assert!(status.cleanup_pending);
                match services.ingest_otlp_logs(&ingest, request(foreground).encode_to_vec()) {
                    Ok(outcome) => {
                        assert_eq!(outcome.accepted_records(), 1);
                        break;
                    },
                    Err(ServiceFailure::CapacityUnavailable)
                        if std::time::Instant::now() < foreground_deadline =>
                    {
                        std::thread::sleep(Duration::from_secs(1));
                    },
                    Err(failure) => {
                        return Err(
                            format!("foreground ingest after remote failure: {failure:?}").into(),
                        );
                    },
                }
            }
            assert!(positron_kernel::BackupCapture::exists(
                &services.instance._authority,
                snapshot
            )?);
            fs::write(&corrupted, &original)?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let status = services
                    .manage_backup(&administrator, &status_request.encode()?)
                    .map_err(|failure| format!("cleanup status: {failure:?}"))?;
                status.encode()?;
                let task_status = services
                    .instance
                    .maintenance_coordinator()
                    .status(task)
                    .map_err(|failure| format!("cleanup task: {failure:?}"))?;
                if status.operation.status == "failed"
                    && !status.cleanup_pending
                    && task_status.phase() == MaintenanceTaskPhase::Failed
                {
                    break;
                }
                if process.health().phase() != crate::ProcessPhase::Serving {
                    return Err("instance stopped during failed cleanup".into());
                }
                if std::time::Instant::now() >= deadline {
                    return Err(format!("failed cleanup deadline: {status:?}").into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(!positron_kernel::BackupCapture::exists(
                &services.instance._authority,
                snapshot
            )?);
            let bodies = services.query_log_bodies(
                &query,
                "logs | range query_time 0 100 | limit 10",
                QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 60)?
                    .with_cpu_work_units(16)?,
            )?;
            assert_eq!(
                bodies
                    .iter()
                    .filter(|body| body.as_str() == foreground)
                    .count(),
                1
            );
            Ok(())
        },
    ));
    drop(services);
    let shutdown = process.shutdown(ShutdownTrigger::FirstSignal);
    match result {
        Ok(Err(error)) => return Err(format!("{error}; shutdown: {shutdown:?}").into()),
        Ok(Ok(())) => assert_eq!(shutdown, crate::ExitOutcome::Graceful),
        Err(panic) => std::panic::resume_unwind(panic),
    }
    fs::remove_dir_all(repository_path)?;
    Ok(())
}
