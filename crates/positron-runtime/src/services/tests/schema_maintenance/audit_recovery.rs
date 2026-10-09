use super::*;

#[test]
fn maintenance_worker_treats_cancellation_before_dispatch_as_a_normal_exit()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(initialized)?;
    let cancellation = crate::TaskCancellation::new();
    // Poll one is the outer worker-loop check; poll two is the scheduler
    // admission boundary immediately before a task can become Running.
    cancellation.cancel_after_polls(2);

    assert_eq!(services.run_maintenance_worker(&cancellation), Ok(()));
    Ok(())
}

#[test]
fn runtime_worker_wakes_for_a_poststart_future_lease_expiry() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));

    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog_operation = services.catalog_operation()?;
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let now = initialized.retention_time.governance_now_seconds()?;
    let coordinator = initialized.maintenance_coordinator();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        coordinator,
        now,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    drop(lease);
    drop(ledger);
    drop(catalog);
    drop(catalog_operation);

    elapsed.advance(2_000_000_000)?;
    services.notify_maintenance_worker();
    let deadline = Instant::now() + Duration::from_secs(2);
    while initialized
        .maintenance_coordinator()
        .status(task)
        .map_err(|_| "maintenance task status")?
        .phase()
        != MaintenanceTaskPhase::Succeeded
    {
        if Instant::now() >= deadline {
            cancellation.cancel();
            services.notify_maintenance_worker();
            let phase = initialized
                .maintenance_coordinator()
                .status(task)
                .map_err(|_| "maintenance task status after timeout")?
                .phase();
            let worker = worker
                .join()
                .map_err(|_| "maintenance worker panicked after wake timeout")?;
            return Err(format!(
                "runtime maintenance worker did not wake for poststart expiry work (phase: {phase:?}, worker: {worker:?})"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    cancellation.cancel();
    assert_eq!(
        worker.join().map_err(|_| "maintenance worker panicked")?,
        Ok(())
    );
    drop(services);
    drop(initialized);
    let reopened = ServiceHandle::new(fixture.reopen()?)?;
    assert_eq!(
        reopened
            .instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "restored poststart expiry task status")?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the exact poststart expiry completion remains durable after reopen"
    );
    Ok(())
}

#[test]
fn runtime_worker_retries_a_running_expiry_after_terminal_publication_outage()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog_operation = services.catalog_operation()?;
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let coordinator = initialized.maintenance_coordinator();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        coordinator,
        0,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    drop(lease);
    drop(ledger);
    drop(catalog);
    drop(catalog_operation);
    elapsed.advance(1_000_000_000)?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker = std::thread::spawn(move || {
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 1, || {
            worker_services.run_maintenance_worker(&worker_cancellation)
        })
    });
    services.notify_maintenance_worker();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_running = false;
    while initialized
        .maintenance_coordinator()
        .status(task)
        .map_err(|_| "maintenance task status")?
        .phase()
        != MaintenanceTaskPhase::Succeeded
    {
        let phase = initialized
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "maintenance task status")?
            .phase();
        saw_running |= phase == MaintenanceTaskPhase::Running;
        if Instant::now() >= deadline {
            cancellation.cancel();
            return Err("worker did not retry running expiry".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        saw_running,
        "terminal-publication fault retains the same Running execution before retry"
    );
    cancellation.cancel();
    worker.join().map_err(|_| "maintenance worker panicked")??;
    Ok(())
}

#[test]
fn public_audit_checkpoint_reports_the_worker_task_before_artifact_publication()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let task = initialized.queue_governance_audit_checkpoint_for_test()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let cancellation = crate::TaskCancellation::new();
    // The runtime worker checks cancellation once before scheduling and once
    // after durably transitioning the selected task to Running, before any
    // handler can publish its checkpoint artifact.
    cancellation.cancel_after_polls(2);
    assert_eq!(
        services.wake_maintenance_worker_with_cancellation(&cancellation),
        Err(ServiceFailure::Cancelled)
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "audit task status")?
            .phase(),
        MaintenanceTaskPhase::Running
    );
    assert_eq!(
        initialized.latest_governance_audit_checkpoint_for_test()?,
        None,
        "the public caller arrives before the worker handler can publish an artifact"
    );

    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let attached = initialized
        .publish_governance_audit_checkpoint(actor)
        .expect_err(
            "the public caller must not claim storage is unavailable for a worker-owned task",
        );
    assert_eq!(
        attached.code(),
        crate::BootstrapFailureCode::GovernanceAuditCheckpointInProgress
    );
    assert_eq!(
        attached.maintenance_task(),
        Some(task),
        "the retryable result exposes the exact stable worker identity"
    );
    assert!(
        attached.to_string().ends_with(
            &task
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
        "the retryable public message provides the stable task identity without credential material"
    );
    assert_eq!(
        initialized.governance_audit_checkpoint_state_for_test()?,
        (false, 1),
        "the public request neither redispatches nor duplicates the worker-owned task"
    );
    drop(services);

    let recovered = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "recovered audit task status")?
            .phase(),
        MaintenanceTaskPhase::Queued,
        "restart recovery returns the interrupted worker task to its durable queue"
    );
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let checkpoint = initialized.publish_governance_audit_checkpoint(actor)?;
    assert_eq!(checkpoint.position(), 1);
    assert_eq!(
        initialized.governance_audit_checkpoint_state_for_test()?,
        (true, 1),
        "retry completes the recovered worker task instead of granting a duplicate"
    );
    drop(recovered);
    Ok(())
}

#[test]
fn public_audit_checkpoint_returns_a_running_worker_artifact_without_redispatch()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let task = initialized.queue_governance_audit_checkpoint_for_test()?;
    let worker_checkpoint =
        initialized.publish_running_governance_audit_checkpoint_for_test(task)?;
    assert_eq!(
        initialized.governance_audit_checkpoint_phase_for_test(task)?,
        MaintenanceTaskPhase::Running,
        "the handler published before terminalization"
    );

    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        initialized.publish_governance_audit_checkpoint(actor)?,
        worker_checkpoint,
        "the authenticated public call reads the worker-owned signed artifact"
    );
    assert_eq!(
        initialized.governance_audit_checkpoint_phase_for_test(task)?,
        MaintenanceTaskPhase::Running,
        "reading the artifact does not redispatch or terminalize the worker task"
    );
    assert_eq!(
        initialized.governance_audit_checkpoint_state_for_test()?,
        (true, 1),
        "attachment retains one durable artifact and one stable task"
    );
    Ok(())
}

#[test]
fn native_runtime_worker_expires_a_durable_lease_and_joins_before_reopen()
-> Result<(), Box<dyn Error>> {
    let _test_guard = live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    let coordinator = initialized.maintenance_coordinator();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        coordinator,
        0,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    drop(lease);
    drop(ledger);
    drop(catalog);
    elapsed.advance(1_000_000_000)?;
    drop(initialized);

    let [operations, api, otlp_grpc, otlp_http, loki_push] = reserve_native_addresses()?;
    static NEXT_NATIVE_CONTROL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let control = std::env::temp_dir().join(format!(
        "positron-maintenance-worker-{}-{}.sock",
        std::process::id(),
        NEXT_NATIVE_CONTROL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    match fs::remove_file(&control) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let host = NativeHost::new(NativeBindings::new(
        control, operations, api, otlp_grpc, otlp_http, loki_push,
    )?);
    let paths = BootstrapPaths::new(
        &fixture.root.join("data"),
        &fixture.root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let services = process.services().ok_or("serving services")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while services
        .instance
        .maintenance_coordinator()
        .status(task)
        .map_err(|_| "maintenance task status")?
        .phase()
        != MaintenanceTaskPhase::Succeeded
    {
        if Instant::now() >= deadline {
            return Err("native maintenance worker did not complete the due lease expiry".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful,
        "shutdown joins the internal maintenance worker"
    );

    let reopened = fixture.reopen()?;
    let restored = ServiceHandle::new(reopened)?;
    assert_eq!(
        restored
            .instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|_| "maintenance task status")?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the worker-published terminal result survives reopen"
    );
    Ok(())
}

#[test]
fn crash_without_publication_rebuilds_from_committed_blocks() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("replayed").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop(services);

    let reopened = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        reopened.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["replayed"]
    );
    Ok(())
}

#[test]
fn shutdown_capacity_is_reserved_before_admission_closes_and_released_after_publish()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("shutdown").encode_to_vec())?
            .accepted_records(),
        1
    );
    services
        .prepare_shutdown_schema_checkpoint()
        .map_err(|failure| format!("prepare shutdown checkpoint: {failure:?}"))?;
    services
        .publish_prepared_shutdown_schema_checkpoint(&mut || false)
        .map_err(|failure| format!("publish shutdown checkpoint: {failure:?}"))?;
    let after = initialized._authority.begin_shutdown()?;
    assert_eq!(
        after.outstanding_for(WorkClass::OrdinaryMaintenanceBackup),
        0
    );
    Ok(())
}

#[test]
fn unchanged_session_skips_shutdown_checkpoint_publication() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let initial_audits = schema_audit_count(&initialized)?;

    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint(&mut || false)?;

    assert_eq!(schema_audit_count(&initialized)?, initial_audits);
    let after = initialized._authority.begin_shutdown()?;
    assert_eq!(
        after.outstanding_for(WorkClass::OrdinaryMaintenanceBackup),
        0
    );
    Ok(())
}

#[test]
fn failed_shutdown_publication_releases_its_pre_admitted_capacity() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("shutdown-failure").encode_to_vec())?
            .accepted_records(),
        1
    );
    services.prepare_shutdown_schema_checkpoint()?;
    publish_unrelated_bytes(&initialized, vec![0x55; 1_048_576])?;
    initialized._authority.begin_shutdown()?;
    assert!(
        services
            .publish_prepared_shutdown_schema_checkpoint(&mut || false)
            .is_err()
    );
    let after = initialized._authority.begin_shutdown()?;
    assert_eq!(
        after.outstanding_for(WorkClass::OrdinaryMaintenanceBackup),
        0
    );
    Ok(())
}

#[test]
fn quiescent_publication_is_tenant_bound_and_same_content_is_idempotent()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let checkpoint = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?;
    let audits = schema_audit_count(&initialized)?;

    schema_maintenance::publish_quiescent_checkpoint(&initialized, checkpoint)?;
    assert_eq!(schema_audit_count(&initialized)?, audits + 1);
    let checkpoint = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?;
    schema_maintenance::publish_quiescent_checkpoint(&initialized, checkpoint)?;
    assert_eq!(schema_audit_count(&initialized)?, audits + 1);

    let other_fixture = Fixture::new()?;
    let (other, _, _) = other_fixture.initialized()?;
    let other_services = ServiceHandle::new(Arc::clone(&other))?;
    let foreign = other_services
        .schema_sessions
        .session(other.tenant, other.resource_governor())?
        .checkpoint()?;
    assert_eq!(
        schema_maintenance::publish_quiescent_checkpoint(&initialized, foreign),
        Err(ServiceFailure::CorruptState)
    );
    Ok(())
}
