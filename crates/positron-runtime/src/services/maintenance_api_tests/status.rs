use super::*;

#[test]
fn maximal_integrity_findings_page_tasks_within_the_canonical_transport_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let finding = IntegrityQuarantineDescriptor {
        tenant: "00000000-0000-0000-0000-000000000001".to_owned(),
        signal: "logs".to_owned(),
        shard: 1,
        segment: "00000000000000000000000000000001".to_owned(),
        base_position: u64::MAX,
        event_range: AuthenticatedTimeRangeDescriptor {
            provenance: "missing_source_time".to_owned(),
            earliest_unix_nanos: None,
            latest_unix_nanos: None,
        },
        ingest_range: AuthenticatedTimeRangeDescriptor {
            provenance: "known".to_owned(),
            earliest_unix_nanos: Some(i64::MAX),
            latest_unix_nanos: Some(i64::MAX),
        },
    };
    let mut response = MaintenanceStatusResponse {
        tasks: Vec::with_capacity(MAX_STATUS_PAGE_TASKS),
        returned: 0,
        total: MAX_STATUS_PAGE_TASKS as u32,
        next_cursor: None,
        queued: 0,
        running: MAX_STATUS_PAGE_TASKS as u32,
        deferred: 0,
        terminal: 0,
        integrity_findings: vec![finding; MAX_INTEGRITY_FINDINGS],
    };
    for index in 0..MAX_STATUS_PAGE_TASKS {
        let continued = super::append_status_task_within_response_limit(
            &mut response,
            maximal_status_task(index),
            MAX_STATUS_PAGE_TASKS,
        )
        .map_err(|failure| format!("combined status page: {failure:?}"))?;
        if !continued {
            break;
        }
    }
    assert!(response.returned > 0, "a full evidence page must advance");
    assert!(response.returned < MAX_STATUS_PAGE_TASKS as u32);
    assert!(response.next_cursor.is_some());
    assert!(
        response.encode().is_ok(),
        "the served page fits the wire limit"
    );
    Ok(())
}

fn maximal_status_task(index: usize) -> MaintenanceTaskStatus {
    MaintenanceTaskStatus {
        identity: format!("{index:032x}"),
        class: "catalog_reclamation".to_owned(),
        scope: "segment:00000000-0000-0000-0000-000000000001:traces:4294967295".to_owned(),
        phase: "running".to_owned(),
        submitted_at_unix_seconds: u64::MAX,
        checkpoint_sequence: Some(u64::MAX),
        last_progress_at_unix_seconds: Some(u64::MAX),
        no_durable_progress_slo_breached: Some(true),
        no_durable_progress_slo_seconds: Some(u64::MAX),
        capacity_risk: Some("foreground_reservation".to_owned()),
        retention_impact: Some("unaffected".to_owned()),
        recovery_impact: Some("unaffected".to_owned()),
        automatic_resume_at_unix_seconds: Some(u64::MAX),
        pause_until_unix_seconds: None,
        cancellation_requested: false,
        resource_generation: Some(u64::MAX),
        reservations: Some(maximal_reservations()),
        expected_foreground_impact: Some(maximal_reservations()),
        blocked_precondition: Some("maintenance_window_active".to_owned()),
        maintenance_window_until_unix_seconds: Some(u64::MAX),
        safe_actions: vec!["pause".to_owned()],
        backlog_age_seconds: Some(u64::MAX),
        conflict_owner: Some(format!("{:032x}", (index + 1) % 128)),
        checkpoint_completed_inputs: Some(16),
        input_object_count: 16,
        output_object_count: 16,
        estimated_output_object_amplification_milli: Some(1_000),
        terminal_outcome: None,
        terminal_failure_class: None,
    }
}

fn maximal_reservations() -> MaintenanceResourceReservations {
    MaintenanceResourceReservations {
        memory_bytes: u64::MAX,
        queue_slots: u64::MAX,
        task_slots: u64::MAX,
        buffer_cache_bytes: u64::MAX,
        batch_items: u64::MAX,
        lease_slots: u64::MAX,
        retry_slots: u64::MAX,
        io_permits: u64::MAX,
        cpu_work_units: u64::MAX,
        file_descriptors: u64::MAX,
        disk_headroom_bytes: u64::MAX,
    }
}

#[test]
fn authenticated_maintenance_status_waits_for_catalog_ownership_before_attribution()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = Arc::new(ServiceHandle::new(initialized)?);
    let catalog_operation = services.catalog_operation()?;
    let barrier = Arc::new(Barrier::new(2));
    let (sender, receiver) = mpsc::sync_channel(1);
    let request_services = Arc::clone(&services);
    let request_barrier = Arc::clone(&barrier);
    let request = std::thread::spawn(move || {
        request_barrier.wait();
        let result = request_services
            .maintenance_status(&administrator, br"{}")
            .map(|_| ());
        let _ = sender.send(result);
    });
    barrier.wait();
    assert!(
        receiver.recv_timeout(Duration::from_millis(100)).is_err(),
        "maintenance attribution bypassed the catalog-operation gate"
    );
    drop(catalog_operation);
    assert_eq!(
        receiver
            .recv_timeout(Duration::from_secs(1))
            .map_err(|_| "maintenance request did not resume")?,
        Ok(())
    );
    request
        .join()
        .map_err(|_| "maintenance request thread panicked")?;
    Ok(())
}

#[test]
fn authenticated_status_and_explain_report_a_durable_terminal_failure_class()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let mut initialized = Arc::try_unwrap(initialized)
        .map_err(|_| "maintenance fixture retains the initialized instance")?;
    let task = initialized.queue_governance_audit_checkpoint_for_test()?;
    initialized.rotate_governance_audit_fingerprint_for_test([0xa5; 32])?;
    let failure = initialized
        .complete_queued_governance_audit_checkpoint_for_test(task)
        .expect_err("retired identity binding must terminalize");
    assert_eq!(
        failure.code(),
        crate::BootstrapFailureCode::IdentityMismatch
    );
    let initialized = Arc::new(initialized);
    let services = ServiceHandle::new(initialized)?;
    let identity = super::hex(task.to_bytes());
    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("status: {failure:?}"))?;
    let observed = status
        .tasks
        .into_iter()
        .find(|candidate| candidate.identity == identity)
        .ok_or("failed task missing from status")?;
    assert_eq!(observed.phase, "failed");
    assert_eq!(
        observed.terminal_failure_class.as_deref(),
        Some("identity_mismatch")
    );
    let explained = services
        .explain_maintenance_task(
            &administrator,
            &serde_json::to_vec(&MaintenanceExplainRequest { identity })?,
        )
        .map_err(|failure| format!("explain: {failure:?}"))?;
    assert_eq!(
        explained.task.terminal_failure_class.as_deref(),
        Some("identity_mismatch")
    );
    Ok(())
}

#[test]
fn authenticated_status_and_explain_report_the_durable_progress_deadline_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let mut initialized = Arc::try_unwrap(initialized)
        .map_err(|_| "maintenance fixture retains the initialized instance")?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(1_000_000_000));
    initialized.install_retention_time_for_test(retention_time)?;
    let initialized = Arc::new(initialized);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let operations = crate::health::ProcessState::starting();
    operations.set_inspection_authority(Arc::clone(&initialized))?;
    operations.set_catalog_operation(services.catalog_operation_gate())?;
    let identity = initialized.queue_governance_audit_checkpoint_for_test()?;
    let catalog = open_catalog(&initialized)?;
    let execution = initialized
        .maintenance_coordinator()
        .start_task_with_reservation_and_persist(
            &catalog,
            &initialized._authority,
            1,
            false,
            identity,
        )
        .map_err(|failure| format!("durably start task: {failure:?}"))?
        .ok_or("running task was not selected")?;
    drop(execution);
    drop(catalog);
    let rendered_identity = super::hex(identity.to_bytes());

    elapsed.advance(59_000_000_000)?;
    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("pre-deadline status: {failure:?}"))?;
    let observed = status
        .tasks
        .into_iter()
        .find(|candidate| candidate.identity == rendered_identity)
        .ok_or("running task missing before deadline")?;
    assert_eq!(observed.phase, "running");
    assert_eq!(observed.last_progress_at_unix_seconds, Some(1));
    assert_eq!(observed.no_durable_progress_slo_seconds, Some(60));
    assert_eq!(observed.no_durable_progress_slo_breached, Some(false));
    let explain = services
        .explain_maintenance_task(
            &administrator,
            &serde_json::to_vec(&MaintenanceExplainRequest {
                identity: rendered_identity.clone(),
            })?,
        )
        .map_err(|failure| format!("pre-deadline explain: {failure:?}"))?;
    assert_eq!(explain.task.no_durable_progress_slo_seconds, Some(60));
    assert_eq!(explain.task.no_durable_progress_slo_breached, Some(false));
    let health = operations
        .health()
        .authorized_configuration_status(&administrator)
        .map_err(|failure| format!("pre-deadline operations health: {failure:?}"))?
        .maintenance;
    assert_eq!(health.running(), 1);
    assert_eq!(health.running_no_durable_progress_slo_breaches(), 0);
    assert_eq!(health.running_no_durable_progress_slo_unknown(), 0);

    elapsed.advance(1_000_000_000)?;
    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("deadline status: {failure:?}"))?;
    let observed = status
        .tasks
        .into_iter()
        .find(|candidate| candidate.identity == rendered_identity)
        .ok_or("running task missing at deadline")?;
    assert_eq!(observed.no_durable_progress_slo_breached, Some(true));
    let explain = services
        .explain_maintenance_task(
            &administrator,
            &serde_json::to_vec(&MaintenanceExplainRequest {
                identity: rendered_identity,
            })?,
        )
        .map_err(|failure| format!("deadline explain: {failure:?}"))?;
    assert_eq!(explain.task.no_durable_progress_slo_breached, Some(true));
    let health = operations
        .health()
        .authorized_configuration_status(&administrator)
        .map_err(|failure| format!("deadline operations health: {failure:?}"))?
        .maintenance;
    assert_eq!(health.running_no_durable_progress_slo_breaches(), 1);
    assert_eq!(health.running_no_durable_progress_slo_unknown(), 0);
    Ok(())
}

#[test]
fn authenticated_running_status_and_explain_report_progress_unknown_when_clock_is_uncertain()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let mut initialized = Arc::try_unwrap(initialized)
        .map_err(|_| "maintenance fixture retains the initialized instance")?;
    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(10_000_000_000)));
    initialized.install_retention_time_for_test(RetentionTimeAuthority::establish_with_source(
        MutableWallClock(Arc::clone(&wall)),
        LifecycleClockPolicy::new(10)?,
    )?)?;
    let scope = SegmentScope::new(
        initialized.default_tenant_id(),
        SignalKind::Logs,
        positron_domain::routing::VirtualShardId::new(1)?,
    );
    let now = initialized.retention_time.governance_time_seconds(scope)?;
    let initialized = Arc::new(initialized);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let operations = crate::health::ProcessState::starting();
    operations.set_inspection_authority(Arc::clone(&initialized))?;
    operations.set_catalog_operation(services.catalog_operation_gate())?;
    let identity = initialized.queue_governance_audit_checkpoint_for_test()?;
    let catalog = open_catalog(&initialized)?;
    let execution = initialized
        .maintenance_coordinator()
        .start_task_with_reservation_and_persist(
            &catalog,
            &initialized._authority,
            now,
            false,
            identity,
        )
        .map_err(|failure| format!("durably start task: {failure:?}"))?
        .ok_or("running task was not selected")?;
    drop(execution);
    drop(catalog);
    *wall.lock().map_err(|_| "maintenance test wall clock")? = UnixNanoseconds::new(500);
    initialized.retention_time.governance_time_seconds(scope)?;
    let rendered_identity = super::hex(identity.to_bytes());

    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("uncertain running status: {failure:?}"))?;
    let observed = status
        .tasks
        .into_iter()
        .find(|candidate| candidate.identity == rendered_identity)
        .ok_or("running uncertain task missing from status")?;
    assert_eq!(observed.phase, "running");
    assert_eq!(observed.no_durable_progress_slo_seconds, Some(60));
    assert_eq!(observed.no_durable_progress_slo_breached, None);
    assert_eq!(observed.backlog_age_seconds, None);
    let explain = services
        .explain_maintenance_task(
            &administrator,
            &serde_json::to_vec(&MaintenanceExplainRequest {
                identity: rendered_identity,
            })?,
        )
        .map_err(|failure| format!("uncertain running explain: {failure:?}"))?;
    assert_eq!(explain.task.no_durable_progress_slo_seconds, Some(60));
    assert_eq!(explain.task.no_durable_progress_slo_breached, None);
    assert_eq!(explain.task.backlog_age_seconds, None);
    let health = operations
        .health()
        .authorized_configuration_status(&administrator)
        .map_err(|failure| format!("uncertain operations health: {failure:?}"))?
        .maintenance;
    assert!(health.clock_uncertain());
    assert_eq!(health.running(), 1);
    assert_eq!(health.running_no_durable_progress_slo_breaches(), 0);
    assert_eq!(health.running_no_durable_progress_slo_unknown(), 1);
    Ok(())
}

#[test]
fn authenticated_status_and_explain_report_clock_uncertain_destructive_blocking()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let mut initialized = Arc::try_unwrap(initialized)
        .map_err(|_| "maintenance fixture retains the initialized instance")?;
    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(1_000)));
    initialized.install_retention_time_for_test(RetentionTimeAuthority::establish_with_source(
        MutableWallClock(Arc::clone(&wall)),
        LifecycleClockPolicy::new(10)?,
    )?)?;
    *wall.lock().map_err(|_| "maintenance test wall clock")? = UnixNanoseconds::new(500);
    let scope = SegmentScope::new(
        initialized.default_tenant_id(),
        SignalKind::Logs,
        positron_domain::routing::VirtualShardId::new(1)?,
    );
    initialized.retention_time.governance_time_seconds(scope)?;
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0x44; 16])
            .map_err(|failure| format!("maintenance identity: {failure:?}"))?,
        MaintenanceTaskClass::RepositoryCleanup,
        MaintenanceScope::System,
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(1, 1)
            .map_err(|failure| format!("maintenance preconditions: {failure:?}"))?,
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([64, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
    )
    .map_err(|failure| format!("scheduled destructive task: {failure:?}"))?;
    let initialized = Arc::new(initialized);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    initialized
        .maintenance_coordinator()
        .submit_at(task, 1)
        .map_err(|failure| format!("queue destructive task: {failure:?}"))?;

    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("uncertain maintenance status: {failure:?}"))?;
    let observed = status.tasks.first().ok_or("uncertain task status")?;
    assert_eq!(
        observed.blocked_precondition.as_deref(),
        Some("clock_uncertain_destructive_schedule")
    );
    assert_eq!(
        observed.backlog_age_seconds, None,
        "inspection must not invent an age from an uncertain lifecycle clock"
    );
    assert_eq!(
        observed.retention_impact.as_deref(),
        Some("eligibility_unknown")
    );
    assert_eq!(observed.automatic_resume_at_unix_seconds, None);
    let explain = services
        .explain_maintenance_task(
            &administrator,
            &serde_json::to_vec(&MaintenanceExplainRequest {
                identity: observed.identity.clone(),
            })?,
        )
        .map_err(|failure| format!("uncertain maintenance explain: {failure:?}"))?;
    assert_eq!(
        explain.task.blocked_precondition.as_deref(),
        Some("clock_uncertain_destructive_schedule")
    );
    assert_eq!(explain.task.backlog_age_seconds, None);
    Ok(())
}

#[test]
fn authenticated_status_and_explain_report_an_active_maintenance_window()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let task = MaintenanceTask::new(
        MaintenanceTaskId::new([0x51; 16])
            .map_err(|failure| format!("window identity: {failure:?}"))?,
        MaintenanceTaskClass::Compaction,
    );
    let identity = super::hex(task.identity().to_bytes());
    let now = services
        .maintenance_status_now()
        .map_err(|failure| format!("window clock: {failure:?}"))?;
    initialized
        .maintenance_coordinator()
        .submit_at(task, now)
        .map_err(|failure| format!("queue window task: {failure:?}"))?;
    let expected_catalog_generation = open_catalog(&initialized)?.pin()?.number();
    let window = services
        .set_maintenance_window(
            &administrator,
            &MaintenanceWindowRequest::new(
                vec!["compaction".to_owned()],
                expected_catalog_generation,
                60,
                "00000000-0000-0000-0000-000000000031".to_owned(),
            )
            .encode()?,
        )
        .map_err(|failure| format!("set window: {failure:?}"))?;
    assert!(window.until_unix_seconds >= now);

    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("window status: {failure:?}"))?;
    let observed = status
        .tasks
        .into_iter()
        .find(|candidate| candidate.identity == identity)
        .ok_or("window task missing from status")?;
    assert_eq!(
        observed.blocked_precondition.as_deref(),
        Some("maintenance_window_active")
    );
    assert_eq!(
        observed.maintenance_window_until_unix_seconds,
        Some(window.until_unix_seconds)
    );
    assert_eq!(
        observed.capacity_risk.as_deref(),
        Some("foreground_reservation")
    );
    assert_eq!(observed.retention_impact.as_deref(), Some("unaffected"));
    assert_eq!(observed.recovery_impact.as_deref(), Some("unaffected"));
    assert_eq!(
        observed.automatic_resume_at_unix_seconds,
        Some(window.until_unix_seconds)
    );

    let explain = services
        .explain_maintenance_task(
            &administrator,
            &serde_json::to_vec(&MaintenanceExplainRequest { identity })?,
        )
        .map_err(|failure| format!("window explain: {failure:?}"))?;
    assert_eq!(
        explain.task.blocked_precondition.as_deref(),
        Some("maintenance_window_active")
    );
    assert_eq!(
        explain.task.maintenance_window_until_unix_seconds,
        Some(window.until_unix_seconds)
    );
    assert_eq!(
        explain.task.automatic_resume_at_unix_seconds,
        Some(window.until_unix_seconds)
    );
    assert_eq!(
        explain.task.capacity_risk.as_deref(),
        Some("foreground_reservation")
    );
    assert_eq!(explain.task.retention_impact.as_deref(), Some("unaffected"));
    assert_eq!(explain.task.recovery_impact.as_deref(), Some("unaffected"));
    Ok(())
}

#[test]
fn authenticated_maintenance_status_pages_the_full_registry_without_hiding_queued_work()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    for value in 1_u8..=33 {
        initialized
            .maintenance_coordinator()
            .submit_at(
                MaintenanceTask::new(
                    MaintenanceTaskId::new([value; 16])
                        .map_err(|failure| format!("task identity: {failure:?}"))?,
                    MaintenanceTaskClass::SchemaStatistics,
                ),
                u64::from(value),
            )
            .map_err(|failure| format!("queued task: {failure:?}"))?;
    }

    let first = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("first page: {failure:?}"))?;
    assert_eq!(first.total, 33);
    assert_eq!(first.queued, 33);
    assert_eq!(first.returned, 32);
    let cursor = first.next_cursor.clone().ok_or("first page continuation")?;
    assert_eq!(first.tasks.len(), 32);
    let second_body = serde_json::to_vec(&MaintenanceStatusRequest::page_after(cursor, 32))?;
    let second = services
        .maintenance_status(&administrator, &second_body)
        .map_err(|failure| format!("second page: {failure:?}"))?;
    assert_eq!(second.total, 33);
    assert_eq!(second.queued, 33);
    assert_eq!(second.returned, 1);
    assert_eq!(second.next_cursor, None);
    assert_eq!(second.tasks.len(), 1);
    let second_task = second.tasks.first().ok_or("second page task")?;
    assert!(
        first
            .tasks
            .iter()
            .all(|first_task| first_task.identity != second_task.identity),
        "the continuation must expose the queued task omitted from the first bounded page"
    );
    Ok(())
}

#[test]
fn authenticated_status_reports_protected_recovery_reserve_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let task = MaintenanceTask::new(
        MaintenanceTaskId::new([0x82; 16]).map_err(|_| "task identity")?,
        MaintenanceTaskClass::CatalogReclamation,
    );
    let identity = task.identity();
    let catalog = open_catalog(&initialized)?;
    initialized
        .maintenance_coordinator()
        .submit_and_persist(&catalog, task, 1)
        .map_err(|failure| format!("submit recovery task: {failure:?}"))?;
    drop(catalog);
    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("status recovery task: {failure:?}"))?;
    let observed = status
        .tasks
        .iter()
        .find(|candidate| candidate.identity == super::hex(identity.to_bytes()))
        .ok_or("recovery task status")?;
    assert_eq!(
        observed.capacity_risk.as_deref(),
        Some("recovery_reserve"),
        "catalog reclamation is admitted through the protected Recovery Reserve"
    );
    assert_eq!(observed.retention_impact, None);
    assert_eq!(observed.recovery_impact, None);
    Ok(())
}

#[test]
fn clock_uncertainty_fails_readiness_without_failing_liveness()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, _) = fixture.initialized_with_admin()?;
    let mut initialized = Arc::try_unwrap(initialized).map_err(|_| "retained fixture")?;
    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(10_000_000_000)));
    initialized.install_retention_time_for_test(RetentionTimeAuthority::establish_with_source(
        MutableWallClock(Arc::clone(&wall)),
        LifecycleClockPolicy::new(1_000_000_000)?,
    )?)?;
    let initialized = Arc::new(initialized);
    let operations = crate::health::ProcessState::starting();
    operations.set_inspection_authority(Arc::clone(&initialized))?;
    operations.transition(crate::ProcessPhase::Serving);
    let health = operations.health();
    assert_eq!(
        health.readiness(),
        crate::Readiness::Ready,
        "clock={:?} resources={:?}",
        initialized.retention_time.status(),
        initialized.resource_governor().inspect()
    );
    *wall.lock().map_err(|_| "wall clock")? = UnixNanoseconds::new(5_000_000_000);
    let scope = SegmentScope::new(
        initialized.default_tenant_id(),
        SignalKind::Logs,
        positron_domain::routing::VirtualShardId::new(1)?,
    );
    initialized.retention_time.governance_time_seconds(scope)?;
    assert_eq!(health.readiness(), crate::Readiness::NotReady);
    initialized
        ._authority
        .with_control_contention_for_test(|| {
            assert_eq!(health.readiness(), crate::Readiness::NotReady)
        })?;
    assert_eq!(health.liveness(), crate::Liveness::Live);
    assert_eq!(health.phase(), crate::ProcessPhase::Serving);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.attach_health(health.clone());
    let outcome =
        services.ingest_otlp_logs(&ingest, request("uncertain-safe-ingest").encode_to_vec())?;
    assert_eq!(
        outcome.accepted_records(),
        1,
        "ingestion outcome: {outcome:?}"
    );
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(16)?
        )?,
        ["uncertain-safe-ingest"]
    );
    Ok(())
}

#[test]
fn disk_pressure_fails_readiness_and_restores_it_without_a_process_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, _) = fixture.initialized_with_admin()?;
    let operations = crate::health::ProcessState::starting();
    operations.set_inspection_authority(Arc::clone(&initialized))?;
    operations.transition(crate::ProcessPhase::Serving);
    let health = operations.health();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.attach_health(health.clone());
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("pressure-safe-read").encode_to_vec())?
            .accepted_records(),
        1
    );
    let usable = initialized
        .resource_governor()
        .inspect()?
        .usable_disk_bytes();
    assert_eq!(health.readiness(), crate::Readiness::Ready);
    let recovery_disk = initialized
        .resource_governor()
        .inspect()?
        .recovery_reserve_capacity(positron_kernel::ResourceDimension::DiskHeadroomBytes);
    initialized
        ._authority
        .observe_disk_for_fuzz(positron_kernel::DiskObservation::new(
            recovery_disk.saturating_sub(1),
        ))?;
    assert_eq!(
        initialized.resource_governor().inspect()?.disk_pressure(),
        positron_kernel::DiskPressureState::HardPressure
    );
    assert_eq!(health.readiness(), crate::Readiness::NotReady);
    initialized
        ._authority
        .with_control_contention_for_test(|| {
            assert_eq!(health.readiness(), crate::Readiness::NotReady)
        })?;
    assert_eq!(health.liveness(), crate::Liveness::Live);
    let result = services.query_log_bodies(
        &query,
        "logs | range query_time 0 100 | limit 16",
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(16)?,
    );
    assert_eq!(
        result,
        Ok(vec!["pressure-safe-read".to_owned()]),
        "resources={:?}",
        initialized.resource_governor().inspect()
    );
    let denied =
        services.ingest_otlp_logs(&ingest, request("pressure-refused-ingest").encode_to_vec());
    assert!(
        matches!(
            denied,
            Err(super::super::super::ServiceFailure::CapacityUnavailable)
        ),
        "disk-growing ingestion: {denied:?}"
    );
    initialized
        ._authority
        .observe_disk_for_fuzz(positron_kernel::DiskObservation::new(usable))?;
    assert_eq!(health.readiness(), crate::Readiness::Ready);
    assert_eq!(health.phase(), crate::ProcessPhase::Serving);
    Ok(())
}

#[test]
fn contended_canonical_fence_and_shutdown_keep_serving_health_not_ready()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, _) = fixture.initialized_with_admin()?;
    let state = crate::health::ProcessState::starting();
    state.set_inspection_authority(initialized.clone())?;
    state.transition(crate::ProcessPhase::Serving);
    let health = state.health();
    assert_eq!(health.readiness(), crate::Readiness::Ready);
    initialized
        ._authority
        .with_fenced_control_contention_for_test(|| {
            assert_eq!(health.phase(), crate::ProcessPhase::Serving);
            assert_eq!(health.readiness(), crate::Readiness::NotReady);
            assert!(matches!(
                initialized.resource_governor().inspect(),
                Err(positron_kernel::GovernorFailure::GovernorContended {
                    pressure: positron_kernel::DiskPressureState::Healthy
                })
            ));
        })?;
    let stopping_fixture = Fixture::new()?;
    let (stopping, _, _, _) = stopping_fixture.initialized_with_admin()?;
    let state = crate::health::ProcessState::starting();
    state.set_inspection_authority(stopping.clone())?;
    state.transition(crate::ProcessPhase::Serving);
    stopping._authority.begin_shutdown()?;
    stopping._authority.with_control_contention_for_test(|| {
        assert_eq!(state.health().readiness(), crate::Readiness::NotReady)
    })?;
    Ok(())
}
