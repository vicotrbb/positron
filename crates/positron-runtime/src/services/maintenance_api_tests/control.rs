use super::*;

#[test]
fn authenticated_run_prepares_one_sealed_compaction_task_and_replays_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("run-api-sealed-source").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let request = MaintenanceRunRequest::new(
        "compaction".to_owned(),
        initialized.default_tenant_id().to_canonical_text(),
        "logs".to_owned(),
        scope.shard_id().value(),
        "00000000-0000-0000-0000-000000000001".to_owned(),
    );
    let body = request.encode()?;
    let first = services
        .run_maintenance(&administrator, &body)
        .map_err(|failure| format!("first run: {failure:?}"))?;
    assert_eq!(first.task.class, "compaction");
    assert_eq!(first.resource_generation, 1);
    assert!(
        open_catalog(&initialized)?
            .governance_audit_records()?
            .into_iter()
            .map(|record| positron_governance::GovernanceAuditEntry::decode(&record))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|entry| entry.action() == "maintenance.run"),
        "the first durable task submission must atomically leave immutable governance evidence"
    );
    let replay = services
        .run_maintenance(&administrator, &body)
        .map_err(|failure| format!("replayed run: {failure:?}"))?;
    assert_eq!(replay, first, "retry attaches to the durable task");
    let identity = super::task_identity(&first.task.identity).ok_or("task identity")?;
    let catalog = open_catalog(&initialized)?;
    initialized
        .maintenance_coordinator()
        .cancel_and_persist(&catalog, identity)
        .map_err(|failure| format!("terminal successor: {failure:?}"))?;
    for raw in 1..=128_u8 {
        let filler = MaintenanceTask::new(
            MaintenanceTaskId::new([raw; 16])
                .map_err(|failure| format!("filler identity: {failure:?}"))?,
            MaintenanceTaskClass::SchemaPromotion,
        );
        initialized
            .maintenance_coordinator()
            .submit_and_persist(&catalog, filler.clone(), 2)
            .map_err(|failure| format!("fill retained task capacity: {failure:?}"))?;
        initialized
            .maintenance_coordinator()
            .cancel_and_persist(&catalog, filler.identity())
            .map_err(|failure| format!("terminal filler task: {failure:?}"))?;
    }
    assert!(matches!(
        initialized.maintenance_coordinator().status(identity),
        Err(positron_kernel::MaintenanceFailure::UnknownTask)
    ));
    drop(catalog);
    assert_eq!(
        services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("terminal replay: {failure:?}"))?,
        first,
        "a terminal successor cannot change the durable run acknowledgement"
    );
    let conflicting = MaintenanceRunRequest::new(
        "compaction".to_owned(),
        initialized.default_tenant_id().to_canonical_text(),
        "traces".to_owned(),
        scope.shard_id().value(),
        "00000000-0000-0000-0000-000000000001".to_owned(),
    )
    .encode()?;
    assert_eq!(
        services.run_maintenance(&administrator, &conflicting),
        Err(MaintenanceServiceFailure::IdempotencyConflict),
        "a retained immutable receipt rejects a different request before source lookup"
    );
    drop(services);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        restored_services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("reopened terminal replay: {failure:?}"))?,
        first,
        "a reopened terminal successor cannot change the durable run acknowledgement"
    );
    assert!(
        matches!(
            reopened.maintenance_coordinator().status(identity),
            Err(positron_kernel::MaintenanceFailure::UnknownTask)
        ),
        "terminal retention reclamation removes the mutable task record while the audit receipt remains replayable after reopen"
    );
    Ok(())
}

#[test]
fn authenticated_run_terminalizes_a_one_segment_log_compaction()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("run-api-one-segment").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);

    let body = MaintenanceRunRequest::new(
        "compaction".to_owned(),
        initialized.default_tenant_id().to_canonical_text(),
        "logs".to_owned(),
        scope.shard_id().value(),
        "00000000-0000-0000-0000-000000000021".to_owned(),
    )
    .encode()?;
    let response = services
        .run_maintenance(&administrator, &body)
        .map_err(|failure| format!("one-segment run: {failure:?}"))?;
    let identity = super::task_identity(&response.task.identity).ok_or("task identity")?;

    assert!(
        services.wake_maintenance_worker()?,
        "the public Run task dispatches through the bounded worker"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("one-segment status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "a selected sealed source with one segment has no compaction work but still terminalizes"
    );
    Ok(())
}

#[test]
fn authenticated_run_keeps_audit_and_task_publication_atomic_across_faults()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("run-fault-sealed-source").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let request = MaintenanceRunRequest::new(
        "compaction".to_owned(),
        initialized.default_tenant_id().to_canonical_text(),
        "logs".to_owned(),
        scope.shard_id().value(),
        "00000000-0000-0000-0000-000000000031".to_owned(),
    );
    let body = request.encode()?;
    let rejected =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            services.run_maintenance(&administrator, &body)
        });
    assert_eq!(
        rejected,
        Err(MaintenanceServiceFailure::AdministrationUnavailable)
    );
    assert!(
        initialized
            .maintenance_coordinator()
            .statuses()
            .map_err(|failure| format!("coordinator status: {failure:?}"))?
            .is_empty(),
        "the in-memory coordinator cannot expose a descriptor whose catalog publication failed"
    );
    assert!(
        open_catalog(&initialized)?
            .governance_audit_records()?
            .into_iter()
            .map(|record| positron_governance::GovernanceAuditEntry::decode(&record))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .all(|entry| entry.action() != "maintenance.run"),
        "a failed pre-publication commit leaves neither a Run receipt nor a task descriptor"
    );
    let first = services
        .run_maintenance(&administrator, &body)
        .map_err(|failure| format!("retry after rejected publication: {failure:?}"))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .durable_records()
            .map_err(|failure| format!("coordinator records: {failure:?}"))?
            .len(),
        1,
        "the retry publishes one descriptor only after the rejected transaction left no durable state"
    );
    assert_eq!(
        services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("retry acknowledgement: {failure:?}"))?,
        first
    );
    Ok(())
}

#[test]
fn authenticated_run_reconciles_a_lost_publication_acknowledgement_once()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("run-lost-ack-source").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let body = MaintenanceRunRequest::new(
        "compaction".to_owned(),
        initialized.default_tenant_id().to_canonical_text(),
        "logs".to_owned(),
        scope.shard_id().value(),
        "00000000-0000-0000-0000-000000000032".to_owned(),
    )
    .encode()?;
    let acknowledged = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || services.run_maintenance(&administrator, &body),
    )
    .map_err(|failure| format!("reconcile lost acknowledgement: {failure:?}"))?;
    let replay = services
        .run_maintenance(&administrator, &body)
        .map_err(|failure| format!("replay reconciled acknowledgement: {failure:?}"))?;
    assert_eq!(
        replay, acknowledged,
        "a post-marker fault reconciles the same immutable acknowledgement before responding"
    );
    assert_eq!(
        services
            .run_maintenance(&administrator, &body)
            .map_err(|failure| format!("repeat reconciled acknowledgement: {failure:?}"))?,
        replay,
        "identical retries expose one immutable acknowledgement"
    );
    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("reconciled status: {failure:?}"))?;
    assert_eq!(status.total, 1);
    assert_eq!(status.tasks.len(), 1);
    assert_eq!(status.tasks[0].identity, replay.task.identity);
    let runs = open_catalog(&initialized)?
        .governance_audit_records()?
        .into_iter()
        .map(|record| positron_governance::GovernanceAuditEntry::decode(&record))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| entry.action() == "maintenance.run")
        .count();
    assert_eq!(runs, 1, "the lost acknowledgement retains one audit intent");
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .durable_records()
            .map_err(|failure| format!("reconciled records: {failure:?}"))?
            .len(),
        1,
        "the audit receipt and coordinator registry retain one task identity"
    );
    Ok(())
}

#[test]
fn maintenance_run_rejects_unauthenticated_requests_before_decoding()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    assert_eq!(
        services.run_maintenance("not-a-credential", br#"{\"unknown\":true}"#),
        Err(MaintenanceServiceFailure::AuthenticationRejected),
        "authentication precedes decoding"
    );
    Ok(())
}

#[test]
fn authenticated_pause_and_resume_replay_durably_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("pause-api-sealed-source").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    let run = MaintenanceRunRequest::new(
        "compaction".to_owned(),
        initialized.default_tenant_id().to_canonical_text(),
        "logs".to_owned(),
        scope.shard_id().value(),
        "00000000-0000-0000-0000-000000000011".to_owned(),
    );
    let task = services
        .run_maintenance(&administrator, &run.encode()?)
        .map_err(|failure| format!("run task: {failure:?}"))?
        .task;
    let pause = MaintenancePauseRequest::new(
        task.identity.clone(),
        1,
        60,
        "00000000-0000-0000-0000-000000000012".to_owned(),
    );
    let paused = services
        .pause_maintenance(&administrator, &pause.encode()?)
        .map_err(|failure| format!("pause task: {failure:?}"))?;
    assert_eq!(paused.action, "pause");
    assert_eq!(paused.resource_generation, Some(1));
    assert!(paused.pause_until_unix_seconds.is_some());
    assert_ne!(paused.audit_position, 0);
    let status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("paused status: {failure:?}"))?;
    assert_eq!(status.returned, 1);
    assert_eq!(status.total, 1);
    assert_eq!(status.next_cursor, None);
    assert_eq!(status.queued, 0);
    assert_eq!(status.running, 0);
    assert_eq!(status.deferred, 1);
    assert_eq!(status.terminal, 0);
    let observed = status
        .tasks
        .iter()
        .find(|candidate| candidate.identity == task.identity)
        .ok_or("paused task status")?;
    assert_eq!(
        observed.blocked_precondition.as_deref(),
        Some("maintenance_pause_active"),
        "status reports the durable scheduling precondition"
    );
    assert_eq!(observed.resource_generation, Some(1));
    assert_eq!(
        observed
            .reservations
            .as_ref()
            .ok_or("task reservation profile")?
            .task_slots,
        1
    );
    assert_eq!(
        observed
            .expected_foreground_impact
            .as_ref()
            .ok_or("foreground impact")?
            .task_slots,
        1,
        "the declared task reservation is the exact foreground-impact estimate"
    );
    assert_eq!(
        observed.capacity_risk.as_deref(),
        Some("foreground_reservation"),
        "the current reservation truthfully identifies foreground capacity contention"
    );
    assert_eq!(observed.retention_impact.as_deref(), Some("unaffected"));
    assert_eq!(observed.recovery_impact.as_deref(), Some("unaffected"));
    assert_eq!(
        observed.automatic_resume_at_unix_seconds, observed.pause_until_unix_seconds,
        "a finite pause exposes its authoritative automatic-resume time"
    );
    assert_eq!(observed.safe_actions, ["resume"]);
    assert!(observed.backlog_age_seconds.is_some());
    assert_eq!(observed.conflict_owner, None);
    assert_eq!(observed.checkpoint_completed_inputs, Some(0));
    assert_eq!(observed.input_object_count, 1);
    assert_eq!(observed.output_object_count, 0);
    assert_eq!(observed.estimated_output_object_amplification_milli, None);
    assert_eq!(observed.terminal_outcome, None);
    let expected_window_generation = open_catalog(&initialized)?.pin()?.number();
    let window_request = MaintenanceWindowRequest::new(
        vec!["compaction".to_owned()],
        expected_window_generation,
        120,
        "00000000-0000-0000-0000-000000000014".to_owned(),
    );
    let window = services
        .set_maintenance_window(&administrator, &window_request.encode()?)
        .map_err(|failure| format!("overlapping window: {failure:?}"))?;
    let overlapping_status = services
        .maintenance_status(&administrator, br"{}")
        .map_err(|failure| format!("overlapping status: {failure:?}"))?;
    let overlapping = overlapping_status
        .tasks
        .iter()
        .find(|candidate| candidate.identity == task.identity)
        .ok_or("overlapping task status")?;
    assert_eq!(
        overlapping.blocked_precondition.as_deref(),
        Some("maintenance_pause_active"),
        "the task-specific pause remains the immediate scheduler blocker"
    );
    assert_eq!(
        overlapping.maintenance_window_until_unix_seconds,
        Some(window.until_unix_seconds),
        "status retains the concurrent global window rather than hiding it behind the pause"
    );
    assert_eq!(
        overlapping.automatic_resume_at_unix_seconds,
        Some(window.until_unix_seconds),
        "automatic resume means the earliest execution time after every finite deferral"
    );
    assert_eq!(
        services
            .pause_maintenance(&administrator, &pause.encode()?)
            .map_err(|failure| format!("replay pause: {failure:?}"))?,
        paused,
        "an exact operator retry replays its acknowledged durable pause"
    );
    let conflicting_pause = MaintenancePauseRequest::new(
        task.identity.clone(),
        1,
        61,
        "00000000-0000-0000-0000-000000000012".to_owned(),
    );
    assert_eq!(
        services.pause_maintenance(&administrator, &conflicting_pause.encode()?),
        Err(MaintenanceServiceFailure::IdempotencyConflict)
    );
    let identity = super::task_identity(&task.identity).ok_or("task identity")?;
    drop(services);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    let reopened_phase = {
        let coordinator_handle = reopened.maintenance_coordinator();
        let coordinator = coordinator_handle;
        coordinator
            .status(identity)
            .map_err(|failure| format!("reopened task: {failure:?}"))?
            .phase()
    };
    assert_eq!(reopened_phase, MaintenanceTaskPhase::Deferred);
    let resume = MaintenanceResumeRequest::new(
        task.identity,
        "00000000-0000-0000-0000-000000000013".to_owned(),
    );
    let resumed = services
        .resume_maintenance(&administrator, &resume.encode()?)
        .map_err(|failure| format!("resume task: {failure:?}"))?;
    assert_eq!(resumed.action, "resume");
    assert_eq!(resumed.resource_generation, None);
    assert_eq!(resumed.pause_until_unix_seconds, None);
    assert_eq!(
        resumed.task, paused.task,
        "both controls identify the same immutable task descriptor"
    );
    assert_eq!(
        services
            .resume_maintenance(&administrator, &resume.encode()?)
            .map_err(|failure| format!("replay resume: {failure:?}"))?,
        resumed,
        "an exact operator retry replays its acknowledged durable resume"
    );
    assert_eq!(
        services
            .pause_maintenance(&administrator, &pause.encode()?)
            .map_err(|failure| format!("pause replay after successor: {failure:?}"))?,
        paused,
        "a later resume cannot change the acknowledged pause receipt"
    );
    Ok(())
}

#[test]
fn authenticated_pause_rejects_emergency_compaction_without_audit_or_transition()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let task = MaintenanceTask::new(
        MaintenanceTaskId::new([0x83; 16]).map_err(|_| "task identity")?,
        MaintenanceTaskClass::Compaction,
    )
    .emergency_compaction_for_test()
    .map_err(|_| "emergency compaction")?;
    let identity = task.identity();
    let audit_count = open_catalog(&initialized)?
        .governance_audit_records()?
        .len();
    initialized
        .maintenance_coordinator()
        .submit(task)
        .map_err(|failure| format!("submit emergency task: {failure:?}"))?;
    let pause = MaintenancePauseRequest::new(
        super::hex(identity.to_bytes()),
        1,
        60,
        "00000000-0000-0000-0000-000000000083".to_owned(),
    );
    assert_eq!(
        services.pause_maintenance(&administrator, &pause.encode()?),
        Err(MaintenanceServiceFailure::PreconditionFailed),
        "ADR-0071 forbids an authenticated expiring pause from deferring emergency work"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("emergency task status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Queued,
        "rejected pause must not change the durable scheduler phase"
    );
    assert_eq!(
        open_catalog(&initialized)?
            .governance_audit_records()?
            .len(),
        audit_count,
        "rejected pause must not publish an immutable control receipt"
    );
    Ok(())
}
