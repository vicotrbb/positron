use super::*;

#[test]
fn runtime_maintenance_worker_verifies_a_durable_integrity_scrub_task() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let key = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    ActiveSegmentLedger::open(&initialized._authority, &catalog, scope, key)?.seal()?;
    let snapshot = catalog.pin()?;
    let generation = snapshot.number();
    let source_manifest = snapshot.integrity_scope_source_identity(scope)?;
    let task = MaintenanceTask::integrity_scrub(
        MaintenanceTaskId::new([0xdc; 16]).map_err(|_| "invalid task id")?,
        positron_kernel::MaintenanceScope::segment(
            scope.tenant_id(),
            scope.signal_kind(),
            scope.shard_id(),
        ),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(generation, 1).map_err(|_| "invalid preconditions")?,
        source_manifest,
        0,
    )
    .map_err(|_| "invalid integrity scrub task")?;
    let task_id = task.identity();
    initialized
        .maintenance_coordinator()
        .submit_and_persist(&catalog, task, 0)
        .map_err(|_| "submit integrity scrub task")?;
    drop(catalog);

    assert!(services.wake_maintenance_worker()?);
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task_id)
            .map_err(|_| "missing integrity scrub status")?
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}

#[test]
fn continuously_admitted_compaction_does_not_starve_due_integrity_scrub_discovery()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    let target_request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 10_000_000_000,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("scrub-target".to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    };
    let admitted = services.ingest_otlp_logs(&ingest, target_request.encode_to_vec())?;
    if admitted.accepted_records() != 1 {
        return Err(format!("authenticated scrub target admission: {admitted:?}").into());
    }
    let catalog = open_catalog(&initialized)?;
    let target_scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.tenant, SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("reachable authenticated logs target")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        target_scope,
        initialized.tenant_segment_key_for_test(target_scope)?,
    )?
    .seal()?;
    drop(catalog);

    assert_eq!(
        services
            .ingest_otlp_traces(
                &ingest,
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans {
                        scope_spans: vec![ScopeSpans {
                            spans: vec![Span {
                                trace_id: vec![0x82; 16],
                                span_id: vec![0x83; 8],
                                name: "continuous-compaction-work-one".to_owned(),
                                start_time_unix_nano: 10_000_000_001,
                                end_time_unix_nano: 10_000_000_002,
                                ..Span::default()
                            }],
                            ..ScopeSpans::default()
                        }],
                        ..ResourceSpans::default()
                    }]
                }
                .encode_to_vec(),
            )?
            .accepted_records(),
        1,
        "authenticated first compaction input"
    );
    let catalog = open_catalog(&initialized)?;
    let work_scope = catalog
        .pin()?
        .reachable_ledger_scopes(initialized.tenant, SignalKind::Traces)?
        .into_iter()
        .next()
        .ok_or("reachable authenticated traces work scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        work_scope,
        initialized.tenant_segment_key_for_test(work_scope)?,
    )?
    .seal()?;
    drop(catalog);
    assert_eq!(
        services
            .ingest_otlp_traces(
                &ingest,
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans {
                        scope_spans: vec![ScopeSpans {
                            spans: vec![Span {
                                trace_id: vec![0x84; 16],
                                span_id: vec![0x85; 8],
                                name: "continuous-compaction-work-two".to_owned(),
                                start_time_unix_nano: 10_000_000_003,
                                end_time_unix_nano: 10_000_000_004,
                                ..Span::default()
                            }],
                            ..ScopeSpans::default()
                        }],
                        ..ResourceSpans::default()
                    }]
                }
                .encode_to_vec(),
            )?
            .accepted_records(),
        1,
        "authenticated second compaction input"
    );
    let catalog = open_catalog(&initialized)?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        work_scope,
        initialized.tenant_segment_key_for_test(work_scope)?,
    )?
    .seal()?;
    let target_source = catalog
        .pin()?
        .integrity_scope_source_identity(target_scope)?;
    drop(catalog);

    let work_request = |turn: u8| {
        positron_api::maintenance::MaintenanceRunRequest::new(
            "compaction".to_owned(),
            initialized.default_tenant_id().to_canonical_text(),
            "traces".to_owned(),
            work_scope.shard_id().value(),
            format!("00000000-0000-0000-0000-{:012}", 82 + u32::from(turn)),
        )
    };
    for turn in 0..3_u8 {
        let request = work_request(turn);
        services
            .run_maintenance(&administrator, &request.encode()?)
            .map_err(|failure| {
                format!("admit continuously queued compaction {turn}: {failure:?}")
            })?;
        assert!(
            services
                .wake_maintenance_worker()
                .map_err(|failure| format!("continuous compaction worker {turn}: {failure:?}"))?,
            "each admitted public compaction must make bounded worker progress"
        );
    }

    let target_maintenance_scope = MaintenanceScope::segment(
        target_scope.tenant_id(),
        target_scope.signal_kind(),
        target_scope.shard_id(),
    );
    let statuses = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|failure| format!("statuses during continuous compaction: {failure:?}"))?;
    let scrub = statuses
        .iter()
        .find(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && status.task().scope() == target_maintenance_scope
        })
        .ok_or("continuous admitted compaction must not starve scrub discovery")?
        .task()
        .clone();
    assert_eq!(
        scrub.source_binding().map(|binding| binding.to_bytes()),
        Some(target_source),
        "the discovered scrub remains bound to the untouched authenticated target source"
    );
    let now = initialized
        .retention_time
        .governance_now_seconds()
        .map_err(|failure| format!("lifecycle clock after continuous backlog: {failure:?}"))?;
    elapsed.advance(
        scrub
            .not_before()
            .checked_sub(now)
            .ok_or("scheduled integrity due remains monotonic")?
            .checked_mul(1_000_000_000)
            .ok_or("scheduled integrity due nanos")?,
    )?;
    let due_now = initialized
        .retention_time
        .governance_now_seconds()
        .map_err(|failure| format!("lifecycle clock after advance: {failure:?}"))?;
    assert!(
        due_now >= scrub.not_before(),
        "the persisted target descriptor must be actually due before fairness is tested"
    );
    for turn in 3..11_u8 {
        let due_work = work_request(turn);
        services
            .run_maintenance(&administrator, &due_work.encode()?)
            .map_err(|failure| {
                format!("admit continuous work beside due scrub {turn}: {failure:?}")
            })?;
        let live_now = initialized
            .retention_time
            .governance_now_seconds()
            .map_err(|failure| format!("lifecycle clock beside due scrub {turn}: {failure:?}"))?;
        assert!(
            live_now >= scrub.not_before(),
            "public compaction must not roll the persisted due scrub backward: turn={turn}, live_now={live_now}, due={}",
            scrub.not_before()
        );
        if let Err(failure) = services.wake_maintenance_worker() {
            let statuses =
                initialized
                    .maintenance_coordinator()
                    .statuses()
                    .map_err(|status_failure| {
                        format!("due scrub status after worker {turn}: {status_failure:?}")
                    })?;
            let resources =
                initialized
                    .resource_governor()
                    .inspect()
                    .map_err(|resource_failure| {
                        format!("due scrub resources after worker {turn}: {resource_failure:?}")
                    })?;
            return Err(format!(
                "due scrub worker {turn}: {failure:?}; statuses={statuses:?}; resources={resources:?}"
            )
            .into());
        }
        let statuses = initialized
            .maintenance_coordinator()
            .statuses()
            .map_err(|failure| format!("due scrub statuses {turn}: {failure:?}"))?;
        if statuses.iter().any(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && status.task().scope() == target_maintenance_scope
                && status.phase() == MaintenanceTaskPhase::Succeeded
        }) {
            return Ok(());
        }
    }
    let statuses = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|failure| format!("final continuous maintenance statuses: {failure:?}"))?;
    let resources = initialized
        .resource_governor()
        .inspect()
        .map_err(|failure| format!("due target resource inspection: {failure:?}"))?;
    let live_now = initialized
        .retention_time
        .governance_now_seconds()
        .map_err(|failure| format!("live lifecycle clock after continuous work: {failure:?}"))?;
    let target_identity = scrub
        .identity()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let public_explanation = services
        .explain_maintenance_task(
            &administrator,
            &serde_json::to_vec(&positron_api::maintenance::MaintenanceExplainRequest {
                identity: target_identity,
            })?,
        )
        .map(|response| response.task)
        .map_err(|failure| format!("due target public explanation: {failure:?}"))?;
    let selector_catalog = open_catalog(&initialized)?;
    let selector_result = match initialized
        .maintenance_coordinator()
        .start_next_with_reservation_and_persist(
            &selector_catalog,
            &initialized._authority,
            due_now,
            false,
        ) {
        Ok(Some(execution)) => format!("selected {:?}", execution.task().identity()),
        Ok(None) => "no eligible task".to_owned(),
        Err(failure) => format!("selection failed: {failure:?}"),
    };
    let direct_admission = positron_kernel::RecoveryWorkClaim::tenant(
        initialized.tenant,
        positron_kernel::RecoveryWorkKind::Repair,
        scrub.reservations(),
    )?;
    let direct_admission = match initialized._authority.recovery().reserve(direct_admission) {
        Ok(reservation) => {
            drop(reservation);
            "admitted"
        },
        Err(failure) => {
            return Err(format!(
                "due target repair admission was refused: {failure:?}; statuses={statuses:?}, resources={resources:?}"
            )
            .into());
        },
    };
    Err(format!(
        "due target scrub did not progress while public compaction continued despite {direct_admission} repair admission, elapsed={}ns, previously_due={due_now}, live_now={live_now}, public explanation {public_explanation:?}, and selector result {selector_result}: statuses={statuses:?}, resources={resources:?}", elapsed.nanoseconds()
    )
    .into())
}

#[test]
fn queued_integrity_scrub_with_a_stale_source_binding_never_scans_or_succeeds()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let key = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    ActiveSegmentLedger::open(&initialized._authority, &catalog, scope, key)?.seal()?;
    let snapshot = catalog.pin()?;
    let task = MaintenanceTask::integrity_scrub(
        MaintenanceTaskId::new([0xde; 16]).map_err(|_| "invalid task id")?,
        positron_kernel::MaintenanceScope::segment(
            scope.tenant_id(),
            scope.signal_kind(),
            scope.shard_id(),
        ),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(snapshot.number(), 1).map_err(|_| "preconditions")?,
        snapshot.integrity_scope_source_identity(scope)?,
        0,
    )
    .map_err(|_| "source-bound scrub")?;
    let task_id = task.identity();
    initialized
        .maintenance_coordinator()
        .submit_and_persist(&catalog, task, 0)
        .map_err(|_| "submit scrub")?;

    let key = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    ActiveSegmentLedger::open(&initialized._authority, &catalog, scope, key)?.seal()?;
    let replacement_binding = catalog.pin()?.integrity_scope_source_identity(scope)?;
    drop(catalog);

    assert!(services.wake_maintenance_worker()?);
    let status = initialized
        .maintenance_coordinator()
        .status(task_id)
        .map_err(|_| "stale scrub status")?;
    assert_eq!(status.phase(), MaintenanceTaskPhase::Failed);
    assert_eq!(
        status.terminal_failure(),
        Some(positron_kernel::MaintenanceTerminalFailure::StaleGeneration),
        "the public maintenance status distinguishes a stale source basis from an execution failure"
    );
    assert!(
        status.checkpoint().is_none(),
        "a stale queued basis must be rejected before any scrub pass can report progress"
    );
    assert!(services.wake_maintenance_worker()?);
    assert!(
        initialized
            .maintenance_coordinator()
            .statuses()
            .map_err(|_| "replacement scrub status")?
            .iter()
            .any(|candidate| {
                candidate.task().identity() != task_id
                    && candidate.task().class() == MaintenanceTaskClass::IntegrityScrub
                    && candidate
                        .task()
                        .source_binding()
                        .is_some_and(|binding| binding.to_bytes() == replacement_binding)
            }),
        "a later discovery pass must replace stale work with the current bound source"
    );
    Ok(())
}

#[test]
fn runtime_integrity_scrub_accumulates_three_passes_and_resumes_after_cancellation()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = Arc::new(ServiceHandle::new(Arc::clone(&initialized))?);
    services.install_integrity_scrub_budget_for_test(2)?;
    let scope = SegmentScope::new(
        initialized.tenant,
        positron_domain::routing::SignalKind::Logs,
        initialized.logs_shard,
    );
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let pass_segments = 2_usize;
    let segment_count = pass_segments
        .checked_mul(3)
        .and_then(|count| count.checked_add(1))
        .ok_or("bounded scrub fixture count")?;
    for _ in 0..segment_count {
        ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            super::super::super::tenant_segment_key(&initialized, &identity, scope)?,
        )?
        .seal()?;
    }
    let active = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        super::super::super::tenant_segment_key(&initialized, &identity, scope)?,
    )?;
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, Vec::new(), LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected scrub fixture".into());
    };
    let capacity = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
    active.append(
        LogStore::new()
            .prepare(
                active.begin_store_block(capacity, StoreBlockIdentity::new([0xde; 16])?)?,
                vec![StoredLogRecord::checked_evaluated(
                    positron_domain::value::ValueLimitProfile::release_1_system_maximum(),
                    *evaluated,
                )?],
            )?
            .into_store_block(),
    )?;
    drop(active);
    let snapshot = catalog.pin()?;
    let generation = snapshot.number();
    let source_manifest = snapshot.integrity_scope_source_identity(scope)?;
    let task = MaintenanceTask::integrity_scrub(
        MaintenanceTaskId::new([0xdd; 16]).map_err(|_| "invalid task id")?,
        positron_kernel::MaintenanceScope::segment(
            scope.tenant_id(),
            scope.signal_kind(),
            scope.shard_id(),
        ),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(generation, 1).map_err(|_| "invalid preconditions")?,
        source_manifest,
        0,
    )
    .map_err(|_| "invalid integrity scrub task")?;
    let task_id = task.identity();
    initialized
        .maintenance_coordinator()
        .submit_and_persist(&catalog, task, 0)
        .map_err(|_| "submit integrity scrub task")?;
    drop(catalog);

    let cancellation = crate::TaskCancellation::new();
    let worker_services = Arc::clone(&services);
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let required_progress = u32::try_from(
        pass_segments
            .checked_mul(3)
            .ok_or("bounded cumulative progress")?,
    )?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let status = initialized
            .maintenance_coordinator()
            .status(task_id)
            .map_err(|_| "integrity scrub status")?;
        if status
            .checkpoint()
            .is_some_and(|checkpoint| checkpoint.completed_inputs() >= required_progress)
        {
            cancellation.cancel();
            break;
        }
        if Instant::now() >= deadline {
            return Err("three bounded scrub passes did not checkpoint".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        worker.join().map_err(|_| "maintenance worker panicked")?,
        Ok(())
    );
    let before_restart = initialized
        .maintenance_coordinator()
        .status(task_id)
        .map_err(|_| "cancelled integrity scrub status")?;
    assert_eq!(before_restart.phase(), MaintenanceTaskPhase::Running);
    assert_eq!(
        before_restart
            .checkpoint()
            .ok_or("checkpoint before restart")?
            .completed_inputs(),
        required_progress
    );

    drop(services);
    let resumed = Arc::new(ServiceHandle::new(Arc::clone(&initialized))?);
    let resumed_status = initialized
        .maintenance_coordinator()
        .status(task_id)
        .map_err(|_| "resumed integrity scrub status")?;
    assert_eq!(resumed_status.phase(), MaintenanceTaskPhase::Queued);
    assert_eq!(
        resumed_status
            .checkpoint()
            .ok_or("checkpoint after restart")?
            .completed_inputs(),
        required_progress
    );
    let continuation = positron_kernel::IntegrityScrubContinuation::decode(
        resumed_status
            .checkpoint()
            .ok_or("resumed checkpoint")?
            .opaque_progress(),
    )
    .map_err(|_| "resumed integrity continuation")?;
    let catalog = open_catalog(&initialized)?;
    let resumed_snapshot = catalog.pin()?;
    assert_eq!(
        continuation.source_identity(),
        resumed_snapshot.integrity_scope_source_identity(scope)?,
        "recovery must retain the immutable source binding recorded by the checkpoint"
    );
    drop((resumed_snapshot, catalog));
    let resumed_cancellation = crate::TaskCancellation::new();
    let resumed_services = Arc::clone(&resumed);
    let worker_cancellation = resumed_cancellation.clone();
    let worker =
        std::thread::spawn(move || resumed_services.run_maintenance_worker(&worker_cancellation));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if initialized
            .maintenance_coordinator()
            .status(task_id)
            .map_err(|_| "completed integrity scrub status")?
            .phase()
            == MaintenanceTaskPhase::Succeeded
        {
            resumed_cancellation.cancel();
            break;
        }
        if Instant::now() >= deadline {
            let status = initialized
                .maintenance_coordinator()
                .status(task_id)
                .map_err(|_| "timed out integrity scrub status")?;
            return Err(format!(
                "resumed integrity scrub did not complete (phase: {:?}, terminal: {:?}, checkpoint: {:?})",
                status.phase(),
                status.terminal_failure(),
                status.checkpoint().map(positron_kernel::MaintenanceCheckpoint::completed_inputs),
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        worker
            .join()
            .map_err(|_| "resumed maintenance worker panicked")?,
        Ok(())
    );
    Ok(())
}

#[test]
fn runtime_maintenance_worker_discovers_and_runs_one_integrity_scrub_per_scope()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    assert!(services.wake_maintenance_worker()?);
    let statuses = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "integrity task status")?;
    assert!(statuses.iter().any(|status| {
        status.task().class() == MaintenanceTaskClass::IntegrityScrub
            && status.phase() == MaintenanceTaskPhase::Succeeded
    }));
    Ok(())
}

#[test]
fn repeated_idle_integrity_discovery_does_not_republish_terminal_source()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    assert!(services.wake_maintenance_worker()?);
    let first_records = initialized
        .maintenance_coordinator()
        .durable_records()
        .map_err(|_| "first integrity task records")?;
    assert!(
        initialized
            .maintenance_coordinator()
            .statuses()
            .map_err(|_| "first integrity task statuses")?
            .iter()
            .any(|status| status.task().class() == MaintenanceTaskClass::IntegrityScrub),
        "the first wake publishes the source-bound descriptor"
    );

    // A fresh process rebuilds the same durable task registry. Its idle wake
    // may run other eligible maintenance, but must never publish a second
    // integrity descriptor for unchanged sealed source metadata.
    drop(services);
    drop(initialized);
    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    let _ = services.wake_maintenance_worker()?;
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .durable_records()
            .map_err(|_| "second integrity task records")?
            .len(),
        first_records.len(),
        "idle discovery after reopen must not consume the bounded task registry with duplicate records"
    );
    Ok(())
}

#[test]
fn scheduled_integrity_scrub_persists_its_jittered_lifecycle_due_instant_across_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, _, _) = fixture.initialized()?;
    let epoch_seconds = 7_u64.checked_mul(86_400).ok_or("fixture epoch")?;
    let (retention_time, _elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::try_from(
            epoch_seconds
                .checked_mul(1_000_000_000)
                .ok_or("epoch nanos")?,
        )?));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    assert!(services.wake_maintenance_worker()?);
    let task = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "scheduled task status")?
        .into_iter()
        .find(|status| {
            status.phase() == MaintenanceTaskPhase::Queued
                && status.task().class() == MaintenanceTaskClass::IntegrityScrub
        })
        .ok_or("queued scheduled scrub")?
        .task()
        .clone();
    let due = task.not_before();
    assert!(
        (epoch_seconds..epoch_seconds + 900).contains(&due),
        "the scheduled descriptor stores an instance-scoped jitter inside its bounded epoch slot"
    );
    assert!(
        due > epoch_seconds,
        "the chosen fixture instance is not admitted before its persisted jittered due instant"
    );
    let identity = task.identity();
    drop(services);
    drop(initialized);

    let reopened = fixture.reopen()?;
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .status(identity)
            .map_err(|_| "reopened task")?
            .task()
            .not_before(),
        due,
        "reopen preserves the descriptor's original lifecycle-clock due instant"
    );
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert!(
        services.wake_maintenance_worker()?,
        "a restart after the persisted calendar due instant admits the original descriptor"
    );
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .status(identity)
            .map_err(|_| "late reopened task")?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "late restart dispatch completes the durable descriptor without resampling its jitter"
    );
    Ok(())
}

#[test]
fn runtime_integrity_scrub_revisits_an_unchanged_scope_and_quarantines_later_bit_rot()
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
    let sealed_directory = fixture.root.join("data/segments/sealed");
    let before_seal = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let key = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        key,
    )?;
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(Some(40), None, None, Vec::new(), LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected scrub fixture".into());
    };
    let capacity = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
    ledger.append(
        LogStore::new()
            .prepare(
                ledger.begin_store_block(capacity, StoreBlockIdentity::new([0xc8; 16])?)?,
                vec![StoredLogRecord::checked_evaluated(
                    positron_domain::value::ValueLimitProfile::release_1_system_maximum(),
                    *evaluated,
                )?],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    drop(catalog);
    let damaged_segment = fs::read_dir(&sealed_directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            !before_seal.contains(path)
                && path
                    .extension()
                    .is_some_and(|extension| extension == "segment")
        })
        .ok_or("newly sealed block-bearing segment")?;

    assert!(
        services.wake_maintenance_worker()?,
        "the first maintenance turn persists the initial scrub descriptors"
    );
    let initial_log_scrub = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|failure| format!("first integrity status: {failure:?}"))?
        .into_iter()
        .find(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && status.task().scope()
                    == MaintenanceScope::segment(
                        scope.tenant_id(),
                        scope.signal_kind(),
                        scope.shard_id(),
                    )
                && status.phase() == MaintenanceTaskPhase::Queued
        })
        .ok_or("queued initial logs scrub")?
        .task()
        .clone();
    let initial_due = initial_log_scrub.not_before();
    let current_seconds = 10_u64;
    assert!(
        initial_due > current_seconds,
        "the initial logs scrub remains ineligible until its persisted lifecycle due instant"
    );
    elapsed.advance(
        initial_due
            .checked_sub(current_seconds)
            .ok_or("checked initial logs scrub due delta")?
            .checked_mul(1_000_000_000)
            .ok_or("checked initial logs scrub due nanoseconds")?,
    )?;
    let mut first_log_scrub_succeeded = false;
    for _ in 0..4 {
        let _ = services.wake_maintenance_worker()?;
        first_log_scrub_succeeded = initialized
            .maintenance_coordinator()
            .status(initial_log_scrub.identity())
            .map_err(|failure| format!("initial logs scrub status: {failure:?}"))?
            .phase()
            == MaintenanceTaskPhase::Succeeded;
        if first_log_scrub_succeeded {
            break;
        }
    }
    assert!(
        first_log_scrub_succeeded,
        "the initial logs scrub completes before retention can reclaim its sealed source"
    );
    let first_passes = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|failure| format!("first integrity status: {failure:?}"))?
        .into_iter()
        .filter(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && status.phase() == MaintenanceTaskPhase::Succeeded
        })
        .count();
    assert!(first_passes > 0, "the first due pass is durably recorded");

    const INTEGRITY_SCRUB_CADENCE_SECONDS: u64 = 86_400;
    let mut next_log_due = None;
    for _ in 0..4 {
        let current_seconds = initialized
            .retention_time
            .governance_now_seconds()
            .map_err(|failure| format!("current lifecycle clock: {failure:?}"))?;
        let next_epoch_start = current_seconds
            .checked_div(INTEGRITY_SCRUB_CADENCE_SECONDS)
            .and_then(|epoch| epoch.checked_add(1))
            .and_then(|epoch| epoch.checked_mul(INTEGRITY_SCRUB_CADENCE_SECONDS))
            .ok_or("next integrity scrub epoch")?;
        elapsed.advance(
            next_epoch_start
                .checked_sub(current_seconds)
                .ok_or("next integrity scrub epoch delta")?
                .checked_mul(1_000_000_000)
                .ok_or("next integrity scrub epoch nanoseconds")?,
        )?;
        let _ = services.wake_maintenance_worker()?;
        next_log_due = initialized
            .maintenance_coordinator()
            .statuses()
            .map_err(|failure| format!("next integrity status: {failure:?}"))?
            .into_iter()
            .find(|status| {
                status.task().class() == MaintenanceTaskClass::IntegrityScrub
                    && status.task().scope()
                        == MaintenanceScope::segment(
                            scope.tenant_id(),
                            scope.signal_kind(),
                            scope.shard_id(),
                        )
                    && status.phase() == MaintenanceTaskPhase::Queued
                    && status.task().identity() != initial_log_scrub.identity()
            })
            .map(|status| status.task().not_before());
        if next_log_due.is_some() {
            break;
        }
    }
    let current_seconds = initialized
        .retention_time
        .governance_now_seconds()
        .map_err(|failure| format!("current lifecycle clock: {failure:?}"))?;
    let next_due = next_log_due.ok_or("fresh queued logs integrity scrub")?;
    assert!(
        damaged_segment.is_file(),
        "catalog-bound sealed segment exists"
    );
    let mut corrupted_segment = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&damaged_segment)?;
    corrupted_segment.write_all(b"corrupt after a successful scrub")?;
    corrupted_segment.sync_all()?;
    drop(corrupted_segment);
    if next_due > current_seconds {
        elapsed.advance(
            next_due
                .checked_sub(current_seconds)
                .ok_or("next scrub due delta")?
                .checked_mul(1_000_000_000)
                .ok_or("next scrub due nanoseconds")?,
        )?;
    }
    for _ in 0..8 {
        let _ = services
            .wake_maintenance_worker()
            .map_err(|failure| format!("scheduled integrity scrub failed: {failure:?}"))?;
        let catalog = open_catalog(&initialized)?;
        let snapshot = catalog.pin()?;
        let quarantined = positron_kernel::integrity_quarantine_findings(&snapshot)?;
        if !quarantined.is_empty() {
            break;
        }
    }
    let revisited = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|failure| format!("revisited integrity status: {failure:?}"))?
        .into_iter()
        .filter(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && matches!(
                    status.phase(),
                    MaintenanceTaskPhase::Succeeded | MaintenanceTaskPhase::Failed
                )
        })
        .count();
    assert!(
        revisited > first_passes,
        "a source that stays reachable is authenticated again in its next bounded pass"
    );
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert!(
        !positron_kernel::integrity_quarantine_findings(&snapshot)?.is_empty(),
        "a later corruption is durably quarantined by the next due scrub"
    );
    assert!(
        catalog
            .governance_audit_records()?
            .into_iter()
            .map(|record| GovernanceAuditEntry::decode(&record))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|entry| {
                entry.as_integrity_quarantine().is_some_and(|audit| {
                    audit.tenant() == initialized.tenant
                        && audit.signal() == SignalKind::Logs
                        && audit.shard() == scope.shard_id().value()
                        && audit.segment().is_none()
                })
            }),
        "the periodic trusted quarantine is atomically evidenced by its scope-bound audit"
    );
    Ok(())
}

#[test]
fn startup_frontier_verification_fences_an_authenticated_active_scope_failure()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let active = fs::read_dir(fixture.root.join("data/segments/active"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "segment")
        })
        .ok_or("bootstrap active segment")?;
    fs::write(active, b"corrupt")?;

    assert_eq!(
        crate::services::verify_startup_integrity(&initialized),
        Err(ServiceFailure::CorruptState)
    );
    Ok(())
}
