use super::*;

#[test]
fn runtime_maintenance_worker_discovers_and_completes_expired_log_and_trace_retention()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let tenant = initialized.default_tenant_id();
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let retention = std::num::NonZeroU64::new(1).ok_or("one second retention")?;
    let preview = initialized.inspect_tenant_retention_impact(system, tenant, retention)?;
    initialized.update_tenant_retention(
        system,
        tenant,
        retention,
        ResourceGeneration::new(1)?,
        Some(&preview),
        AdministrativeIdempotencyKey::new([0x83; 16])?,
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("runtime-retention-log").encode_to_vec())?
            .accepted_records(),
        1
    );
    assert_eq!(
        services
            .ingest_otlp_traces(
                &ingest,
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans {
                        scope_spans: vec![ScopeSpans {
                            spans: vec![Span {
                                trace_id: vec![0x83; 16],
                                span_id: vec![0x84; 8],
                                name: "runtime-retention-trace".to_owned(),
                                start_time_unix_nano: 41,
                                end_time_unix_nano: 42,
                                ..Span::default()
                            }],
                            ..ScopeSpans::default()
                        }],
                        ..ResourceSpans::default()
                    }],
                }
                .encode_to_vec(),
            )?
            .accepted_records(),
        1
    );

    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let scopes = [SignalKind::Logs, SignalKind::Traces]
        .into_iter()
        .map(|signal| snapshot.reachable_ledger_scopes(tenant, signal))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(
        scopes.len(),
        2,
        "one canonical scope for each stored signal"
    );
    drop((snapshot, catalog));
    for scope in &scopes {
        let catalog = open_catalog(&initialized)?;
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let protection = super::super::super::tenant_segment_key(&initialized, &identity, *scope)?;
        ActiveSegmentLedger::open_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            *scope,
            protection,
        )?
        .seal()?;
    }
    elapsed.advance(2_000_000_000)?;

    assert!(
        services.wake_maintenance_worker()?,
        "the sole runtime worker discovers and begins due retention work"
    );
    for _ in 0..8 {
        if !services.wake_maintenance_worker()? {
            break;
        }
    }
    let scheduled_scrubs = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "scheduled integrity scrub statuses")?
        .into_iter()
        .filter(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && status.phase() == MaintenanceTaskPhase::Queued
        })
        .map(|status| status.task().not_before())
        .collect::<Vec<_>>();
    assert_eq!(
        scheduled_scrubs.len(),
        scopes.len(),
        "each retention publication schedules one persisted scrub"
    );
    let current_seconds = 12_u64;
    assert!(
        scheduled_scrubs
            .iter()
            .all(|due| *due > current_seconds && *due < 900),
        "each initial queued scrub remains in the first lifecycle epoch"
    );
    assert!(
        !services.wake_maintenance_worker()?,
        "the worker remains idle before every queued scrub's persisted due instant"
    );
    let latest_due = *scheduled_scrubs
        .iter()
        .max()
        .ok_or("latest queued jittered integrity scrub")?;
    elapsed.advance(
        latest_due
            .checked_sub(current_seconds)
            .ok_or("checked latest scrub due delta")?
            .checked_mul(1_000_000_000)
            .ok_or("checked latest scrub due nanoseconds")?,
    )?;
    let mut drained_turns = 0_usize;
    for _ in 0..16 {
        if !services.wake_maintenance_worker()? {
            break;
        }
        drained_turns += 1;
    }
    assert!(
        drained_turns < 16,
        "the finite maintenance drain reaches an idle state"
    );
    let statuses = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "completed retention and scrub statuses")?;
    for scope in &scopes {
        let maintenance_scope =
            MaintenanceScope::segment(scope.tenant_id(), scope.signal_kind(), scope.shard_id());
        for class in [
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceTaskClass::RetentionReclamation,
            MaintenanceTaskClass::IntegrityScrub,
        ] {
            assert!(
                statuses.iter().any(|status| {
                    status.task().class() == class
                        && status.task().scope() == maintenance_scope
                        && status.phase() == MaintenanceTaskPhase::Succeeded
                }),
                "the {class:?} task for each expired scope completes before the worker is idle"
            );
        }
    }
    let catalog = open_catalog(&initialized)?;
    let idle_generation = catalog.pin()?.number();
    let idle_task_count = initialized
        .maintenance_coordinator()
        .durable_records()
        .map_err(|_| "durable maintenance records")?
        .len();
    drop(catalog);
    for _ in 0..4 {
        assert!(
            !services.wake_maintenance_worker()?,
            "a quiescent maintenance worker must not roll an empty active segment"
        );
    }
    let catalog = open_catalog(&initialized)?;
    assert_eq!(
        catalog.pin()?.number(),
        idle_generation,
        "idle discovery does not publish a Catalog generation"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .durable_records()
            .map_err(|_| "durable maintenance records")?
            .len(),
        idle_task_count,
        "idle discovery does not create a new durable task"
    );
    drop(catalog);

    for scope in scopes {
        let catalog = open_catalog(&initialized)?;
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let protection = super::super::super::tenant_segment_key(&initialized, &identity, scope)?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            protection,
        )?;
        assert_eq!(
            ledger
                .prepare_retention_publication()
                .expect_err("the runtime worker has consumed this expired scope")
                .code(),
            positron_kernel::LedgerFailureCode::InvalidInput
        );
    }
    Ok(())
}

#[test]
fn pending_integrity_scrub_blocks_retention_only_for_its_own_scope() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (mut initialized, ingest, _, administrator_secret) = fixture.initialized_with_admin()?;
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        UnixNanoseconds::new(86_397_000_000_000),
    );
    Arc::get_mut(&mut initialized)
        .ok_or("sole initialized instance")?
        .install_retention_time_for_test(retention_time)?;
    let tenant = initialized.default_tenant_id();
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let retention = std::num::NonZeroU64::new(1).ok_or("one second retention")?;
    let preview = initialized.inspect_tenant_retention_impact(system, tenant, retention)?;
    initialized.update_tenant_retention(
        system,
        tenant,
        retention,
        ResourceGeneration::new(1)?,
        Some(&preview),
        AdministrativeIdempotencyKey::new([0x84; 16])?,
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("scrub-blocked-log").encode_to_vec())?
            .accepted_records(),
        1
    );
    assert_eq!(
        services
            .ingest_otlp_traces(
                &ingest,
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans {
                        scope_spans: vec![ScopeSpans {
                            spans: vec![Span {
                                trace_id: vec![0x85; 16],
                                span_id: vec![0x86; 8],
                                name: "scrub-healthy-trace".to_owned(),
                                start_time_unix_nano: 41,
                                end_time_unix_nano: 42,
                                ..Span::default()
                            }],
                            ..ScopeSpans::default()
                        }],
                        ..ResourceSpans::default()
                    }],
                }
                .encode_to_vec(),
            )?
            .accepted_records(),
        1
    );

    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    let scopes = [SignalKind::Logs, SignalKind::Traces]
        .into_iter()
        .map(|signal| snapshot.reachable_ledger_scopes(tenant, signal))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let logs_scope = *scopes
        .iter()
        .find(|scope| scope.signal_kind() == SignalKind::Logs)
        .ok_or("canonical logs scope")?;
    let traces_scope = *scopes
        .iter()
        .find(|scope| scope.signal_kind() == SignalKind::Traces)
        .ok_or("canonical traces scope")?;
    drop(snapshot);
    for scope in &scopes {
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let protection = super::super::super::tenant_segment_key(&initialized, &identity, *scope)?;
        ActiveSegmentLedger::open_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            *scope,
            protection,
        )?
        .seal()?;
    }
    let snapshot = catalog.pin()?;
    let pending_scrub = MaintenanceTask::integrity_scrub(
        MaintenanceTaskId::new([0x87; 16]).map_err(|_| "pending scrub identity")?,
        MaintenanceScope::segment(
            logs_scope.tenant_id(),
            logs_scope.signal_kind(),
            logs_scope.shard_id(),
        ),
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(snapshot.number(), 1).map_err(|_| "pending preconditions")?,
        snapshot.integrity_scope_source_identity(logs_scope)?,
        86_400,
    )
    .map_err(|_| "pending source-bound scrub")?;
    let pending_scrub_id = pending_scrub.identity();
    initialized
        .maintenance_coordinator()
        .submit_and_persist(&catalog, pending_scrub, 10)
        .map_err(|_| "persist pending scrub")?;
    drop(catalog);
    elapsed.advance(2_000_000_000)?;

    let traces_maintenance_scope = MaintenanceScope::segment(
        traces_scope.tenant_id(),
        traces_scope.signal_kind(),
        traces_scope.shard_id(),
    );
    assert!(
        services.wake_maintenance_worker()?,
        "the healthy scope receives its own persisted integrity descriptor"
    );
    let trace_scrub = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "healthy scrub status")?
        .into_iter()
        .find(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && status.task().scope() == traces_maintenance_scope
        })
        .ok_or("healthy scrub status")?;
    let trace_scrub_due = trace_scrub.task().not_before();
    let current_seconds = initialized
        .retention_time
        .governance_now_seconds()
        .map_err(|failure| format!("current lifecycle clock: {failure:?}"))?;
    const INTEGRITY_SCRUB_CADENCE_SECONDS: u64 = 86_400;
    const INTEGRITY_SCRUB_JITTER_SECONDS: u64 = 900;
    let epoch_start = current_seconds
        .checked_div(INTEGRITY_SCRUB_CADENCE_SECONDS)
        .and_then(|epoch| epoch.checked_mul(INTEGRITY_SCRUB_CADENCE_SECONDS))
        .ok_or("current integrity scrub epoch")?;
    let epoch_end = epoch_start
        .checked_add(INTEGRITY_SCRUB_JITTER_SECONDS)
        .ok_or("current integrity scrub jitter window")?;
    assert!(
        (epoch_start..epoch_end).contains(&trace_scrub_due),
        "the healthy scope's persisted scrub belongs to the current lifecycle epoch"
    );
    assert!(
        trace_scrub_due <= current_seconds,
        "the end-of-epoch healthy scrub is due in the same discovery turn"
    );
    assert_eq!(
        trace_scrub.phase(),
        MaintenanceTaskPhase::Succeeded,
        "the due healthy scrub completes without stranding the unrelated scope"
    );
    let mut healthy_scope_completed = false;
    for _ in 0..8 {
        let _ = services.wake_maintenance_worker()?;
        let statuses = initialized
            .maintenance_coordinator()
            .statuses()
            .map_err(|_| "maintenance statuses")?;
        healthy_scope_completed = [
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceTaskClass::RetentionReclamation,
        ]
        .into_iter()
        .all(|class| {
            statuses.iter().any(|status| {
                status.task().class() == class
                    && status.task().scope() == traces_maintenance_scope
                    && status.phase() == MaintenanceTaskPhase::Succeeded
            })
        });
        if healthy_scope_completed {
            break;
        }
    }
    assert!(
        healthy_scope_completed,
        "a pending scrub for logs does not strand the independently healthy traces retention scope"
    );
    let statuses = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "final maintenance statuses")?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(pending_scrub_id)
            .map_err(|_| "pending scrub status")?
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the blocked scope remains behind its persisted scrub due instant"
    );
    let logs_maintenance_scope = MaintenanceScope::segment(
        logs_scope.tenant_id(),
        logs_scope.signal_kind(),
        logs_scope.shard_id(),
    );
    assert!(
        !statuses.iter().any(|status| {
            matches!(
                status.task().class(),
                MaintenanceTaskClass::RetentionPublication
                    | MaintenanceTaskClass::RetentionReclamation
            ) && status.task().scope() == logs_maintenance_scope
        }),
        "the maintenance guard blocks retention only for the scrub's exact scope"
    );
    Ok(())
}

#[test]
fn cancellation_after_maintenance_dispatch_preserves_the_lease_for_recovery()
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
    let lease_id = lease.identity();
    let task = MaintenanceTaskId::new(lease_id.to_bytes()).expect("lease task id");
    drop(lease);
    drop(ledger);
    drop(catalog);
    elapsed.advance(1_000_000_000)?;

    let cancellation = crate::TaskCancellation::new();
    cancellation.cancel_after_polls(2);
    assert!(matches!(
        services.wake_maintenance_worker_with_cancellation(&cancellation),
        Err(ServiceFailure::Cancelled)
    ));

    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .expect("running task")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    drop(services);

    let recovered = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .expect("recovered task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    drop(recovered);
    Ok(())
}
