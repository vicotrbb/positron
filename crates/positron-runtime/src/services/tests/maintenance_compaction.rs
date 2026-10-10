use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::routing::SignalKind;
use positron_kernel::{
    ActiveSegmentLedger, CatalogPublicationFault, MaintenanceTask, MaintenanceTaskClass,
    MaintenanceTaskId, MaintenanceTaskPhase, RetentionBucket, with_catalog_publication_fault_after,
};
use positron_signals::{LogScan, LogStore, ScanLimit, TraceScan, TraceStore};
use prost::Message;

use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, open_catalog, request};

#[test]
fn runtime_worker_executes_a_persisted_log_compaction_and_preserves_it_across_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let tenant = initialized.default_tenant_id();

    services.ingest_otlp_logs(&ingest, request("first compactable log").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(tenant, SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log ledger scope")?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    drop(catalog);

    services.ingest_otlp_logs(&ingest, request("first compactable log").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    assert_eq!(
        snapshot.blocks().len(),
        2,
        "the fixture must seal two canonical records in one source scope"
    );
    let scanned = LogStore::new().scan(
        initialized._authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(16)?),
    )?;
    let ingest_time = scanned
        .records()
        .first()
        .ok_or("sealed log record")?
        .ingest_time();
    drop((scanned, snapshot));
    let policy = catalog.pin()?.retention_policy(SignalKind::Logs)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        ingest_time,
        policy.retention_seconds(),
    )?;
    let identity =
        MaintenanceTaskId::new([0xc1; 16]).map_err(|failure| format!("task id: {failure:?}"))?;
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    let coordinator = initialized.maintenance_coordinator();
    task.submit_and_persist(coordinator, &catalog, 1)?;
    drop(ledger);
    drop(catalog);

    assert!(
        services.wake_maintenance_worker()?,
        "one public worker wake must execute the queued durable compaction"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the worker must terminalize the exact persisted descriptor"
    );
    drop(services);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let _restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
    let catalog = open_catalog(&reopened)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &reopened._authority,
        &reopened.retention_time,
        &catalog,
        scope,
        reopened.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    let records = LogStore::new()
        .scan(
            reopened.resource_governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(16)?),
        )?
        .into_records();
    let bodies = records
        .iter()
        .map(|record| record.stored().body().and_then(|body| body.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        bodies,
        vec![Some("first compactable log"), Some("first compactable log")],
        "the reopened canonical log query retains each compacted record"
    );
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("restored compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "reopen retains the terminal compaction record"
    );
    Ok(())
}

#[test]
fn runtime_worker_terminalizes_a_stale_log_compaction_binding() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let tenant = initialized.default_tenant_id();
    services.ingest_otlp_logs(&ingest, request("stale binding first").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(tenant, SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log ledger scope")?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);
    services.ingest_otlp_logs(&ingest, request("stale binding second").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    let ingest_time = LogStore::new()
        .scan(
            initialized._authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(16)?),
        )?
        .records()
        .first()
        .ok_or("sealed log")?
        .ingest_time();
    let policy = catalog.pin()?.retention_policy(SignalKind::Logs)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        ingest_time,
        policy.retention_seconds(),
    )?;
    drop(snapshot);
    let identity = MaintenanceTaskId::new([0xd1; 16])
        .map_err(|failure| format!("task identity: {failure:?}"))?;
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    task.submit_and_persist(initialized.maintenance_coordinator(), &catalog, 1)?;
    drop(ledger);
    drop(catalog);

    services.ingest_otlp_logs(&ingest, request("stale binding successor").encode_to_vec())?;
    let catalog = open_catalog(&initialized)?;
    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .seal()?;
    drop(catalog);

    let reservation_baseline = initialized
        .resource_governor()
        .inspect()?
        .outstanding_total();
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker = std::thread::spawn(move || {
        with_catalog_publication_fault_after(
            CatalogPublicationFault::SynchronizeGenerationDirectory,
            1,
            || worker_services.run_maintenance_worker(&worker_cancellation),
        )
    });
    services.notify_maintenance_worker();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_running = false;
    let status = loop {
        let status = initialized
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("stale task status: {failure:?}"))?;
        saw_running |= status.phase() == MaintenanceTaskPhase::Running;
        if status.phase() == MaintenanceTaskPhase::Failed {
            break status;
        }
        if Instant::now() >= deadline {
            cancellation.cancel();
            return Err("stale compaction did not recover its terminal write".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    cancellation.cancel();
    worker.join().map_err(|_| "maintenance worker panicked")??;
    assert!(
        saw_running,
        "the post-marker fault keeps the one execution Running until its exact retry resolves"
    );
    assert_eq!(status.phase(), MaintenanceTaskPhase::Failed);
    assert_eq!(
        status.terminal_failure(),
        Some(positron_kernel::MaintenanceTerminalFailure::StaleGeneration)
    );
    assert_eq!(
        initialized
            .resource_governor()
            .inspect()?
            .outstanding_total(),
        reservation_baseline,
        "the rejected descriptor releases its worker reservation"
    );
    assert_eq!(
        services
            .maintenance_status(&administrator, br"{}")
            .map_err(|failure| format!("public stale status: {failure:?}"))?
            .tasks
            .into_iter()
            .find(|task| task.class == "compaction")
            .ok_or("public stale task status")?
            .terminal_failure_class
            .as_deref(),
        Some("stale_generation")
    );
    let catalog = open_catalog(&initialized)?;
    assert_eq!(
        ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &initialized._authority,
            &initialized.retention_time,
            &catalog,
            scope,
            initialized.tenant_segment_key_for_test(scope)?,
        )?
        .snapshot()?
        .blocks()
        .len(),
        3,
        "a rejected binding publishes no output or source replacement"
    );
    assert_eq!(
        positron_kernel::MaintenanceCoordinator::restore_from_catalog(&catalog)
            .map_err(|failure| format!("direct stale restore: {failure:?}"))?
            .status(identity)
            .map_err(|failure| format!("direct stale status: {failure:?}"))?
            .terminal_failure(),
        Some(positron_kernel::MaintenanceTerminalFailure::StaleGeneration)
    );
    let cancelled_identity = MaintenanceTaskId::new([0xd3; 16])
        .map_err(|failure| format!("cancelled stale identity: {failure:?}"))?;
    let cancelled_task = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?
    .prepare_compaction_task(bucket, cancelled_identity)?;
    cancelled_task.submit_and_persist(initialized.maintenance_coordinator(), &catalog, 2)?;
    let cancelled_execution = initialized
        .maintenance_coordinator()
        .start_compaction_task_with_reservation_and_persist(
            &catalog,
            &initialized._authority,
            2,
            false,
            cancelled_identity,
        )
        .map_err(|failure| format!("start cancelled stale task: {failure:?}"))?
        .ok_or("cancelled stale task dispatch")?;
    initialized
        .maintenance_coordinator()
        .cancel_and_persist(&catalog, cancelled_identity)
        .map_err(|failure| format!("persist stale cancellation: {failure:?}"))?;
    cancelled_execution
        .fail_rejected_compaction_and_persist(initialized.maintenance_coordinator(), &catalog)
        .map_err(|failure| format!("terminalize cancelled stale task: {failure:?}"))?;
    let cancelled = initialized
        .maintenance_coordinator()
        .status(cancelled_identity)
        .map_err(|failure| format!("cancelled stale status: {failure:?}"))?;
    assert_eq!(cancelled.phase(), MaintenanceTaskPhase::Cancelled);
    assert_eq!(cancelled.terminal_failure(), None);
    assert!(cancelled.cancellation_requested());
    drop(cancelled_execution);
    drop(catalog);
    drop(services);
    drop(initialized);
    let reopened = fixture.reopen()?;
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("reopened stale status: {failure:?}"))?
            .terminal_failure(),
        Some(positron_kernel::MaintenanceTerminalFailure::StaleGeneration)
    );
    Ok(())
}

#[test]
fn bootstrap_reopen_requeues_a_running_maintenance_descriptor() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let identity = MaintenanceTaskId::new([0xd2; 16])
        .map_err(|failure| format!("running maintenance identity: {failure:?}"))?;
    let catalog = open_catalog(&initialized)?;
    initialized
        .maintenance_coordinator()
        .submit_and_persist(
            &catalog,
            MaintenanceTask::new(identity, MaintenanceTaskClass::SchemaPromotion),
            1,
        )
        .map_err(|failure| format!("submit running maintenance: {failure:?}"))?;
    let execution = initialized
        .maintenance_coordinator()
        .start_next_with_reservation_and_persist(&catalog, &initialized._authority, 2, false)
        .map_err(|failure| format!("start running maintenance: {failure:?}"))?
        .ok_or("running maintenance descriptor")?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("running maintenance status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Running
    );
    drop(execution);
    drop(catalog);
    drop(initialized);

    let reopened = fixture.reopen()?;
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("reopened maintenance status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Queued,
        "bootstrap restores the durable descriptor and applies crash recovery before a handler can resume"
    );
    let resources = reopened.resource_governor().inspect()?;
    assert_eq!(resources.outstanding_total(), 1);
    assert_eq!(
        resources.outstanding_for(positron_kernel::WorkClass::SecurityLifecycle),
        1,
        "reopen retains its admitted native System KEK cache"
    );
    assert_eq!(
        resources.outstanding_for(positron_kernel::WorkClass::OrdinaryMaintenanceBackup),
        0,
        "reopened maintenance has no inherited live reservation"
    );
    assert_eq!(resources.outstanding_recovery(), 0);
    Ok(())
}

#[test]
fn runtime_worker_executes_a_persisted_trace_compaction_and_preserves_spans_across_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let tenant = initialized.default_tenant_id();

    services.ingest_otlp_traces(
        &ingest,
        trace_request([0xd1; 16], [0xe1; 8]).encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(tenant, SignalKind::Traces)?
        .into_iter()
        .next()
        .ok_or("trace ledger scope")?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    drop(catalog);

    services.ingest_otlp_traces(
        &ingest,
        trace_request([0xd2; 16], [0xe2; 8]).encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    assert_eq!(
        snapshot.blocks().len(),
        2,
        "the fixture must seal two canonical spans in one source scope"
    );
    let scanned = TraceStore::new().scan_physical(
        initialized.resource_governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(16)?),
    )?;
    let ingest_time = scanned
        .observations()
        .first()
        .ok_or("sealed trace observation")?
        .stored()
        .ingest_time();
    drop((scanned, snapshot));
    let policy = catalog.pin()?.retention_policy(SignalKind::Traces)?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Traces,
        ingest_time,
        policy.retention_seconds(),
    )?;
    let identity =
        MaintenanceTaskId::new([0xc2; 16]).map_err(|failure| format!("task id: {failure:?}"))?;
    let task = ledger.prepare_compaction_task(bucket, identity)?;
    let coordinator = initialized.maintenance_coordinator();
    task.submit_and_persist(coordinator, &catalog, 1)?;
    drop(ledger);
    drop(catalog);

    assert!(
        services.wake_maintenance_worker()?,
        "one public worker wake must execute the queued durable compaction"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the worker must terminalize the exact persisted descriptor"
    );
    drop(services);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let _restored_services = ServiceHandle::new(Arc::clone(&reopened))?;
    let catalog = open_catalog(&reopened)?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &reopened._authority,
        &reopened.retention_time,
        &catalog,
        scope,
        reopened.tenant_segment_key_for_test(scope)?,
    )?;
    let snapshot = ledger.snapshot()?;
    let mut spans = TraceStore::new()
        .scan_physical(
            reopened.resource_governor(),
            tenant,
            &snapshot,
            TraceScan::all(ScanLimit::new(16)?),
        )?
        .observations()
        .iter()
        .map(|span| (span.observation().trace_id(), span.observation().span_id()))
        .collect::<Vec<_>>();
    spans.sort_unstable();
    assert_eq!(
        spans,
        vec![([0xd1; 16], [0xe1; 8]), ([0xd2; 16], [0xe2; 8])],
        "the reopened canonical trace scan retains every compacted span"
    );
    assert_eq!(
        reopened
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("restored compaction status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "reopen retains the terminal compaction record"
    );
    Ok(())
}

#[test]
fn runtime_worker_terminalizes_a_one_segment_trace_compaction() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let tenant = initialized.default_tenant_id();

    services.ingest_otlp_traces(
        &ingest,
        trace_request([0xe1; 16], [0xf1; 8]).encode_to_vec(),
    )?;
    let catalog = open_catalog(&initialized)?;
    let scope = catalog
        .pin()?
        .reachable_ledger_scopes(tenant, SignalKind::Traces)?
        .into_iter()
        .next()
        .ok_or("trace ledger scope")?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        initialized.tenant_segment_key_for_test(scope)?,
    )?;
    let identity =
        MaintenanceTaskId::new([0xe3; 16]).map_err(|failure| format!("task id: {failure:?}"))?;
    let task = ledger.prepare_compaction_task(ledger.sealed_compaction_bucket()?, identity)?;
    task.submit_and_persist(initialized.maintenance_coordinator(), &catalog, 1)?;
    drop(ledger);
    drop(catalog);

    assert!(
        services.wake_maintenance_worker()?,
        "the worker must process the one sealed trace source"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .map_err(|failure| format!("one-segment trace status: {failure:?}"))?
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "a one-segment trace source must terminalize without inventing a replacement"
    );
    Ok(())
}

fn trace_request(trace_id: [u8; 16], span_id: [u8; 8]) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: trace_id.to_vec(),
                    span_id: span_id.to_vec(),
                    name: "compactable-runtime-trace".to_owned(),
                    start_time_unix_nano: 1,
                    end_time_unix_nano: 2,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}
