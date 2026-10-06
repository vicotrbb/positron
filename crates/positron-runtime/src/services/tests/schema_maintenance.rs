use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::routing::SignalKind;
use positron_domain::time::UnixNanoseconds;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, GovernanceAuditEntry, PresentedCredential,
    RequestedIntent, ResourceGeneration,
};
use positron_ingest::load_schema_checkpoint;
use positron_kernel::{
    ActiveSegmentLedger, AuditIntent, Catalog, CatalogObject, CatalogProposal,
    CatalogPublicationFault, FormatEpoch, MaintenancePreconditions, MaintenanceScope,
    MaintenanceTask, MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase,
    MaintenanceTrigger, MountQualification, ResourceAmounts, ResourceDimension,
    RetentionTimeAuthority, SegmentScope, StoreBlockIdentity, TransactionId, WorkClaim, WorkClass,
    WorkKind, with_catalog_publication_fault_after,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
};
use positron_query::QueryBudget;
use positron_signals::{LogRecord as StoredLogRecord, LogStore};
use prost::Message;

use super::super::{ServiceFailure, ServiceHandle, schema_maintenance};
use crate::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};

pub(crate) type InitializedCredentials = (Arc<crate::InitializedInstance>, String, String, String);

static LIVE_NATIVE_MAINTENANCE_TEST: Mutex<()> = Mutex::new(());

fn live_native_maintenance_test_guard() -> MutexGuard<'static, ()> {
    match LIVE_NATIVE_MAINTENANCE_TEST.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[test]
fn service_startup_restores_catalog_backed_maintenance_before_serving() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    let task = MaintenanceTask::new(
        MaintenanceTaskId::new([0x91; 16]).expect("stable maintenance identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let identity = task.identity();
    let catalog = open_catalog(&initialized)?;
    initialized
        .maintenance_coordinator()
        .submit_and_persist(&catalog, task, 7)
        .expect("durable task submission");
    drop(catalog);

    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(identity)
            .expect("restored task")
            .task()
            .class(),
        MaintenanceTaskClass::SchemaPromotion
    );
    drop(services);
    Ok(())
}

#[test]
fn startup_rebuild_publishes_before_service_and_preserves_unrelated_objects()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let unrelated = publish_unrelated(&initialized)?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("rebuild").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop(services);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;

    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        snapshot.object(unrelated)?,
        Some(b"unrelated-runtime-state".as_slice())
    );
    assert!(
        load_schema_checkpoint(
            &snapshot,
            initialized.tenant,
            initialized.resource_governor()
        )
        .map_err(|_| "schema checkpoint load failed")?
        .is_some()
    );
    drop((snapshot, catalog, services));
    Ok(())
}

#[test]
fn serving_updates_live_schema_without_catalog_publication() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let initial_audits = schema_audit_count(&initialized)?;

    for body in ["first", "latest"] {
        assert_eq!(
            services
                .ingest_otlp_logs(&ingest, request(body).encode_to_vec())?
                .accepted_records(),
            1
        );
    }
    assert_eq!(schema_audit_count(&initialized)?, initial_audits);
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["first", "latest"]
    );

    services.prepare_shutdown_schema_checkpoint()?;
    services.publish_prepared_shutdown_schema_checkpoint()?;
    assert_eq!(schema_audit_count(&initialized)?, initial_audits + 1);
    Ok(())
}

#[test]
fn production_query_publishes_a_durable_snapshot_lease_expiry_task() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("lease-task").encode_to_vec())?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["lease-task"]
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .durable_records()
            .expect("query expiry task is coordinator-owned")
            .len(),
        1,
        "the runtime query path asks the kernel lease publisher to atomically create expiry work"
    );
    let catalog = open_catalog(&initialized)?;
    assert!(
        initialized
            .maintenance_coordinator()
            .start_next_with_reservation_and_persist(
                &catalog,
                &initialized._authority,
                u64::MAX,
                false,
            )
            .expect("released query expiry task is terminal")
            .is_none(),
        "collecting the ordinary query releases its lease and cancels its paired expiry task"
    );
    Ok(())
}

#[test]
fn runtime_maintenance_worker_wake_dispatches_and_completes_a_due_snapshot_lease_expiry()
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
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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

    assert!(services.wake_maintenance_worker()?);

    let catalog = open_catalog(&initialized)?;
    let identity = positron_governance::Identity::open(&catalog.pin()?)?;
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        protection,
    )?;
    assert!(
        reopened
            .resume_snapshot_lease(lease_id, 11)
            .expect_err("the runtime handler removed the expired lease")
            .code()
            == positron_kernel::LedgerFailureCode::SnapshotExpired,
        "the runtime handler removes the expired lease"
    );
    assert_eq!(
        initialized
            .maintenance_coordinator()
            .status(task)
            .expect("terminal task")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}

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
    let key = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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
    let key = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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

    let key = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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
            super::super::tenant_segment_key(&initialized, &identity, scope)?,
        )?
        .seal()?;
    }
    let active = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
        &initialized._authority,
        &initialized.retention_time,
        &catalog,
        scope,
        super::super::tenant_segment_key(&initialized, &identity, scope)?,
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
    let key = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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

    elapsed.advance(86_400_000_000_000)?;
    let mut next_log_due = None;
    for _ in 0..4 {
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
        let protection = super::super::tenant_segment_key(&initialized, &identity, *scope)?;
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
        let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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
        let protection = super::super::tenant_segment_key(&initialized, &identity, *scope)?;
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
    let trace_scrub_due = initialized
        .maintenance_coordinator()
        .statuses()
        .map_err(|_| "healthy scrub status")?
        .into_iter()
        .find(|status| {
            status.task().class() == MaintenanceTaskClass::IntegrityScrub
                && status.task().scope() == traces_maintenance_scope
                && status.phase() == MaintenanceTaskPhase::Queued
        })
        .ok_or("queued healthy scrub")?
        .task()
        .not_before();
    assert!(
        (12..900).contains(&trace_scrub_due),
        "the healthy scope's persisted scrub is eligible in the current lifecycle epoch"
    );
    elapsed.advance(
        trace_scrub_due
            .checked_sub(12)
            .ok_or("healthy scrub due delta")?
            .checked_mul(1_000_000_000)
            .ok_or("healthy scrub due nanoseconds")?,
    )?;
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
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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
    let protection = super::super::tenant_segment_key(&initialized, &identity, scope)?;
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
        .publish_prepared_shutdown_schema_checkpoint()
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
    services.publish_prepared_shutdown_schema_checkpoint()?;

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
            .publish_prepared_shutdown_schema_checkpoint()
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

#[test]
fn corrupted_schema_checkpoint_blocks_serving() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    publish_unrelated_bytes(&initialized, b"PSCHEMA1-corrupt".to_vec())?;
    assert!(matches!(
        ServiceHandle::new(Arc::clone(&initialized)),
        Err(ServiceFailure::CorruptState)
    ));
    Ok(())
}

#[test]
fn duplicate_tenant_checkpoints_block_serving() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let older = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?
        .into_catalog_bytes();
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("new-schema").encode_to_vec())?
            .accepted_records(),
        1
    );
    let newer = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?
        .into_catalog_bytes();
    assert_ne!(older, newer);
    publish_unrelated_bytes(&initialized, older)?;
    publish_unrelated_bytes_with_transaction(&initialized, newer, [0x76; 16])?;
    drop(services);

    assert!(matches!(
        ServiceHandle::new(Arc::clone(&initialized)),
        Err(ServiceFailure::CorruptState)
    ));
    Ok(())
}

fn publish_unrelated(
    initialized: &crate::InitializedInstance,
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            basis
                .object(identity)?
                .ok_or_else(|| "missing object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let unrelated = CatalogObject::new(b"unrelated-runtime-state".to_vec())?;
    let identity = unrelated.identity();
    objects.push(unrelated);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x91; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        Some(AuditIntent::new(b"test-unrelated-state".to_vec())?),
    )?;
    Ok(identity)
}

fn publish_unrelated_bytes(
    initialized: &crate::InitializedInstance,
    bytes: Vec<u8>,
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    publish_unrelated_bytes_with_transaction(initialized, bytes, [0x75; 16])
}

fn publish_unrelated_bytes_with_transaction(
    initialized: &crate::InitializedInstance,
    bytes: Vec<u8>,
    transaction: [u8; 16],
) -> Result<positron_kernel::CatalogObjectId, Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let before = catalog.pin()?;
    let object = CatalogObject::new(bytes)?;
    let identity = object.identity();
    let mut objects = before
        .object_identities()
        .map(|known| {
            before
                .object(known)?
                .ok_or_else(|| "missing object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(object);
    catalog.commit(
        before.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(identity)
}

fn schema_audit_count(initialized: &crate::InitializedInstance) -> Result<usize, Box<dyn Error>> {
    Ok(open_catalog(initialized)?
        .governance_audit_records()?
        .iter()
        .filter(|record| {
            GovernanceAuditEntry::decode(record)
                .ok()
                .and_then(|entry| entry.as_schema_checkpoint().cloned())
                .is_some()
        })
        .count())
}

pub(crate) fn open_catalog(
    initialized: &crate::InitializedInstance,
) -> Result<Catalog<'_>, Box<dyn Error>> {
    Ok(Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?)
}

pub(crate) fn request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn reserve_native_addresses() -> Result<[SocketAddr; 5], Box<dyn Error>> {
    let mut listeners = Vec::with_capacity(5);
    let mut addresses = Vec::with_capacity(5);
    for _ in 0..5 {
        let listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        addresses.push(listener.local_addr()?);
        listeners.push(listener);
    }
    drop(listeners);
    addresses
        .try_into()
        .map_err(|_| "five native listener addresses".into())
}

pub(crate) struct Fixture {
    root: PathBuf,
}

impl Fixture {
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-schema-maintenance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("data"))?;
        fs::create_dir_all(root.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root })
    }

    pub(crate) fn sealed_segments_directory(&self) -> PathBuf {
        self.root.join("data/segments/sealed")
    }

    pub(crate) fn paths(&self) -> Result<BootstrapPaths, Box<dyn Error>> {
        Ok(BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?)
    }

    pub(super) fn initialized(
        &self,
    ) -> Result<(Arc<crate::InitializedInstance>, String, String), Box<dyn Error>> {
        let (initialized, ingest, query, _) = self.initialized_with_admin()?;
        Ok((initialized, ingest, query))
    }

    pub(crate) fn initialized_with_admin(&self) -> Result<InitializedCredentials, Box<dyn Error>> {
        self.initialized_with_admin_max_registered_tenants(2)
    }

    fn initialized_with_admin_max_registered_tenants(
        &self,
        max_registered_tenants: u16,
    ) -> Result<InitializedCredentials, Box<dyn Error>> {
        let paths = BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        drop(InstanceBootstrap::initialize_with_max_registered_tenants(
            &paths,
            InitializationPlan::non_interactive(),
            max_registered_tenants,
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let ingest = claim.ingest_secret().ok_or("ingest secret")?.to_owned();
        let query = claim.query_secret().ok_or("query secret")?.to_owned();
        let administrator = claim.secret().to_owned();
        Ok((
            Arc::new(InstanceBootstrap::reopen_with_max_registered_tenants(
                &paths,
                max_registered_tenants,
            )?),
            ingest,
            query,
            administrator,
        ))
    }

    pub(crate) fn reopen(&self) -> Result<Arc<crate::InitializedInstance>, Box<dyn Error>> {
        let paths = BootstrapPaths::new(
            &self.root.join("data"),
            &self.root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        Ok(Arc::new(InstanceBootstrap::reopen(&paths)?))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
