//! Runtime composition of the Catalog-backed maintenance coordinator.

use std::{
    collections::BTreeMap,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Duration,
};

use sha2::{Digest, Sha256};

use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogIntegrityVerificationRequest, IntegrityCancellation,
    IntegrityScrubBudget, IntegrityVerificationOutcome, IntegrityVerificationRequest,
    MaintenanceCheckpoint, MaintenanceExecution, MaintenanceFailure, MaintenanceScope,
    MaintenanceTaskClass, SegmentScope, SnapshotLeaseId, TransactionId,
};
use positron_signals::{
    LogRetentionPolicy, LogStore, LogStoreFailureCode, MaintenanceCompactionExecution,
    ScanObservationFailureCode, ScanObserver, TraceRetentionPolicy, TraceStore,
    TraceStoreFailureCode,
};

use super::{ServiceFailure, classify_catalog_failure_code};

#[derive(Clone)]
pub(super) struct MaintenanceWake {
    state: Arc<(Mutex<u64>, Condvar)>,
    idle_delay: Duration,
}

impl MaintenanceWake {
    pub(super) fn for_instance(instance: positron_kernel::InstanceId) -> Self {
        // The stable instance-specific offset prevents a fleet of otherwise
        // idle processes from reopening their catalogs on the same cadence.
        let offset = u64::from(instance.to_bytes()[0]) % 250;
        Self {
            state: Arc::new((Mutex::new(0), Condvar::new())),
            idle_delay: Duration::from_millis(500 + offset),
        }
    }

    pub(super) fn notify(&self) {
        let (_, signal) = &*self.state;
        let mut generation = self.lock_generation();
        *generation = generation.saturating_add(1);
        signal.notify_one();
    }

    pub(super) fn generation(&self) -> u64 {
        *self.lock_generation()
    }

    fn wait(&self, observed: &mut u64, delay: Duration) {
        let (_, signal) = &*self.state;
        let current = self.lock_generation();
        if *current != *observed {
            *observed = *current;
            return;
        }
        let (current, _) = match signal.wait_timeout(current, delay) {
            Ok(result) => result,
            Err(poisoned) => poisoned.into_inner(),
        };
        *observed = *current;
    }

    fn idle_delay(&self) -> Duration {
        self.idle_delay
    }

    fn lock_generation(&self) -> MutexGuard<'_, u64> {
        match self.state.0.lock() {
            Ok(generation) => generation,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Startup proves the active durability frontier for every reachable scope.
/// It intentionally does not scan sealed history; the continuously scheduled
/// `IntegrityScrub` task covers that larger immutable scope in bounded passes.
pub(super) fn verify_startup_integrity(
    instance: &crate::InitializedInstance,
) -> Result<(), ServiceFailure> {
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let tenants = positron_governance::TenantAdministration::registered_tenant_ids(&snapshot)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let mut scopes = Vec::new();
    for tenant in tenants {
        for signal in [
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::SignalKind::Traces,
        ] {
            let found = snapshot
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
            scopes
                .try_reserve(found.len())
                .map_err(|_| ServiceFailure::CapacityUnavailable)?;
            scopes.extend(found);
        }
    }
    drop(snapshot);
    for scope in scopes {
        let key = super::tenant_segment_key(instance, &identity, scope)?;
        let cancellation = IntegrityCancellation::new();
        let report = ActiveSegmentLedger::verify_catalog_integrity(
            &instance._authority,
            &catalog,
            CatalogIntegrityVerificationRequest::new(
                IntegrityVerificationRequest::new(
                    scope,
                    key,
                    IntegrityScrubBudget::new(IntegrityScrubBudget::MAX_SEGMENTS)
                        .map_err(|_| ServiceFailure::Internal)?,
                    &cancellation,
                    TransactionId::new([0x7c; 16]).map_err(|_| ServiceFailure::Internal)?,
                    None,
                ),
                positron_kernel::IntegrityVerificationMode::Startup,
            ),
        )
        .map_err(|failure| match failure.code() {
            positron_kernel::IntegrityFailureCode::StorageUnavailable => {
                ServiceFailure::StorageUnavailable
            },
            positron_kernel::IntegrityFailureCode::Cancelled => ServiceFailure::Cancelled,
            positron_kernel::IntegrityFailureCode::InvalidInput
            | positron_kernel::IntegrityFailureCode::AmbiguousIntegrity
            | positron_kernel::IntegrityFailureCode::FindingCapacity => {
                ServiceFailure::CorruptState
            },
        })?;
        if report.outcome() != IntegrityVerificationOutcome::Verified {
            return Err(ServiceFailure::CorruptState);
        }
    }
    Ok(())
}

pub(super) fn restore(instance: &crate::InitializedInstance) -> Result<(), ServiceFailure> {
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    instance
        .maintenance_coordinator()
        .replace_from_catalog(&catalog)
        .map_err(map_failure)
}

const INSTALLED_TASK_CLASSES: &[MaintenanceTaskClass] = &[
    MaintenanceTaskClass::Compaction,
    MaintenanceTaskClass::SnapshotLeaseExpiry,
    MaintenanceTaskClass::RetentionPublication,
    MaintenanceTaskClass::RetentionReclamation,
    MaintenanceTaskClass::CatalogReclamation,
    MaintenanceTaskClass::GovernanceAuditCheckpoint,
    MaintenanceTaskClass::IntegrityScrub,
];

// A source-bound scrub record is durable evidence for one completed pass. The
// next lifecycle-clock epoch receives a different stable identity so a source
// that has not changed is still reauthenticated without turning each Catalog
// publication into an immediate self-triggering loop.
const INTEGRITY_SCRUB_CADENCE_SECONDS: u64 = 86_400;
const INTEGRITY_SCRUB_JITTER_SECONDS: u64 = 900;

/// Performs one bounded coordinator dispatch for the runtime's installed
/// maintenance handlers. Unsupported durable classes remain queued for their
/// own future handlers.
#[cfg(test)]
pub(super) fn wake_runtime_maintenance(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let execution = match start_installed_maintenance(services, cancellation)? {
        Some(execution) => execution,
        None => {
            let discovered = discover_retention_publications(services, cancellation)?;
            let Some(execution) = start_installed_maintenance(services, cancellation)? else {
                return Ok(discovered);
            };
            execution
        },
    };
    let completed = complete_installed_maintenance(services, cancellation, &execution)?;
    drop(execution);
    discover_after_completed_maintenance(services, cancellation, completed)
}

fn discover_after_completed_maintenance(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
    completed: bool,
) -> Result<bool, ServiceFailure> {
    match discover_retention_publications(services, cancellation) {
        Ok(discovered) => Ok(completed || discovered),
        // Completion is already durable. A cancellation observed before the
        // next bounded discovery must stop the worker normally instead of
        // converting completed work into a worker failure.
        Err(ServiceFailure::Cancelled) if completed => Ok(true),
        Err(failure) => Err(failure),
    }
}

enum InstalledMaintenanceExecution<'authority> {
    Compaction {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
    },
    GovernanceAuditCheckpoint {
        execution: MaintenanceExecution<'authority>,
    },
    SnapshotLeaseExpiry {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
        identity: SnapshotLeaseId,
    },
    RetentionPublication {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
    },
    RetentionReclamation {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
    },
    CatalogReclamation {
        execution: MaintenanceExecution<'authority>,
    },
    IntegrityScrub {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
    },
}

fn start_installed_maintenance<'authority>(
    services: &'authority super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<Option<InstalledMaintenanceExecution<'authority>>, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let Some(_catalog_operation) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogBusy);
    };
    let instance = &services.instance;
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let coordinator = instance.maintenance_coordinator();
    let snapshot_lease_times = snapshot_lease_schedule_times(services)?;
    let selected = coordinator
        .start_next_with_reservation_and_persist_for_classes_with_snapshot_lease_times(
            &catalog,
            &instance._authority,
            now,
            instance.retention_time.status().state()
                == positron_kernel::LifecycleClockState::ClockUncertain,
            INSTALLED_TASK_CLASSES,
            &snapshot_lease_times,
        );
    let Some(execution) = (match selected {
        Ok(execution) => execution,
        Err(failure) => return Err(map_failure(failure)),
    }) else {
        return Ok(None);
    };
    // The task is now durably Running. Drain cancellation remains effective
    // until the handler enters its atomic ledger-and-Catalog publication.
    // Restart recovery returns this bounded attempt to its durable queue.
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let execution = match execution.task().class() {
        MaintenanceTaskClass::Compaction => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            InstalledMaintenanceExecution::Compaction { execution, scope }
        },
        MaintenanceTaskClass::GovernanceAuditCheckpoint => {
            InstalledMaintenanceExecution::GovernanceAuditCheckpoint { execution }
        },
        MaintenanceTaskClass::SnapshotLeaseExpiry => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            let identity = SnapshotLeaseId::new(execution.task().identity().to_bytes())
                .map_err(|_| ServiceFailure::Internal)?;
            InstalledMaintenanceExecution::SnapshotLeaseExpiry {
                execution,
                scope,
                identity,
            }
        },
        MaintenanceTaskClass::RetentionPublication => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            InstalledMaintenanceExecution::RetentionPublication { execution, scope }
        },
        MaintenanceTaskClass::RetentionReclamation => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            InstalledMaintenanceExecution::RetentionReclamation { execution, scope }
        },
        MaintenanceTaskClass::CatalogReclamation => {
            if execution.task().scope() != MaintenanceScope::System {
                return Err(ServiceFailure::Internal);
            }
            InstalledMaintenanceExecution::CatalogReclamation { execution }
        },
        MaintenanceTaskClass::IntegrityScrub => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            InstalledMaintenanceExecution::IntegrityScrub { execution, scope }
        },
        _ => return Err(ServiceFailure::Internal),
    };
    Ok(Some(execution))
}

fn snapshot_lease_schedule_times(
    services: &super::ServiceHandle,
) -> Result<BTreeMap<MaintenanceScope, u64>, ServiceFailure> {
    let coordinator = services.instance.maintenance_coordinator();
    let statuses = coordinator.statuses().map_err(map_failure)?;
    let mut times = BTreeMap::new();
    for status in statuses {
        let task = status.task();
        if status.phase() != positron_kernel::MaintenanceTaskPhase::Queued
            || task.class() != MaintenanceTaskClass::SnapshotLeaseExpiry
        {
            continue;
        }
        let scope = task.scope();
        let segment_scope = scope_for_segment_task(scope)?;
        let now = services
            .instance
            .retention_time
            .governance_time_seconds(segment_scope)
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        times.insert(scope, now);
    }
    Ok(times)
}

fn complete_installed_maintenance(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
    execution: &InstalledMaintenanceExecution<'_>,
) -> Result<bool, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let Some(_catalog_operation) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogBusy);
    };
    let instance = &services.instance;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    if let InstalledMaintenanceExecution::GovernanceAuditCheckpoint { execution } = execution {
        services
            .instance
            .complete_governance_audit_checkpoint_execution(&catalog, execution)
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        return Ok(true);
    }
    if let InstalledMaintenanceExecution::CatalogReclamation { execution } = execution {
        let coordinator = instance.maintenance_coordinator();
        catalog
            .complete_running_audit_retention_reclamation(coordinator, execution)
            .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
        return Ok(true);
    }
    let coordinator = instance.maintenance_coordinator();
    if let InstalledMaintenanceExecution::IntegrityScrub { execution, scope } = execution {
        return complete_integrity_scrub(
            services,
            instance,
            &catalog,
            coordinator,
            execution,
            *scope,
            cancellation,
        );
    }
    let scope = match execution {
        InstalledMaintenanceExecution::Compaction { scope, .. }
        | InstalledMaintenanceExecution::SnapshotLeaseExpiry { scope, .. }
        | InstalledMaintenanceExecution::RetentionPublication { scope, .. }
        | InstalledMaintenanceExecution::RetentionReclamation { scope, .. } => *scope,
        InstalledMaintenanceExecution::GovernanceAuditCheckpoint { .. }
        | InstalledMaintenanceExecution::CatalogReclamation { .. }
        | InstalledMaintenanceExecution::IntegrityScrub { .. } => {
            return Err(ServiceFailure::Internal);
        },
    };
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let durable_identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let key = super::tenant_segment_key(instance, &durable_identity, scope)?;
    let ledger = match execution {
        InstalledMaintenanceExecution::SnapshotLeaseExpiry { .. } => {
            ActiveSegmentLedger::open_with_retention_time(
                &instance._authority,
                &instance.retention_time,
                &catalog,
                scope,
                key,
            )
        },
        InstalledMaintenanceExecution::Compaction { .. }
        | InstalledMaintenanceExecution::RetentionPublication { .. }
        | InstalledMaintenanceExecution::RetentionReclamation { .. } => {
            ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                &instance._authority,
                &instance.retention_time,
                &catalog,
                scope,
                key,
            )
        },
        InstalledMaintenanceExecution::GovernanceAuditCheckpoint { .. } => {
            return Err(ServiceFailure::Internal);
        },
        InstalledMaintenanceExecution::CatalogReclamation { .. } => {
            return Err(ServiceFailure::Internal);
        },
        InstalledMaintenanceExecution::IntegrityScrub { .. } => {
            return Err(ServiceFailure::Internal);
        },
    }
    .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
    if let InstalledMaintenanceExecution::Compaction { execution, scope } = execution {
        let observer = MaintenanceScanObserver;
        let uncancelled = UncancelledMaintenance;
        let cancellation: &dyn positron_signals::ScanCancellation = cancellation
            .map(|current| current as &dyn positron_signals::ScanCancellation)
            .unwrap_or(&uncancelled);
        let maintenance =
            MaintenanceCompactionExecution::new(coordinator, execution, cancellation, &observer);
        match scope.signal_kind() {
            positron_domain::routing::SignalKind::Logs => {
                let policy = LogRetentionPolicy::from_catalog(&snapshot)
                    .map_err(map_log_compaction_failure)?;
                match LogStore::new()
                    .compact_with_maintenance(&ledger, scope.tenant_id(), policy, &maintenance)
                    .map(|_| ())
                {
                    Ok(()) => {},
                    Err(failure) if failure.code() == LogStoreFailureCode::StaleGeneration => {
                        execution
                            .fail_rejected_compaction_and_persist(coordinator, &catalog)
                            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    },
                    Err(failure) => return Err(map_log_compaction_failure(failure)),
                }
            },
            positron_domain::routing::SignalKind::Traces => {
                let policy = TraceRetentionPolicy::from_catalog(&snapshot)
                    .map_err(map_trace_compaction_failure)?;
                match TraceStore::new()
                    .compact_with_maintenance(&ledger, scope.tenant_id(), policy, &maintenance)
                    .map(|_| ())
                {
                    Ok(()) => {},
                    Err(failure) if failure.code() == TraceStoreFailureCode::StaleGeneration => {
                        execution
                            .fail_rejected_compaction_and_persist(coordinator, &catalog)
                            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    },
                    Err(failure) => return Err(map_trace_compaction_failure(failure)),
                }
            },
        }
        return Ok(true);
    }
    let completed = match execution {
        InstalledMaintenanceExecution::Compaction { .. } => return Err(ServiceFailure::Internal),
        InstalledMaintenanceExecution::SnapshotLeaseExpiry {
            execution,
            identity,
            ..
        } => ledger.complete_running_snapshot_lease_expiry_task(coordinator, execution, *identity),
        InstalledMaintenanceExecution::RetentionPublication { execution, .. } => {
            match ledger.complete_running_retention_publication_task(coordinator, execution) {
                Ok(_) => return Ok(true),
                // A rejected-before-mutation binding mismatch cannot become
                // valid by retrying the same durable execution. Publish its
                // exact terminal cause, release the existing reservation, and
                // let ordinary discovery derive a descriptor from the current
                // immutable source and retention policy.
                Err(failure)
                    if failure.code() == positron_kernel::LedgerFailureCode::StaleGeneration
                        && failure.completion_state()
                            == positron_kernel::LedgerCompletionState::RejectedBeforeMutation =>
                {
                    execution
                        .fail_rejected_retention_publication_and_persist(
                            coordinator,
                            &catalog,
                            &failure,
                        )
                        .map_err(map_failure)?;
                    return Ok(true);
                },
                Err(failure) => {
                    return Err(super::classify_ledger_failure_code(failure.code()));
                },
            }
        },
        InstalledMaintenanceExecution::RetentionReclamation { execution, .. } => {
            ledger.complete_running_retention_reclamation_task(coordinator, execution)
        },
        InstalledMaintenanceExecution::GovernanceAuditCheckpoint { .. } => {
            return Err(ServiceFailure::Internal);
        },
        InstalledMaintenanceExecution::CatalogReclamation { .. } => {
            return Err(ServiceFailure::Internal);
        },
        InstalledMaintenanceExecution::IntegrityScrub { .. } => {
            return Err(ServiceFailure::Internal);
        },
    };
    if let Err(failure) = completed {
        return Err(super::classify_ledger_failure_code(failure.code()));
    }
    Ok(true)
}

struct UncancelledMaintenance;

impl positron_signals::ScanCancellation for UncancelledMaintenance {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct MaintenanceScanObserver;

impl ScanObserver for MaintenanceScanObserver {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

fn map_log_compaction_failure(failure: positron_signals::LogStoreFailure) -> ServiceFailure {
    match failure.code() {
        LogStoreFailureCode::ResourceExhausted
        | LogStoreFailureCode::ResourceAdmissionRefused
        | LogStoreFailureCode::StorageExhausted
        | LogStoreFailureCode::LimitExceeded
        | LogStoreFailureCode::BudgetExhausted => ServiceFailure::CapacityUnavailable,
        LogStoreFailureCode::StorageUnavailable => ServiceFailure::StorageUnavailable,
        LogStoreFailureCode::Cancelled => ServiceFailure::Cancelled,
        LogStoreFailureCode::StaleGeneration
        | LogStoreFailureCode::ConcurrentWriter
        | LogStoreFailureCode::IdempotencyConflict
        | LogStoreFailureCode::SnapshotExpired
        | LogStoreFailureCode::ClockUnavailable
        | LogStoreFailureCode::ClockUncertain => ServiceFailure::CatalogUnavailable,
        LogStoreFailureCode::InvalidInput
        | LogStoreFailureCode::MalformedBlock
        | LogStoreFailureCode::PhysicalScopeMismatch
        | LogStoreFailureCode::Quarantined
        | LogStoreFailureCode::IntegrityCorruption
        | LogStoreFailureCode::AuthenticationFailed
        | LogStoreFailureCode::UnsupportedFormat
        | LogStoreFailureCode::RecoveryRequired
        | LogStoreFailureCode::StaleResumeMarker => ServiceFailure::CorruptState,
        LogStoreFailureCode::Internal => ServiceFailure::Internal,
    }
}

fn map_trace_compaction_failure(failure: positron_signals::TraceStoreFailure) -> ServiceFailure {
    match failure.code() {
        TraceStoreFailureCode::ResourceExhausted
        | TraceStoreFailureCode::ResourceAdmissionRefused
        | TraceStoreFailureCode::StorageExhausted
        | TraceStoreFailureCode::LimitExceeded
        | TraceStoreFailureCode::BudgetExhausted => ServiceFailure::CapacityUnavailable,
        TraceStoreFailureCode::StorageUnavailable => ServiceFailure::StorageUnavailable,
        TraceStoreFailureCode::Cancelled => ServiceFailure::Cancelled,
        TraceStoreFailureCode::StaleGeneration
        | TraceStoreFailureCode::ConcurrentWriter
        | TraceStoreFailureCode::IdempotencyConflict
        | TraceStoreFailureCode::SnapshotExpired
        | TraceStoreFailureCode::ClockUnavailable
        | TraceStoreFailureCode::ClockUncertain => ServiceFailure::CatalogUnavailable,
        TraceStoreFailureCode::InvalidInput
        | TraceStoreFailureCode::MalformedBlock
        | TraceStoreFailureCode::PhysicalScopeMismatch
        | TraceStoreFailureCode::Quarantined
        | TraceStoreFailureCode::IntegrityCorruption
        | TraceStoreFailureCode::AuthenticationFailed
        | TraceStoreFailureCode::UnsupportedFormat
        | TraceStoreFailureCode::RecoveryRequired
        | TraceStoreFailureCode::StaleResumeMarker => ServiceFailure::CorruptState,
        TraceStoreFailureCode::Internal => ServiceFailure::Internal,
    }
}

fn complete_integrity_scrub(
    services: &super::ServiceHandle,
    instance: &crate::InitializedInstance,
    catalog: &Catalog<'_>,
    coordinator: &positron_kernel::MaintenanceCoordinator,
    execution: &MaintenanceExecution<'_>,
    scope: SegmentScope,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let status = coordinator
        .status(execution.task().identity())
        .map_err(map_failure)?;
    let continuation = status
        .checkpoint()
        .map(|checkpoint| {
            positron_kernel::IntegrityScrubContinuation::decode(checkpoint.opaque_progress())
                .map_err(|_| ServiceFailure::CorruptState)
        })
        .transpose()?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let Some(source_binding) = execution.task().source_binding() else {
        // A record written before source binding existed is never allowed to
        // authenticate a mutable current scope by implication. Completing it
        // unsuccessfully permits discovery to publish a fresh bound task.
        execution
            .fail_and_persist(
                coordinator,
                catalog,
                positron_kernel::MaintenanceTerminalFailure::Unclassified,
            )
            .map_err(map_failure)?;
        return Ok(true);
    };
    if snapshot
        .integrity_scope_source_identity(scope)
        .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?
        != source_binding.to_bytes()
    {
        // The queued basis changed before this task was admitted. It neither
        // scanned nor succeeded; the next discovery pass owns a new basis.
        execution
            .fail_and_persist(
                coordinator,
                catalog,
                positron_kernel::MaintenanceTerminalFailure::StaleGeneration,
            )
            .map_err(map_failure)?;
        return Ok(true);
    }
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let key = super::tenant_segment_key(instance, &identity, scope)?;
    let transaction = TransactionId::new(execution.task().identity().to_bytes())
        .map_err(|_| ServiceFailure::Internal)?;
    let quarantine_audit = positron_governance::integrity_quarantine_audit_intent(
        positron_governance::IntegrityQuarantineAuditRequest {
            tenant: scope.tenant_id(),
            signal: scope.signal_kind(),
            shard: scope.shard_id().value(),
            // The kernel selects the exact localized segment only after its
            // authenticated frame check. Periodic discovery binds the durable
            // scope and reason without inventing a pre-scan segment identity.
            segment: None,
        },
    )
    .map_err(|_| ServiceFailure::Internal)?;
    let uncancelled = IntegrityCancellation::new();
    let cancellation: &dyn positron_kernel::IntegrityCancellationProbe = cancellation
        .map(|current| current as &dyn positron_kernel::IntegrityCancellationProbe)
        .unwrap_or(&uncancelled);
    let report = ActiveSegmentLedger::verify_catalog_integrity_with_audit(
        &instance._authority,
        catalog,
        CatalogIntegrityVerificationRequest::new(
            IntegrityVerificationRequest::new(
                scope,
                key,
                services.maintenance_integrity_scrub_budget()?,
                cancellation,
                transaction,
                continuation,
            ),
            positron_kernel::IntegrityVerificationMode::Online,
        )
        .with_quarantine_audit(quarantine_audit),
    )
    .map_err(|failure| match failure.code() {
        positron_kernel::IntegrityFailureCode::StorageUnavailable => {
            ServiceFailure::StorageUnavailable
        },
        positron_kernel::IntegrityFailureCode::Cancelled => ServiceFailure::Cancelled,
        positron_kernel::IntegrityFailureCode::InvalidInput
        | positron_kernel::IntegrityFailureCode::AmbiguousIntegrity
        | positron_kernel::IntegrityFailureCode::FindingCapacity => ServiceFailure::CorruptState,
    })?;
    match report.outcome() {
        IntegrityVerificationOutcome::Verified => {
            execution
                .complete_and_persist(coordinator, catalog, true)
                .map_err(map_failure)?;
            Ok(true)
        },
        IntegrityVerificationOutcome::Incomplete => {
            let continuation = report.continuation().ok_or(ServiceFailure::CorruptState)?;
            let sequence = status
                .checkpoint()
                .map_or(1, |checkpoint| checkpoint.sequence().saturating_add(1));
            let current_completed_inputs = status
                .checkpoint()
                .map_or(0, positron_kernel::MaintenanceCheckpoint::completed_inputs);
            let examined_inputs = u32::try_from(report.examined_segments())
                .map_err(|_| ServiceFailure::CapacityUnavailable)?;
            let completed_inputs = current_completed_inputs
                .checked_add(examined_inputs)
                .ok_or(ServiceFailure::CapacityUnavailable)?;
            let checkpoint = MaintenanceCheckpoint::new(
                sequence,
                completed_inputs,
                continuation.encode().to_vec(),
            )
            .map_err(map_failure)?;
            execution
                // Integrity authentication is not age-derived work. A clock
                // uncertainty therefore must not make a bounded scrub lose its
                // durable resume point or stop responding to corruption.
                .checkpoint_and_persist(coordinator, catalog, checkpoint)
                .map_err(map_failure)?;
            Ok(false)
        },
        IntegrityVerificationOutcome::Quarantined => {
            execution
                .complete_and_persist(coordinator, catalog, false)
                .map_err(map_failure)?;
            services.mark_integrity_degraded();
            Ok(true)
        },
        IntegrityVerificationOutcome::Stale => {
            // A sealed source changed while this bounded task was waiting.
            // Leave its truthful terminal record, then let discovery submit
            // the new source identity without fencing healthy service.
            execution
                .complete_and_persist(coordinator, catalog, false)
                .map_err(map_failure)?;
            Ok(true)
        },
        IntegrityVerificationOutcome::Fenced => {
            execution
                .complete_and_persist(coordinator, catalog, false)
                .map_err(map_failure)?;
            Err(ServiceFailure::CorruptState)
        },
    }
}

fn discover_retention_publications(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let integrity_discovered = discover_integrity_scrubs(services, cancellation)?;
    // Do not let retention open a newly discovered damaged source before its
    // higher-priority scrub has authenticated it. The next worker turn will
    // dispatch this durable descriptor and either quarantine localized damage
    // or preserve the existing fail-closed fence for ambiguous evidence.
    if integrity_discovered {
        return Ok(true);
    }
    let instance = &services.instance;
    if instance.retention_time.status().state() != positron_kernel::LifecycleClockState::Certain {
        return Ok(integrity_discovered);
    }
    let Some(_catalog_operation) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogBusy);
    };
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let tenants = positron_governance::TenantAdministration::registered_tenant_ids(&snapshot)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let mut scopes = Vec::new();
    for tenant in tenants {
        for signal in [
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::SignalKind::Traces,
        ] {
            let found = snapshot
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
            scopes
                .try_reserve(found.len())
                .map_err(|_| ServiceFailure::CapacityUnavailable)?;
            scopes.extend(found);
        }
    }
    drop(snapshot);
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let coordinator = instance.maintenance_coordinator();
    let mut submitted = false;
    for scope in scopes {
        if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
            return Err(ServiceFailure::Cancelled);
        }
        let maintenance_scope =
            MaintenanceScope::segment(scope.tenant_id(), scope.signal_kind(), scope.shard_id());
        if coordinator
            .has_nonterminal_task_for_scope(MaintenanceTaskClass::IntegrityScrub, maintenance_scope)
            .map_err(map_failure)?
        {
            // A persisted scrub describes this exact immutable source. Wait
            // for its due instant and authentication outcome before retention
            // opens the same scope; other scopes remain independently eligible.
            continue;
        }
        if coordinator
            .has_nonterminal_retention_task_for_scope(maintenance_scope)
            .map_err(map_failure)?
        {
            continue;
        }
        let key = super::tenant_segment_key(instance, &identity, scope)?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )
        .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
        match ledger.prepare_retention_publication() {
            Ok(preparation) => {
                preparation
                    .submit_and_persist(coordinator, &catalog, now)
                    .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
                submitted = true;
            },
            Err(failure)
                if matches!(
                    failure.code(),
                    positron_kernel::LedgerFailureCode::InvalidInput
                        | positron_kernel::LedgerFailureCode::ClockUncertain
                ) => {},
            Err(failure) => return Err(super::classify_ledger_failure_code(failure.code())),
        }
    }
    Ok(submitted)
}

fn discover_integrity_scrubs(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let Some(_catalog_operation) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogBusy);
    };
    let instance = &services.instance;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let tenants = positron_governance::TenantAdministration::registered_tenant_ids(&snapshot)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let mut scopes = Vec::new();
    for tenant in tenants {
        for signal in [
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::SignalKind::Traces,
        ] {
            let found = snapshot
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
            scopes
                .try_reserve(found.len())
                .map_err(|_| ServiceFailure::CapacityUnavailable)?;
            for scope in found {
                let source_identity = snapshot
                    .integrity_scope_source_identity(scope)
                    .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
                scopes.push((scope, source_identity));
            }
        }
    }
    drop(snapshot);
    // The Lifecycle Clock remains process-monotonic when wall-clock safety is
    // uncertain. Integrity authentication is safe work, so it must retain its
    // cadence instead of being treated like age-derived destruction.
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let verification_epoch = now / INTEGRITY_SCRUB_CADENCE_SECONDS;
    let coordinator = instance.maintenance_coordinator();
    let mut submitted = false;
    for (scope, source_identity) in scopes {
        if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
            return Err(ServiceFailure::Cancelled);
        }
        let maintenance_scope =
            MaintenanceScope::segment(scope.tenant_id(), scope.signal_kind(), scope.shard_id());
        if coordinator
            .has_nonterminal_task_for_scope(MaintenanceTaskClass::IntegrityScrub, maintenance_scope)
            .map_err(map_failure)?
        {
            continue;
        }
        let identity = integrity_task_identity(scope, source_identity, verification_epoch)?;
        match coordinator.status(identity) {
            Ok(_) => continue,
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(failure) => return Err(map_failure(failure)),
        }
        let task = positron_kernel::MaintenanceTask::integrity_scrub(
            identity,
            maintenance_scope,
            positron_kernel::MaintenanceTrigger::Scheduled,
            // A task record publication advances the Catalog generation but
            // does not change the immutable-segment source identity. Read the
            // current generation immediately before each descriptor so later
            // scopes do not inherit a stale precondition from an earlier
            // descriptor's publication.
            positron_kernel::MaintenancePreconditions::new(
                catalog
                    .pin()
                    .map_err(|failure| classify_catalog_failure_code(failure.code()))?
                    .number(),
                1,
            )
            .map_err(map_failure)?,
            source_identity,
            integrity_scrub_not_before(instance.instance, scope, verification_epoch)?,
        )
        .map_err(map_failure)?;
        coordinator
            .submit_and_persist(&catalog, task, now)
            .map_err(map_failure)?;
        submitted = true;
    }
    Ok(submitted)
}

fn integrity_scrub_not_before(
    instance: positron_kernel::InstanceId,
    scope: SegmentScope,
    verification_epoch: u64,
) -> Result<u64, ServiceFailure> {
    let epoch_start = verification_epoch
        .checked_mul(INTEGRITY_SCRUB_CADENCE_SECONDS)
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    let mut digest = Sha256::new();
    digest.update(b"positron/integrity-scrub-jitter/v1");
    digest.update(instance.to_bytes());
    digest.update(scope.tenant_id().to_bytes());
    digest.update([match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    }]);
    digest.update(scope.shard_id().value().to_be_bytes());
    digest.update(verification_epoch.to_be_bytes());
    let bytes: [u8; 8] = digest
        .finalize()
        .get(..8)
        .and_then(|value| value.try_into().ok())
        .ok_or(ServiceFailure::Internal)?;
    epoch_start
        .checked_add(u64::from_be_bytes(bytes) % INTEGRITY_SCRUB_JITTER_SECONDS)
        .ok_or(ServiceFailure::CapacityUnavailable)
}

fn integrity_task_identity(
    scope: SegmentScope,
    source_identity: [u8; 32],
    verification_epoch: u64,
) -> Result<positron_kernel::MaintenanceTaskId, ServiceFailure> {
    let mut digest = Sha256::new();
    digest.update(b"positron/integrity-scrub/v2");
    digest.update(scope.tenant_id().to_bytes());
    digest.update([match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    }]);
    digest.update(scope.shard_id().value().to_be_bytes());
    digest.update(source_identity);
    digest.update(verification_epoch.to_be_bytes());
    let bytes = digest.finalize();
    let identity = bytes
        .get(..16)
        .and_then(|value| value.try_into().ok())
        .ok_or(ServiceFailure::Internal)?;
    positron_kernel::MaintenanceTaskId::new(identity).map_err(map_failure)
}

pub(super) fn run_runtime_maintenance_worker(
    services: &super::ServiceHandle,
    cancellation: &crate::TaskCancellation,
    wake_signal: &MaintenanceWake,
) -> Result<(), ServiceFailure> {
    const WORK_YIELD: Duration = Duration::from_millis(10);
    const INITIAL_TRANSIENT_BACKOFF: Duration = Duration::from_millis(50);
    const MAX_TRANSIENT_BACKOFF: Duration = Duration::from_secs(2);

    let mut observed = wake_signal.generation();
    let mut retry_delay = INITIAL_TRANSIENT_BACKOFF;
    let mut in_flight = None;
    while !cancellation.is_cancelled() {
        let mut completed_integrity = false;
        let result = match in_flight.take() {
            Some(execution) => {
                completed_integrity = matches!(
                    execution,
                    InstalledMaintenanceExecution::IntegrityScrub { .. }
                );
                match complete_installed_maintenance(services, Some(cancellation), &execution) {
                    Ok(completed) => {
                        let continues_integrity_scrub = match &execution {
                            InstalledMaintenanceExecution::IntegrityScrub { execution, .. } => {
                                services
                                    .instance
                                    .maintenance_coordinator()
                                    .status(execution.task().identity())
                                    .map_err(map_failure)?
                                    .phase()
                                    == positron_kernel::MaintenanceTaskPhase::Running
                            },
                            _ => false,
                        };
                        if continues_integrity_scrub {
                            in_flight = Some(execution);
                            Ok(completed)
                        } else {
                            drop(execution);
                            discover_after_completed_maintenance(
                                services,
                                Some(cancellation),
                                completed,
                            )
                        }
                    },
                    Err(ServiceFailure::Cancelled) => break,
                    Err(failure) => {
                        // A durable task remains Running when its terminal
                        // publication has a transient failure. Keep the same
                        // execution and reservation so the loop's existing
                        // bounded retry policy can reconcile that exact task.
                        in_flight = Some(execution);
                        Err(failure)
                    },
                }
            },
            None => match start_installed_maintenance(services, Some(cancellation)) {
                Ok(Some(execution)) => {
                    in_flight = Some(execution);
                    continue;
                },
                Ok(None) => match discover_retention_publications(services, Some(cancellation)) {
                    Ok(discovered) => {
                        match start_installed_maintenance(services, Some(cancellation)) {
                            Ok(Some(execution)) => {
                                in_flight = Some(execution);
                                continue;
                            },
                            Ok(None) => Ok(discovered),
                            Err(ServiceFailure::Cancelled) => break,
                            Err(failure) => Err(failure),
                        }
                    },
                    Err(ServiceFailure::Cancelled) => break,
                    Err(failure) => Err(failure),
                },
                Err(ServiceFailure::Cancelled) => break,
                Err(failure) => Err(failure),
            },
        };
        let delay = match result {
            Ok(true) => {
                retry_delay = INITIAL_TRANSIENT_BACKOFF;
                if completed_integrity {
                    // Reuse the coordinator's existing instance-stable idle
                    // cadence between bounded full-scope passes. A verified
                    // pass publishes its terminal task and thus advances the
                    // Catalog generation; immediate rediscovery would turn
                    // that publication into a tight self-triggering loop.
                    wake_signal.idle_delay()
                } else {
                    WORK_YIELD
                }
            },
            Ok(false) | Err(ServiceFailure::Cancelled) => {
                retry_delay = INITIAL_TRANSIENT_BACKOFF;
                wake_signal.idle_delay()
            },
            // Public API calls share the in-process Catalog gate. They are
            // healthy work and must not turn a local scheduling collision into
            // exponential I/O backoff that can starve a durable task.
            Err(ServiceFailure::CatalogBusy) => WORK_YIELD,
            Err(
                ServiceFailure::CapacityUnavailable
                | ServiceFailure::CatalogUnavailable
                | ServiceFailure::StorageUnavailable,
            ) => {
                retry_delay = retry_delay.saturating_mul(2).min(MAX_TRANSIENT_BACKOFF);
                retry_delay
            },
            Err(failure) => return Err(failure),
        };
        wake_signal.wait(&mut observed, delay);
    }
    Ok(())
}

fn scope_for_segment_task(scope: MaintenanceScope) -> Result<SegmentScope, ServiceFailure> {
    match scope {
        MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } => Ok(SegmentScope::new(tenant, signal, shard)),
        MaintenanceScope::System | MaintenanceScope::Tenant(_) => Err(ServiceFailure::CorruptState),
    }
}

fn map_failure(failure: MaintenanceFailure) -> ServiceFailure {
    match failure {
        MaintenanceFailure::CatalogUnavailable => ServiceFailure::CatalogUnavailable,
        MaintenanceFailure::ResourceAdmissionRefused | MaintenanceFailure::CapacityExceeded => {
            ServiceFailure::CapacityUnavailable
        },
        MaintenanceFailure::InvalidInput
        | MaintenanceFailure::ConcurrentAccess
        | MaintenanceFailure::UnknownTask
        | MaintenanceFailure::InvalidTransition
        | MaintenanceFailure::PreconditionFailed
        | MaintenanceFailure::Paused => ServiceFailure::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_scrub_jitter_is_stable_per_instance_and_separates_known_fixtures() {
        let scope = SegmentScope::new(
            positron_domain::identity::TenantId::from_bytes([0x31; 16]).expect("tenant"),
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(1).expect("shard"),
        );
        let first = integrity_scrub_not_before(
            positron_kernel::InstanceId::new([0x41; 16]).expect("instance"),
            scope,
            7,
        )
        .expect("jitter");
        assert_eq!(
            first,
            integrity_scrub_not_before(
                positron_kernel::InstanceId::new([0x41; 16]).expect("instance"),
                scope,
                7,
            )
            .expect("reopen jitter"),
            "the persisted descriptor receives one repeatable per-instance due instant"
        );
        assert_ne!(
            first,
            integrity_scrub_not_before(
                positron_kernel::InstanceId::new([0x42; 16]).expect("other instance"),
                scope,
                7,
            )
            .expect("other jitter"),
            "the fixed fleet fixtures do not synchronize their next scrub"
        );
    }

    #[test]
    fn integrity_scrub_jitter_uses_the_current_slot_at_an_arbitrary_lifecycle_time() {
        let scope = SegmentScope::new(
            positron_domain::identity::TenantId::from_bytes([0x31; 16]).expect("tenant"),
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(1).expect("shard"),
        );
        let now = 7_u64
            .checked_mul(INTEGRITY_SCRUB_CADENCE_SECONDS)
            .and_then(|start| start.checked_add(413))
            .expect("bounded fixture time");
        let epoch = now / INTEGRITY_SCRUB_CADENCE_SECONDS;
        let due = integrity_scrub_not_before(
            positron_kernel::InstanceId::new([0x41; 16]).expect("instance"),
            scope,
            epoch,
        )
        .expect("jitter");
        let slot_start = epoch
            .checked_mul(INTEGRITY_SCRUB_CADENCE_SECONDS)
            .expect("bounded fixture slot");
        assert!(
            (slot_start..slot_start + INTEGRITY_SCRUB_JITTER_SECONDS).contains(&due),
            "an arbitrary lifecycle time schedules within its current bounded slot"
        );
        assert_eq!(epoch, 7, "the elapsed offset must not reset the epoch");
    }

    #[test]
    fn poisoned_wake_preserves_the_next_runtime_notification() {
        let wake = MaintenanceWake::for_instance(
            positron_kernel::InstanceId::new([7; 16]).expect("instance"),
        );
        let state = Arc::clone(&wake.state);
        let _ = std::panic::catch_unwind(move || {
            let (generation, _) = &*state;
            let _guard = generation.lock().expect("wake lock");
            panic!("poison the wake lock");
        });

        wake.notify();
        assert_eq!(
            wake.generation(),
            1,
            "a poisoned wake cannot discard runtime work"
        );
    }
}
