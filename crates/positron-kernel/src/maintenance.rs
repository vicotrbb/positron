//! Bounded coordination of Storage Kernel background work.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::{
    CatalogObject, DiskPressureState, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts,
    ResourceDimension, ResourceReservation, StorageKernelResourceAuthority, WorkClaim, WorkKind,
};

mod compaction;
#[cfg(fuzzing)]
mod fuzzing;
mod persistence;
mod record;

#[cfg(fuzzing)]
pub use fuzzing::fuzz_maintenance_catalog_stateful;

pub use compaction::CompactionBinding;
pub(crate) use compaction::{compaction_task_record_bytes, compaction_task_record_working_bytes};

pub(crate) use persistence::{
    SnapshotLeaseExpiryTaskReplacement, retention_publication_record_bytes_bound,
};
use record::{decode_record, encode_record};

pub(crate) fn durable_task_record_identity(
    bytes: &[u8],
) -> Result<Option<MaintenanceTaskId>, MaintenanceFailure> {
    record::record_identity(bytes)
}

/// Verifies the exact queued expiry descriptor paired with one live Snapshot
/// Lease. The caller supplies values decoded from the same Catalog generation
/// as the lease, so a successor Catalog is never used as snapshot authority.
pub(crate) fn validate_active_snapshot_lease_expiry_descriptor(
    bytes: &[u8],
    lease: crate::SnapshotLeaseId,
    scope: crate::active_segment_ledger::SegmentScope,
    lease_object: crate::CatalogObjectId,
    predecessor_generation: u64,
    expiry: u64,
) -> Result<(), MaintenanceFailure> {
    let state = decode_record(bytes)?;
    let expected = MaintenanceTaskId::new(lease.to_bytes())?;
    let expected_input = MaintenanceObjectId::new(lease_object.to_bytes())?;
    if state.task.identity != expected
        || state.task.class != MaintenanceTaskClass::SnapshotLeaseExpiry
        || state.task.scope
            != MaintenanceScope::segment(scope.tenant_id(), scope.signal_kind(), scope.shard_id())
        || state.task.trigger != MaintenanceTrigger::Scheduled
        || state.task.preconditions.catalog_generation != predecessor_generation
        || state.task.preconditions.resource_generation != 1
        || state.task.inputs.as_slice() != [expected_input]
        || !state.task.outputs.is_empty()
        || state.task.not_before != expiry
        || state.phase != MaintenanceTaskPhase::Queued
        || state.cancellation_requested
    {
        return Err(MaintenanceFailure::InvalidInput);
    }
    Ok(())
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn rewrite_durable_task_record_dispatches_for_test(
    bytes: &[u8],
    dispatches: u64,
) -> Result<Vec<u8>, MaintenanceFailure> {
    let mut state = record::decode_record(bytes)?;
    state.dispatches = dispatches;
    Ok(record::encode_record(&state)?.as_bytes().to_vec())
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn rewrite_durable_task_record_not_before_for_test(
    bytes: &[u8],
    not_before: u64,
) -> Result<Vec<u8>, MaintenanceFailure> {
    let mut state = record::decode_record(bytes)?;
    state.task.not_before = not_before;
    Ok(record::encode_record(&state)?.as_bytes().to_vec())
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn rewrite_durable_task_record_trigger_for_test(
    bytes: &[u8],
    trigger: MaintenanceTrigger,
) -> Result<Vec<u8>, MaintenanceFailure> {
    let mut state = record::decode_record(bytes)?;
    state.task.trigger = trigger;
    Ok(record::encode_record(&state)?.as_bytes().to_vec())
}

const MAX_MAINTENANCE_TASKS: usize = 128;
pub(crate) const MAX_TASK_OBJECTS: usize = 16;
pub(crate) const MAX_CHECKPOINT_BYTES: usize = 4_096;
const RETENTION_PUBLICATION_FRONTIER_MAGIC: &[u8; 8] = b"RTPFR001";
const GOVERNANCE_AUDIT_CHECKPOINT_BINDING_MAGIC: &[u8; 8] = b"GACPB001";
const GOVERNANCE_AUDIT_CHECKPOINT_BINDING_BYTES: usize = 8 + 8 + 32 + 32;

pub(crate) fn retention_publication_frontier_checkpoint(
    frontier: crate::IngestTime,
) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(RETENTION_PUBLICATION_FRONTIER_MAGIC.len() + 8)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    bytes.extend_from_slice(RETENTION_PUBLICATION_FRONTIER_MAGIC);
    bytes.extend_from_slice(&frontier.instant().value().to_be_bytes());
    MaintenanceCheckpoint::new(1, 0, bytes)
}

pub(crate) fn retention_publication_frontier(
    checkpoint: Option<&MaintenanceCheckpoint>,
) -> Result<crate::IngestTime, MaintenanceFailure> {
    let checkpoint = checkpoint.ok_or(MaintenanceFailure::InvalidInput)?;
    let bytes = checkpoint.opaque_progress();
    if checkpoint.sequence() != 1
        || checkpoint.completed_inputs() != 0
        || bytes.len() != RETENTION_PUBLICATION_FRONTIER_MAGIC.len() + 8
        || !bytes.starts_with(RETENTION_PUBLICATION_FRONTIER_MAGIC)
    {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let instant = bytes
        .get(RETENTION_PUBLICATION_FRONTIER_MAGIC.len()..)
        .ok_or(MaintenanceFailure::InvalidInput)?
        .try_into()
        .map_err(|_| MaintenanceFailure::InvalidInput)?;
    Ok(crate::IngestTime::from_authenticated_durable(
        positron_domain::time::UnixNanoseconds::new(i64::from_be_bytes(instant)),
    ))
}

/// The immutable frontier and integrity-key identity a governance checkpoint
/// task must sign. Keeping this in the durable task checkpoint prevents a
/// delayed worker from silently advancing a caller's requested frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernanceAuditCheckpointBinding {
    position: u64,
    record_hash: [u8; 32],
    integrity_key_fingerprint: [u8; 32],
}

impl GovernanceAuditCheckpointBinding {
    pub fn new(
        position: u64,
        record_hash: [u8; 32],
        integrity_key_fingerprint: [u8; 32],
    ) -> Result<Self, MaintenanceFailure> {
        if position == 0
            || record_hash.iter().all(|byte| *byte == 0)
            || integrity_key_fingerprint.iter().all(|byte| *byte == 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            position,
            record_hash,
            integrity_key_fingerprint,
        })
    }

    #[must_use]
    pub const fn position(self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn record_hash(self) -> [u8; 32] {
        self.record_hash
    }

    #[must_use]
    pub const fn integrity_key_fingerprint(self) -> [u8; 32] {
        self.integrity_key_fingerprint
    }

    pub fn checkpoint(self) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(GOVERNANCE_AUDIT_CHECKPOINT_BINDING_BYTES)
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        bytes.extend_from_slice(GOVERNANCE_AUDIT_CHECKPOINT_BINDING_MAGIC);
        bytes.extend_from_slice(&self.position.to_be_bytes());
        bytes.extend_from_slice(&self.record_hash);
        bytes.extend_from_slice(&self.integrity_key_fingerprint);
        MaintenanceCheckpoint::new(1, 0, bytes)
    }

    pub fn from_checkpoint(
        checkpoint: Option<&MaintenanceCheckpoint>,
    ) -> Result<Self, MaintenanceFailure> {
        let checkpoint = checkpoint.ok_or(MaintenanceFailure::InvalidInput)?;
        let bytes = checkpoint.opaque_progress();
        if checkpoint.sequence() != 1
            || checkpoint.completed_inputs() != 0
            || bytes.len() != GOVERNANCE_AUDIT_CHECKPOINT_BINDING_BYTES
            || !bytes.starts_with(GOVERNANCE_AUDIT_CHECKPOINT_BINDING_MAGIC)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let position = bytes
            .get(8..16)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let record_hash = bytes
            .get(16..48)
            .and_then(|value| value.try_into().ok())
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let integrity_key_fingerprint = bytes
            .get(48..80)
            .and_then(|value| value.try_into().ok())
            .ok_or(MaintenanceFailure::InvalidInput)?;
        Self::new(position, record_hash, integrity_key_fingerprint)
    }
}
/// The bounded queue delay after which ordinary and required maintenance is
/// promoted to Urgent scheduling priority.
pub const MAX_LOWER_CLASS_QUEUE_DELAY_SECONDS: u64 = 60;
/// The initial server-owned deadline for a running task to durably advance
/// its checkpoint. This is independent from queued-work priority escalation.
pub const NO_DURABLE_PROGRESS_SLO_SECONDS: u64 = 60;
static NEXT_COORDINATOR_ID: AtomicU64 = AtomicU64::new(1);

mod model;

pub use model::*;

/// Typed rejection from the maintenance control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceFailure {
    InvalidInput,
    CapacityExceeded,
    ConcurrentAccess,
    UnknownTask,
    InvalidTransition,
    PreconditionFailed,
    Paused,
    ResourceAdmissionRefused,
    CatalogUnavailable,
}

/// Closed, durable cause for a task that has reached the Failed phase.
///
/// Retryable execution failures never enter this enum: their handler keeps
/// the same running descriptor for the worker's bounded retry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceTerminalFailure {
    /// A legacy record or compatibility boolean failure did not retain a more
    /// specific cause.
    Unclassified,
    /// A Governance Audit checkpoint binding no longer matches durable
    /// identity material and cannot safely execute.
    IdentityMismatch,
    /// An immutable source or policy binding changed before its handler could
    /// begin externally visible work.
    StaleGeneration,
}

/// The only scheduler for background Storage Kernel work.
pub struct MaintenanceCoordinator {
    state: Mutex<CoordinatorState>,
    coordinator_id: u64,
    live_executions: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct CoordinatorState {
    tasks: BTreeMap<MaintenanceTaskId, TaskState>,
    pending_submissions: BTreeSet<MaintenanceTaskId>,
    pending_terminal_reclamations: BTreeSet<MaintenanceTaskId>,
    pending_task_transitions: BTreeSet<MaintenanceTaskId>,
    window: Option<MaintenanceWindow>,
    clock_uncertain_durable_eligibility: BTreeSet<MaintenanceTaskId>,
    fairness: BTreeMap<(MaintenancePriority, MaintenanceScope), u64>,
    next_terminal_order: u64,
}

fn require_unreserved_task_transition(
    state: &CoordinatorState,
    identity: MaintenanceTaskId,
) -> Result<(), MaintenanceFailure> {
    if state.pending_task_transitions.contains(&identity) {
        return Err(MaintenanceFailure::PreconditionFailed);
    }
    Ok(())
}

#[derive(Clone)]
struct MaintenanceWindow {
    deferred: BTreeSet<MaintenanceTaskClass>,
    until: u64,
}

#[derive(Clone, Eq, PartialEq)]
struct TaskState {
    task: MaintenanceTask,
    phase: MaintenanceTaskPhase,
    terminal_failure: Option<MaintenanceTerminalFailure>,
    submitted_at: u64,
    checkpoint: Option<MaintenanceCheckpoint>,
    last_progress_at: Option<u64>,
    pause_until: Option<u64>,
    cancellation_requested: bool,
    dispatches: u64,
    terminal_order: Option<u64>,
    active_dispatch: Option<MaintenanceDispatch>,
}

fn validate_retention_publication_state(state: &TaskState) -> Result<(), MaintenanceFailure> {
    if state.task.class == MaintenanceTaskClass::RetentionPublication {
        let _ = retention_publication_frontier(state.checkpoint.as_ref())?;
    }
    if state.task.class == MaintenanceTaskClass::GovernanceAuditCheckpoint {
        let binding = GovernanceAuditCheckpointBinding::from_checkpoint(state.checkpoint.as_ref())?;
        if !matches!(state.task.scope, MaintenanceScope::System)
            || state.task.inputs.len() != 1
            || state.task.inputs[0].to_bytes() != binding.record_hash()
            || state.task.outputs.len() != 1
            || state.task.outputs[0].to_bytes() != binding.integrity_key_fingerprint()
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
    }
    Ok(())
}

fn validate_retention_reclamation_state(state: &TaskState) -> Result<(), MaintenanceFailure> {
    let task = &state.task;
    if task.class != MaintenanceTaskClass::RetentionReclamation {
        return Ok(());
    }
    let MaintenanceScope::Segment { .. } = task.scope else {
        return Err(MaintenanceFailure::InvalidInput);
    };
    let Some(first) = task.inputs.first() else {
        return Err(MaintenanceFailure::InvalidInput);
    };
    if !matches!(
        task.trigger,
        MaintenanceTrigger::Event | MaintenanceTrigger::AgeDerived
    ) || task.inputs.len() > 16
        || !task.outputs.is_empty()
        || task.not_before != 0
        || task.emergency_compaction
        || state.checkpoint.is_some()
        || state.pause_until.is_some()
        || task.inputs.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&first.to_bytes()[..16]);
    bytes[0] ^= 0xa5;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    if task.identity != MaintenanceTaskId::new(bytes)? {
        return Err(MaintenanceFailure::InvalidInput);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaintenanceDispatch {
    coordinator_id: u64,
    identity: MaintenanceTaskId,
    attempt: u64,
}

/// Immutable durable binding that ties a running Snapshot Lease expiry task to
/// the one lease record it may remove.
pub(crate) struct SnapshotLeaseExpiryBinding<'record> {
    identity: crate::SnapshotLeaseId,
    scope: MaintenanceScope,
    lease_object: crate::CatalogObjectId,
    predecessor_generation: u64,
    not_before: u64,
    durable_record: &'record [u8],
}

/// Immutable task records that the ledger must atomically replace when a
/// Retention Publication becomes visible. The coordinator owns the state
/// transition; the ledger owns the matching Catalog publication.
pub(crate) struct RetentionPublicationBinding<'task, 'record> {
    publication: &'task MaintenanceTask,
    reclamation: MaintenanceTask,
    durable_record: &'record [u8],
}

impl<'task, 'record> RetentionPublicationBinding<'task, 'record> {
    #[must_use]
    pub(crate) const fn new(
        publication: &'task MaintenanceTask,
        reclamation: MaintenanceTask,
        durable_record: &'record [u8],
    ) -> Self {
        Self {
            publication,
            reclamation,
            durable_record,
        }
    }
}

impl<'record> SnapshotLeaseExpiryBinding<'record> {
    #[must_use]
    pub(crate) const fn new(
        identity: crate::SnapshotLeaseId,
        scope: MaintenanceScope,
        lease_object: crate::CatalogObjectId,
        predecessor_generation: u64,
        not_before: u64,
        durable_record: &'record [u8],
    ) -> Self {
        Self {
            identity,
            scope,
            lease_object,
            predecessor_generation,
            not_before,
            durable_record,
        }
    }
}

/// Read-only task status. It exposes no unbounded object identifiers in telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTaskStatus {
    task: MaintenanceTask,
    phase: MaintenanceTaskPhase,
    terminal_failure: Option<MaintenanceTerminalFailure>,
    submitted_at: u64,
    checkpoint: Option<MaintenanceCheckpoint>,
    last_progress_at: Option<u64>,
    no_durable_progress_slo_breached: Option<bool>,
    pause_until: Option<u64>,
    cancellation_requested: bool,
    conflict_owner: Option<MaintenanceTaskId>,
    clock_uncertain_blocked: bool,
}

/// A live Resource Governor grant attached to a running task. The coordinator
/// never manufactures capacity and the grant drops on every handler path.
pub enum MaintenanceReservation<'authority> {
    Ordinary(ResourceReservation<'authority>),
    Recovery(ResourceReservation<'authority>),
}

/// The sole authority from which a task's declared reservation is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceReservationAuthority {
    Foreground,
    RecoveryReserve,
}

impl MaintenanceTask {
    /// Returns the coordinator's source of capacity for this task class.
    #[must_use]
    pub fn reservation_authority(&self) -> MaintenanceReservationAuthority {
        if scheduling::recovery_kind(self).is_some() {
            MaintenanceReservationAuthority::RecoveryReserve
        } else {
            MaintenanceReservationAuthority::Foreground
        }
    }
}

impl MaintenanceReservation<'_> {
    #[must_use]
    pub fn granted(&self) -> ResourceAmounts {
        match self {
            Self::Ordinary(reservation) | Self::Recovery(reservation) => reservation.granted(),
        }
    }

    pub(crate) fn authorizes_ordinary_compaction(
        &self,
        governor: crate::ResourceGovernor<'_>,
        tenant: TenantId,
    ) -> bool {
        match self {
            Self::Ordinary(reservation) => {
                reservation.belongs_to(governor)
                    && reservation.authorizes_ordinary_compaction(tenant)
            },
            Self::Recovery(_) => false,
        }
    }
}

/// A task selected by the coordinator after its complete peak reservation was admitted.
pub struct MaintenanceExecution<'authority> {
    task: MaintenanceTask,
    checkpoint: Option<MaintenanceCheckpoint>,
    reservation: MaintenanceReservation<'authority>,
    dispatch: MaintenanceDispatch,
    live_executions: Arc<AtomicUsize>,
    tracked_live: bool,
}

impl Drop for MaintenanceExecution<'_> {
    fn drop(&mut self) {
        if self.tracked_live {
            self.live_executions.fetch_sub(1, Ordering::Release);
        }
    }
}

impl MaintenanceExecution<'_> {
    #[must_use]
    pub fn task(&self) -> &MaintenanceTask {
        &self.task
    }
    #[must_use]
    pub fn task_checkpoint(&self) -> Option<&MaintenanceCheckpoint> {
        self.checkpoint.as_ref()
    }
    #[must_use]
    pub fn reservation(&self) -> &MaintenanceReservation<'_> {
        &self.reservation
    }

    #[cfg(any(test, fuzzing))]
    fn checkpoint_dispatch(
        &self,
        coordinator: &MaintenanceCoordinator,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        if self.dispatch.coordinator_id != coordinator.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, self.dispatch.identity)?;
        let task = state
            .tasks
            .get_mut(&self.dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(self.dispatch)
            || (task.task.class != MaintenanceTaskClass::IntegrityScrub
                && checkpoint.completed_inputs as usize > task.task.inputs.len())
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        if task
            .checkpoint
            .as_ref()
            .is_some_and(|previous| previous.sequence >= checkpoint.sequence)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        task.checkpoint = Some(checkpoint);
        Ok(())
    }

    #[cfg(any(test, fuzzing))]
    pub fn checkpoint(
        &self,
        coordinator: &MaintenanceCoordinator,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        self.checkpoint_dispatch(coordinator, checkpoint)
    }

    #[cfg(any(test, fuzzing))]
    fn complete_dispatch(
        &self,
        coordinator: &MaintenanceCoordinator,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        if self.dispatch.coordinator_id != coordinator.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, self.dispatch.identity)?;
        {
            let task = state
                .tasks
                .get_mut(&self.dispatch.identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if task.phase != MaintenanceTaskPhase::Running
                || task.active_dispatch != Some(self.dispatch)
            {
                return Err(MaintenanceFailure::InvalidTransition);
            }
            let (phase, terminal_failure) = if task.cancellation_requested {
                (MaintenanceTaskPhase::Cancelled, None)
            } else if succeeded {
                (MaintenanceTaskPhase::Succeeded, None)
            } else {
                (
                    MaintenanceTaskPhase::Failed,
                    Some(MaintenanceTerminalFailure::Unclassified),
                )
            };
            task.phase = phase;
            task.terminal_failure = terminal_failure;
            task.last_progress_at = None;
            task.active_dispatch = None;
        }
        assign_terminal_order(&mut state, self.dispatch.identity)
    }

    #[cfg(any(test, fuzzing))]
    pub fn complete(
        self,
        coordinator: &MaintenanceCoordinator,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        self.complete_dispatch(coordinator, succeeded)
    }
}

/// One bounded, versioned Catalog payload for task recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTaskRecord(Vec<u8>);

impl MaintenanceTaskRecord {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the immutable Catalog object that a task-control transaction
    /// publishes alongside its handler checkpoint or terminal outcome.
    pub fn catalog_object(&self) -> Result<CatalogObject, MaintenanceFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.0.len())
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        bytes.extend_from_slice(&self.0);
        CatalogObject::new(bytes).map_err(|_| MaintenanceFailure::CapacityExceeded)
    }
}

impl MaintenanceTaskStatus {
    #[must_use]
    pub fn task(&self) -> &MaintenanceTask {
        &self.task
    }
    #[must_use]
    pub const fn phase(&self) -> MaintenanceTaskPhase {
        self.phase
    }
    /// The bounded durable reason for a failed task. Nonterminal and
    /// successful tasks have no failure cause.
    #[must_use]
    pub const fn terminal_failure(&self) -> Option<MaintenanceTerminalFailure> {
        self.terminal_failure
    }
    #[must_use]
    pub const fn submitted_at(&self) -> u64 {
        self.submitted_at
    }
    #[must_use]
    pub fn checkpoint(&self) -> Option<&MaintenanceCheckpoint> {
        self.checkpoint.as_ref()
    }
    /// The server lifecycle instant of the durable Running transition or the
    /// most recent checkpoint that advanced actual task progress.
    #[must_use]
    pub const fn last_progress_at(&self) -> Option<u64> {
        self.last_progress_at
    }
    /// `Some` only when a running task has a trusted lifecycle-clock age.
    /// `None` deliberately represents an unknown deadline evaluation.
    #[must_use]
    pub const fn no_durable_progress_slo_breached(&self) -> Option<bool> {
        self.no_durable_progress_slo_breached
    }
    #[must_use]
    pub const fn pause_until(&self) -> Option<u64> {
        self.pause_until
    }
    #[must_use]
    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }
    /// Identifies the running task that currently blocks this task through
    /// the coordinator conflict graph, without exposing object identities.
    #[must_use]
    pub const fn conflict_owner(&self) -> Option<MaintenanceTaskId> {
        self.conflict_owner
    }
    /// True when the coordinator's exact scheduler predicate refuses this
    /// queued task while the lifecycle clock is uncertain.
    #[must_use]
    pub const fn clock_uncertain_blocked(&self) -> bool {
        self.clock_uncertain_blocked
    }
}

fn maintenance_task_status(
    state: &CoordinatorState,
    identity: MaintenanceTaskId,
    task: &TaskState,
    clock_uncertain: bool,
    now: Option<u64>,
) -> MaintenanceTaskStatus {
    let conflict_owner = (task.phase == MaintenanceTaskPhase::Queued)
        .then(|| {
            state
                .tasks
                .iter()
                .find(|(candidate, active)| {
                    **candidate != identity
                        && active.phase == MaintenanceTaskPhase::Running
                        && scheduling::tasks_conflict(&task.task, &active.task)
                })
                .map(|(candidate, _)| *candidate)
        })
        .flatten();
    MaintenanceTaskStatus {
        task: task.task.clone(),
        phase: task.phase,
        terminal_failure: task.terminal_failure,
        submitted_at: task.submitted_at,
        checkpoint: task.checkpoint.clone(),
        last_progress_at: task.last_progress_at,
        no_durable_progress_slo_breached: progress_slo_breached(task, now, clock_uncertain),
        pause_until: task.pause_until,
        cancellation_requested: task.cancellation_requested,
        conflict_owner,
        clock_uncertain_blocked: scheduling::clock_uncertain_blocks(
            state,
            identity,
            task,
            clock_uncertain,
        ),
    }
}

fn progress_slo_breached(
    task: &TaskState,
    now: Option<u64>,
    clock_uncertain: bool,
) -> Option<bool> {
    if task.phase != MaintenanceTaskPhase::Running || clock_uncertain {
        return None;
    }
    let age = now?.checked_sub(task.last_progress_at?)?;
    Some(age >= NO_DURABLE_PROGRESS_SLO_SECONDS)
}

fn checkpoint_advances(
    previous: Option<&MaintenanceCheckpoint>,
    candidate: &MaintenanceCheckpoint,
) -> bool {
    candidate.completed_inputs > previous.map_or(0, |current| current.completed_inputs)
}

impl MaintenanceCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CoordinatorState {
                tasks: BTreeMap::new(),
                pending_submissions: BTreeSet::new(),
                pending_terminal_reclamations: BTreeSet::new(),
                pending_task_transitions: BTreeSet::new(),
                window: None,
                clock_uncertain_durable_eligibility: BTreeSet::new(),
                fairness: BTreeMap::new(),
                next_terminal_order: 1,
            }),
            coordinator_id: NEXT_COORDINATOR_ID.fetch_add(1, Ordering::Relaxed),
            live_executions: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Attaches a retry with the same stable identity to its existing work.
    pub fn submit(&self, task: MaintenanceTask) -> Result<MaintenanceTask, MaintenanceFailure> {
        self.submit_at(task, 0)
    }

    /// Marks a compaction task as emergency work only after the sole Resource
    /// Governor has observed hard disk pressure. External callers cannot turn
    /// an ordinary event into Recovery Reserve work by selecting a priority.
    pub fn submit_emergency_compaction(
        &self,
        authority: &StorageKernelResourceAuthority,
        mut task: MaintenanceTask,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        if task.class != MaintenanceTaskClass::Compaction
            || task.trigger != MaintenanceTrigger::Event
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let pressure = authority
            .governor()
            .inspect()
            .map_err(|_| MaintenanceFailure::ResourceAdmissionRefused)?
            .disk_pressure();
        if pressure != DiskPressureState::HardPressure {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        task.emergency_compaction = true;
        self.submit(task)
    }

    /// Registers task work at a monotonic scheduler instant. Queue storage is
    /// bounded and retrying the same contract returns its original identity.
    pub fn submit_at(
        &self,
        task: MaintenanceTask,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if let Some(existing) = state.tasks.get(&task.identity) {
            if existing.task != task {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            return Ok(existing.task.clone());
        }
        if state
            .tasks
            .len()
            .checked_add(state.pending_submissions.len())
            .ok_or(MaintenanceFailure::CapacityExceeded)?
            >= MAX_MAINTENANCE_TASKS
            && reclaim_terminal_slot(&mut state)?.is_none()
        {
            return Err(MaintenanceFailure::CapacityExceeded);
        }
        state.tasks.insert(
            task.identity,
            TaskState {
                task: task.clone(),
                phase: MaintenanceTaskPhase::Queued,
                terminal_failure: None,
                submitted_at: now,
                checkpoint: None,
                last_progress_at: None,
                pause_until: None,
                cancellation_requested: false,
                dispatches: 0,
                terminal_order: None,
                active_dispatch: None,
            },
        );
        Ok(task)
    }

    /// Defers only declared optional work for a finite Lifecycle Clock interval.
    /// Required work and event-driven emergency compaction stay schedulable.
    #[cfg(any(test, fuzzing))]
    pub fn set_window(
        &self,
        deferred: impl IntoIterator<Item = MaintenanceTaskClass>,
        until: u64,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        if until <= now {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut classes = BTreeSet::new();
        for class in deferred {
            if !class.deferrable() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            classes.insert(class);
        }
        state.window = Some(MaintenanceWindow {
            deferred: classes,
            until,
        });
        Ok(())
    }

    /// Pauses one optional task until a finite monotonic deadline.
    #[cfg(any(test, fuzzing))]
    pub fn pause(
        &self,
        identity: MaintenanceTaskId,
        resource_generation: u64,
        until: u64,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        if until <= now {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if !task.task.is_pause_deferrable()
            || task.task.preconditions.resource_generation != resource_generation
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        if !matches!(
            task.phase,
            MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Deferred
        ) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Deferred;
        task.pause_until = Some(until);
        Ok(())
    }

    #[cfg(any(test, fuzzing))]
    pub fn resume(&self, identity: MaintenanceTaskId) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Deferred {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Queued;
        task.pause_until = None;
        Ok(())
    }

    /// Requests cooperative cancellation. A running handler observes this at
    /// its existing safe checkpoint; no output is made current by cancellation.
    #[cfg(any(test, fuzzing))]
    pub fn cancel(&self, identity: MaintenanceTaskId) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, identity)?;
        let terminal = {
            let task = state
                .tasks
                .get_mut(&identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if retains_until_completion(&task.task) {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            match task.phase {
                MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Deferred => {
                    task.phase = MaintenanceTaskPhase::Cancelled;
                    true
                },
                MaintenanceTaskPhase::Running => {
                    task.cancellation_requested = true;
                    false
                },
                MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed => false,
            }
        };
        if terminal {
            assign_terminal_order(&mut state, identity)?;
        }
        Ok(())
    }

    /// Test and fuzz-only scheduling without a live Resource Governor. Product
    /// dispatches use `start_next_with_reservation` so admission precedes the
    /// Running transition.
    #[cfg(any(test, fuzzing))]
    fn start_next(
        &self,
        now: u64,
        clock_uncertain: bool,
    ) -> Result<Option<MaintenanceTask>, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let Some(identity) = eligible_task_ids(&mut state, now, clock_uncertain, &BTreeMap::new())?
            .first()
            .copied()
        else {
            return Ok(None);
        };
        let task = state
            .tasks
            .get(&identity)
            .map(|stored| stored.task.clone())
            .ok_or(MaintenanceFailure::UnknownTask)?;
        dispatch_task(
            &mut state,
            self.coordinator_id,
            identity,
            now,
            clock_uncertain,
        )?;
        Ok(Some(task))
    }

    /// Selects and reserves one task in one operation. A refusal returns the
    /// task to the bounded queue, preserving its identity and checkpoint for a
    /// later wakeup instead of creating a retry loop or a second scheduler.
    #[cfg(any(test, fuzzing))]
    pub fn start_next_with_reservation<'authority>(
        &self,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let candidates = eligible_task_ids(&mut state, now, clock_uncertain, &BTreeMap::new())?;
        if candidates.is_empty() {
            return Ok(None);
        }
        for identity in candidates {
            let task = state
                .tasks
                .get(&identity)
                .map(|stored| stored.task.clone())
                .ok_or(MaintenanceFailure::UnknownTask)?;
            let reservation = match reserve_task(authority, &task) {
                Ok(reservation) => reservation,
                Err(()) => continue,
            };
            let dispatch = dispatch_task(
                &mut state,
                self.coordinator_id,
                identity,
                now,
                clock_uncertain,
            )?;
            self.live_executions.fetch_add(1, Ordering::AcqRel);
            return Ok(Some(MaintenanceExecution {
                task,
                checkpoint: state
                    .tasks
                    .get(&identity)
                    .and_then(|stored| stored.checkpoint.clone()),
                reservation,
                dispatch,
                live_executions: Arc::clone(&self.live_executions),
                tracked_live: true,
            }));
        }
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    }

    #[cfg(test)]
    pub fn checkpoint(
        &self,
        identity: MaintenanceTaskId,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        self.checkpoint_at_inner(identity, checkpoint, None)
    }

    /// Test and fuzz seam for the same server-time checkpoint transition that
    /// production commits through the Catalog writer.
    #[cfg(any(test, fuzzing))]
    pub fn checkpoint_at(
        &self,
        identity: MaintenanceTaskId,
        checkpoint: MaintenanceCheckpoint,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        self.checkpoint_at_inner(identity, checkpoint, Some(now))
    }

    #[cfg(any(test, fuzzing))]
    fn checkpoint_at_inner(
        &self,
        identity: MaintenanceTaskId,
        checkpoint: MaintenanceCheckpoint,
        progress_at: Option<u64>,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, identity)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || task.task.class == MaintenanceTaskClass::RetentionPublication
            || (task.task.class != MaintenanceTaskClass::IntegrityScrub
                && checkpoint.completed_inputs as usize > task.task.inputs.len())
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        if task
            .checkpoint
            .as_ref()
            .is_some_and(|previous| previous.sequence >= checkpoint.sequence)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        if checkpoint_advances(task.checkpoint.as_ref(), &checkpoint) {
            task.last_progress_at = progress_at;
        }
        task.checkpoint = Some(checkpoint);
        Ok(())
    }

    #[cfg(test)]
    pub fn complete(
        &self,
        identity: MaintenanceTaskId,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, identity)?;
        {
            let task = state
                .tasks
                .get_mut(&identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if task.phase != MaintenanceTaskPhase::Running {
                return Err(MaintenanceFailure::InvalidTransition);
            }
            let (phase, terminal_failure) = if task.cancellation_requested {
                (MaintenanceTaskPhase::Cancelled, None)
            } else if succeeded {
                (MaintenanceTaskPhase::Succeeded, None)
            } else {
                (
                    MaintenanceTaskPhase::Failed,
                    Some(MaintenanceTerminalFailure::Unclassified),
                )
            };
            task.phase = phase;
            task.terminal_failure = terminal_failure;
        }
        assign_terminal_order(&mut state, identity)?;
        Ok(())
    }

    /// Crash recovery releases ephemeral reservations and makes any nonterminal
    /// checkpointed task eligible to resume through its same stable identity.
    #[cfg(any(test, fuzzing))]
    pub fn recover_after_crash(&self) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut terminal = Vec::new();
        for (identity, task) in &mut state.tasks {
            if task.phase == MaintenanceTaskPhase::Running {
                task.active_dispatch = None;
                task.last_progress_at = None;
                task.phase = if task.cancellation_requested {
                    MaintenanceTaskPhase::Cancelled
                } else {
                    MaintenanceTaskPhase::Queued
                };
                if task.phase == MaintenanceTaskPhase::Cancelled {
                    terminal.push(*identity);
                }
            }
        }
        for identity in terminal {
            assign_terminal_order(&mut state, identity)?;
        }
        state.pending_submissions.clear();
        state.pending_terminal_reclamations.clear();
        state.pending_task_transitions.clear();
        Ok(())
    }

    pub fn status(
        &self,
        identity: MaintenanceTaskId,
    ) -> Result<MaintenanceTaskStatus, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        Ok(maintenance_task_status(&state, identity, task, false, None))
    }

    /// Returns one status with the same ClockUncertain scheduling predicate
    /// used by dispatch. Inspection does not sample uncertain lifecycle time.
    pub fn status_with_clock_uncertainty(
        &self,
        identity: MaintenanceTaskId,
        clock_uncertain: bool,
    ) -> Result<MaintenanceTaskStatus, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        Ok(maintenance_task_status(
            &state,
            identity,
            task,
            clock_uncertain,
            None,
        ))
    }

    /// Returns one task's deadline fact using server-authenticated lifecycle
    /// time. A `ClockUncertain` server must report an unknown fact rather than
    /// inventing an age or a healthy result.
    pub fn status_with_progress_slo(
        &self,
        identity: MaintenanceTaskId,
        now: Option<u64>,
        clock_uncertain: bool,
    ) -> Result<MaintenanceTaskStatus, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        Ok(maintenance_task_status(
            &state,
            identity,
            task,
            clock_uncertain,
            now,
        ))
    }

    /// Returns the server-derived expiry of the finite durable window that is
    /// currently deferring one queued task. The coordinator remains the sole
    /// authority for both this inspection result and scheduling eligibility.
    pub fn window_blocking_until(
        &self,
        identity: MaintenanceTaskId,
        now: u64,
    ) -> Result<Option<u64>, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        let Some(window) = state.window.as_ref() else {
            return Ok(None);
        };
        Ok((task.phase == MaintenanceTaskPhase::Queued
            && window.until > now
            && window.deferred.contains(&task.task.class)
            && task
                .task
                .class
                .is_window_deferrable(task.task.emergency_compaction))
        .then_some(window.until))
    }

    /// Returns the finite window currently applicable to a nonterminal task,
    /// even when a task-specific pause is its immediate scheduler blocker.
    /// This permits an authenticated status to report the later execution
    /// boundary when both deferrals overlap.
    pub fn active_window_until(
        &self,
        identity: MaintenanceTaskId,
        now: u64,
    ) -> Result<Option<u64>, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        let Some(window) = state.window.as_ref() else {
            return Ok(None);
        };
        Ok((matches!(
            task.phase,
            MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Deferred
        ) && window.until > now
            && window.deferred.contains(&task.task.class)
            && task
                .task
                .class
                .is_window_deferrable(task.task.emergency_compaction))
        .then_some(window.until))
    }

    /// Returns the complete bounded task view for authenticated administration
    /// and diagnostics. The coordinator remains the only owner of task state.
    pub fn statuses(&self) -> Result<Vec<MaintenanceTaskStatus>, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        Ok(state
            .tasks
            .iter()
            .map(|(identity, task)| maintenance_task_status(&state, *identity, task, false, None))
            .collect())
    }

    /// Returns the bounded task registry with the exact ClockUncertain
    /// scheduler blocker rendered for authenticated inspection.
    pub fn statuses_with_clock_uncertainty(
        &self,
        clock_uncertain: bool,
    ) -> Result<Vec<MaintenanceTaskStatus>, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        Ok(state
            .tasks
            .iter()
            .map(|(identity, task)| {
                maintenance_task_status(&state, *identity, task, clock_uncertain, None)
            })
            .collect())
    }

    /// Bounded coordinator inspection with one server lifecycle instant for
    /// every running no-progress deadline fact.
    pub fn statuses_with_progress_slo(
        &self,
        now: Option<u64>,
        clock_uncertain: bool,
    ) -> Result<Vec<MaintenanceTaskStatus>, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        Ok(state
            .tasks
            .iter()
            .map(|(identity, task)| {
                maintenance_task_status(&state, *identity, task, clock_uncertain, now)
            })
            .collect())
    }

    pub fn durable_records(&self) -> Result<Vec<MaintenanceTaskRecord>, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state.tasks.values().map(encode_record).collect()
    }

    /// Reports whether a nonterminal retention task already owns a segment
    /// scope. Runtime discovery uses this bounded coordinator view to avoid
    /// preparing a second descriptor while the durable first attempt or its
    /// Reclamation successor remains authoritative.
    pub fn has_nonterminal_retention_task_for_scope(
        &self,
        scope: MaintenanceScope,
    ) -> Result<bool, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        Ok(state.tasks.values().any(|task| {
            task.task.scope == scope
                && matches!(
                    task.task.class,
                    MaintenanceTaskClass::RetentionPublication
                        | MaintenanceTaskClass::RetentionReclamation
                )
                && !matches!(
                    task.phase,
                    MaintenanceTaskPhase::Cancelled
                        | MaintenanceTaskPhase::Succeeded
                        | MaintenanceTaskPhase::Failed
                )
        }))
    }

    /// Reports whether the exact maintenance class already owns a scope.
    /// Discovery uses this to make periodic submissions idempotent across
    /// worker wakeups and process recovery.
    pub fn has_nonterminal_task_for_scope(
        &self,
        class: MaintenanceTaskClass,
        scope: MaintenanceScope,
    ) -> Result<bool, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        Ok(state.tasks.values().any(|task| {
            task.task.scope == scope
                && task.task.class == class
                && !matches!(
                    task.phase,
                    MaintenanceTaskPhase::Cancelled
                        | MaintenanceTaskPhase::Succeeded
                        | MaintenanceTaskPhase::Failed
                )
        }))
    }

    pub fn restore(
        records: impl IntoIterator<Item = MaintenanceTaskRecord>,
    ) -> Result<Self, MaintenanceFailure> {
        let coordinator = Self::new();
        for record in records {
            let mut state = decode_record(record.as_bytes())?;
            validate_retention_publication_state(&state)?;
            validate_retention_reclamation_state(&state)?;
            if state.phase == MaintenanceTaskPhase::Running {
                state.phase = if state.cancellation_requested {
                    MaintenanceTaskPhase::Cancelled
                } else {
                    MaintenanceTaskPhase::Queued
                };
                state.last_progress_at = None;
            }
            let mut inner = coordinator
                .state
                .lock()
                .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
            if inner.tasks.len() >= MAX_MAINTENANCE_TASKS
                || inner.tasks.insert(state.task.identity, state).is_some()
            {
                return Err(MaintenanceFailure::CapacityExceeded);
            }
        }
        Ok(coordinator)
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_maintenance_stateful(data: &[u8]) {
    if data.len() > 16_384 {
        return;
    }
    let _ = MaintenanceCoordinator::restore([MaintenanceTaskRecord(data.to_vec())]);
    let coordinator = MaintenanceCoordinator::new();
    let mut identity = [1_u8; 16];
    if let Some(value) = data.first() {
        identity[0] = (*value).max(1);
    }
    let Ok(identity) = MaintenanceTaskId::new(identity) else {
        return;
    };
    let class = match data.get(1).copied().unwrap_or_default() % 4 {
        0 => MaintenanceTaskClass::Compaction,
        1 => MaintenanceTaskClass::RetentionPublication,
        2 => MaintenanceTaskClass::SnapshotLeaseExpiry,
        _ => MaintenanceTaskClass::SchemaPromotion,
    };
    let task = MaintenanceTask::new(identity, class);
    let _ = coordinator.submit_at(task, u64::from(data.get(2).copied().unwrap_or_default()));
    let uncertain = data.get(3).is_some_and(|value| value & 1 == 1);
    let _ = coordinator.start_next(
        u64::from(data.get(4).copied().unwrap_or_default()),
        uncertain,
    );
    let _ = coordinator.cancel(identity);
    let _ = coordinator.recover_after_crash();
    let _ = coordinator.durable_records();
}

mod scheduling;

#[cfg(test)]
use scheduling::recovery_kind;
use scheduling::{
    assign_terminal_order, dispatch_task, eligible_task_ids, reclaim_terminal_slot, reserve_task,
    retains_until_completion,
};

impl Default for MaintenanceCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "maintenance/tests.rs"]
mod tests;
