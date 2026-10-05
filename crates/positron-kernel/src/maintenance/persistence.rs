//! Catalog-backed maintenance task records.
//!
//! The coordinator owns task state while the Catalog Writer remains the sole
//! durable publication authority. Each transition first replaces the one
//! task's record in a complete Catalog proposal, then makes the corresponding
//! in-memory transition visible. An acknowledgement-ambiguous commit is safe
//! to retry because the exact replacement record is content-addressed.

use std::collections::{BTreeMap, BTreeSet};

use super::scheduling::{
    reclaimable_terminal_identity, remove_task_and_clear_empty_scope, snapshot_lease_time_for_task,
};
use super::*;
use crate::Catalog;

pub(crate) fn retention_publication_record_bytes_bound() -> Result<usize, MaintenanceFailure> {
    record::encoded_record_capacity(MAX_TASK_OBJECTS, MAX_TASK_OBJECTS, MAX_CHECKPOINT_BYTES)
}

mod catalog;
mod completions;
mod execution;
mod lifecycle;
mod transitions;

use catalog::*;
use transitions::matches_catalog_reclamation_predecessor;
pub(crate) use transitions::{
    CompactionTaskReplacement, QueuedMaintenanceSubmission, RetentionPublicationTaskCompletion,
    RetentionReclamationTaskReplacement, SnapshotLeaseExpiryTaskReplacement,
};

struct SchedulerSelection<'times> {
    requested_identity: Option<MaintenanceTaskId>,
    snapshot_lease_times: &'times BTreeMap<MaintenanceScope, u64>,
}

impl MaintenanceCoordinator {
    /// Selects, reserves, and durably marks one task Running before handing its
    /// execution to a handler. A failed publication drops the fresh reservation
    /// and leaves the task queued for the same stable retry.
    pub fn start_next_with_reservation_and_persist<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        self.start_next_with_reservation_and_persist_for_class(
            catalog,
            authority,
            now,
            clock_uncertain,
            None,
        )
    }

    /// Selects only work owned by one installed runtime handler. Unsupported
    /// task classes remain queued for their own handler instead of being
    /// dispatched into a worker that cannot truthfully terminalize them.
    pub fn start_next_with_reservation_and_persist_for_class<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        class: Option<MaintenanceTaskClass>,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        let classes = class.as_slice();
        self.start_next_with_reservation_and_persist_for_classes(
            catalog,
            authority,
            now,
            clock_uncertain,
            classes,
        )
    }

    /// Selects only work owned by the installed runtime handler set. Candidate
    /// ordering remains the coordinator's ordinary priority and fairness order;
    /// an unsupported class stays Queued for a future handler.
    pub fn start_next_with_reservation_and_persist_for_classes<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        classes: &[MaintenanceTaskClass],
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        self.start_next_with_reservation_and_persist_matching(
            catalog,
            authority,
            now,
            clock_uncertain,
            classes,
            None,
        )
    }

    /// Selects installed work with Snapshot Lease expiry eligibility evaluated
    /// in the same segment lifecycle-time domain that created each lease.
    /// The coordinator still owns candidate ordering, resource admission, and
    /// the durable Running transition; the caller supplies only authoritative
    /// scope observations for the already-typed lease task class.
    pub fn start_next_with_reservation_and_persist_for_classes_with_snapshot_lease_times<
        'authority,
    >(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        classes: &[MaintenanceTaskClass],
        snapshot_lease_times: &BTreeMap<MaintenanceScope, u64>,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        self.start_next_with_reservation_and_persist_matching_with_snapshot_lease_times(
            catalog,
            authority,
            now,
            clock_uncertain,
            classes,
            SchedulerSelection {
                requested_identity: None,
                snapshot_lease_times,
            },
        )
    }

    /// Starts one exact admitted task without allowing another task of the
    /// same class to consume an attach caller's result path.
    pub fn start_task_with_reservation_and_persist<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        identity: MaintenanceTaskId,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        self.start_next_with_reservation_and_persist_matching(
            catalog,
            authority,
            now,
            clock_uncertain,
            &[MaintenanceTaskClass::GovernanceAuditCheckpoint],
            Some(identity),
        )
    }

    /// Starts one exact durable Compaction descriptor. Other task classes
    /// cannot enter this handler path.
    pub fn start_compaction_task_with_reservation_and_persist<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        identity: MaintenanceTaskId,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        self.start_next_with_reservation_and_persist_matching(
            catalog,
            authority,
            now,
            clock_uncertain,
            &[MaintenanceTaskClass::Compaction],
            Some(identity),
        )
    }

    /// Starts the one exact authenticated integrity task selected by an
    /// operator request. The task still takes the coordinator's durable
    /// admission and Resource Governor reservation before any scan begins.
    pub fn start_integrity_scrub_task_with_reservation_and_persist<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        identity: MaintenanceTaskId,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        self.start_next_with_reservation_and_persist_matching(
            catalog,
            authority,
            now,
            clock_uncertain,
            &[MaintenanceTaskClass::IntegrityScrub],
            Some(identity),
        )
    }

    fn start_next_with_reservation_and_persist_matching<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        classes: &[MaintenanceTaskClass],
        requested_identity: Option<MaintenanceTaskId>,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        self.start_next_with_reservation_and_persist_matching_with_snapshot_lease_times(
            catalog,
            authority,
            now,
            clock_uncertain,
            classes,
            SchedulerSelection {
                requested_identity,
                snapshot_lease_times: &BTreeMap::new(),
            },
        )
    }

    fn start_next_with_reservation_and_persist_matching_with_snapshot_lease_times<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
        classes: &[MaintenanceTaskClass],
        selection: SchedulerSelection<'_>,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut prospective = state.clone();
        let candidates = eligible_task_ids(
            &mut prospective,
            now,
            clock_uncertain,
            selection.snapshot_lease_times,
        )?;
        if candidates.is_empty() {
            return Ok(None);
        }
        for identity in candidates {
            if selection
                .requested_identity
                .is_some_and(|requested| requested != identity)
            {
                continue;
            }
            let task = prospective
                .tasks
                .get(&identity)
                .map(|stored| stored.task.clone())
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if !classes.is_empty() && !classes.contains(&task.class()) {
                continue;
            }
            let reservation = match reserve_task(authority, &task) {
                Ok(reservation) => reservation,
                Err(()) => continue,
            };
            let dispatch = dispatch_task(
                &mut prospective,
                self.coordinator_id,
                identity,
                snapshot_lease_time_for_task(&task, now, selection.snapshot_lease_times),
                clock_uncertain,
            )?;
            let updated = prospective
                .tasks
                .get(&identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            let mut pending_execution = MaintenanceExecution {
                task: task.clone(),
                checkpoint: updated.checkpoint.clone(),
                reservation,
                dispatch,
                live_executions: Arc::clone(&self.live_executions),
                tracked_live: false,
            };
            if task.class == MaintenanceTaskClass::GovernanceAuditCheckpoint {
                persist_task_state_admitted(catalog, updated, None, &pending_execution)?;
            } else {
                persist_task_state(catalog, updated, None)?;
            }
            let updated = updated.clone();
            state.tasks.insert(identity, updated);
            state.fairness = prospective.fairness;
            self.live_executions.fetch_add(1, Ordering::AcqRel);
            pending_execution.tracked_live = true;
            return Ok(Some(pending_execution));
        }
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    }

    /// Submits a task only after its queued state is durably reachable through
    /// the current Catalog generation. Retrying the same stable task identity
    /// attaches to the already published record.
    pub fn submit_and_persist(
        &self,
        catalog: &Catalog<'_>,
        task: MaintenanceTask,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        if matches!(
            task.class,
            MaintenanceTaskClass::Compaction
                | MaintenanceTaskClass::RetentionPublication
                | MaintenanceTaskClass::RetentionReclamation
        ) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        self.submit_task_and_persist(catalog, task, None, now, None)
    }

    pub(crate) fn submit_retention_publication_and_persist(
        &self,
        catalog: &Catalog<'_>,
        task: MaintenanceTask,
        checkpoint: MaintenanceCheckpoint,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        if task.class != MaintenanceTaskClass::RetentionPublication {
            return Err(MaintenanceFailure::InvalidInput);
        }
        super::retention_publication_frontier(Some(&checkpoint))?;
        self.submit_task_and_persist(catalog, task, Some(checkpoint), now, None)
    }

    /// Persists Compaction only with its immutable source and policy proof.
    /// Generic task ingress cannot manufacture or later overwrite this proof.
    pub fn submit_compaction_and_persist(
        &self,
        catalog: &Catalog<'_>,
        task: MaintenanceTask,
        binding: crate::CompactionBinding,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        if task.class != MaintenanceTaskClass::Compaction
            || task.scope != binding.scope()
            || task.inputs.is_empty()
            || !task.outputs.is_empty()
            || task.preconditions.resource_generation != 1
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        self.submit_task_and_persist(catalog, task, Some(binding.checkpoint()?), now, None)
    }

    /// Persists a Compaction descriptor jointly with its immutable Run audit
    /// receipt. A failed Catalog publication leaves neither visible.
    pub fn submit_compaction_and_persist_audited(
        &self,
        catalog: &Catalog<'_>,
        task: MaintenanceTask,
        binding: crate::CompactionBinding,
        now: u64,
        audit: crate::AuditIntent,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        if task.class != MaintenanceTaskClass::Compaction
            || task.scope != binding.scope()
            || task.inputs.is_empty()
            || !task.outputs.is_empty()
            || task.preconditions.resource_generation != 1
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        self.submit_task_and_persist(catalog, task, Some(binding.checkpoint()?), now, Some(audit))
    }

    /// Persists the immutable binding for one system-scoped Governance Audit
    /// checkpoint before the coordinator may admit it for signing.
    pub fn submit_governance_audit_checkpoint_and_persist(
        &self,
        catalog: &Catalog<'_>,
        task: MaintenanceTask,
        binding: GovernanceAuditCheckpointBinding,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        let record = MaintenanceObjectId::new(binding.record_hash())?;
        let fingerprint = MaintenanceObjectId::new(binding.integrity_key_fingerprint())?;
        if task.class != MaintenanceTaskClass::GovernanceAuditCheckpoint
            || task.scope != MaintenanceScope::System
            || task.inputs.as_slice() != [record]
            || task.outputs.as_slice() != [fingerprint]
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        self.submit_task_and_persist(catalog, task, Some(binding.checkpoint()?), now, None)
    }

    fn submit_task_and_persist(
        &self,
        catalog: &Catalog<'_>,
        task: MaintenanceTask,
        checkpoint: Option<MaintenanceCheckpoint>,
        now: u64,
        audit: Option<crate::AuditIntent>,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if let Some(existing) = state.tasks.get(&task.identity) {
            if existing.task != task || existing.checkpoint != checkpoint {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            return Ok(existing.task.clone());
        }

        let occupied = state
            .tasks
            .len()
            .checked_add(state.pending_submissions.len())
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let removed = if occupied >= MAX_MAINTENANCE_TASKS {
            Some(
                reclaimable_terminal_identity(&state)
                    .ok_or(MaintenanceFailure::CapacityExceeded)?,
            )
        } else {
            None
        };
        let task_state = TaskState {
            task: task.clone(),
            phase: MaintenanceTaskPhase::Queued,
            terminal_failure: None,
            submitted_at: now,
            checkpoint,
            last_progress_at: None,
            pause_until: None,
            cancellation_requested: false,
            dispatches: 0,
            terminal_order: None,
            active_dispatch: None,
        };
        if let Some(audit) = audit {
            persist_task_state_audited(catalog, &task_state, removed, audit)?;
        } else {
            persist_task_state(catalog, &task_state, removed)?;
        }
        if let Some(identity) = removed {
            remove_task_and_clear_empty_scope(&mut state, identity)?;
        }
        state.tasks.insert(task.identity, task_state);
        Ok(task)
    }

    /// Publishes a finite pause before exposing it to the scheduler.
    pub fn pause_and_persist(
        &self,
        catalog: &Catalog<'_>,
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
        let mut next = state.clone();
        let task = next
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
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }

    /// Publishes an operator-attributed finite pause jointly with its task
    /// state. The caller supplies only an already-validated audit intent.
    pub fn pause_and_persist_audited(
        &self,
        catalog: &Catalog<'_>,
        identity: MaintenanceTaskId,
        resource_generation: u64,
        until: u64,
        now: u64,
        audit: crate::AuditIntent,
    ) -> Result<(), MaintenanceFailure> {
        if until <= now {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        let task = next
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
        persist_task_state_audited(catalog, task, None, audit)?;
        *state = next;
        Ok(())
    }

    /// Removes a durable pause before returning the task to the queue.
    pub fn resume_and_persist(
        &self,
        catalog: &Catalog<'_>,
        identity: MaintenanceTaskId,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        let task = next
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Deferred {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Queued;
        task.pause_until = None;
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }

    /// Publishes an operator-attributed resume jointly with its task state.
    pub fn resume_and_persist_audited(
        &self,
        catalog: &Catalog<'_>,
        identity: MaintenanceTaskId,
        audit: crate::AuditIntent,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        let task = next
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Deferred {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Queued;
        task.pause_until = None;
        persist_task_state_audited(catalog, task, None, audit)?;
        *state = next;
        Ok(())
    }

    /// Durably requests cancellation before it is visible to the handler or
    /// scheduler. A protected durability completion remains non-cancellable.
    pub fn cancel_and_persist(
        &self,
        catalog: &Catalog<'_>,
        identity: MaintenanceTaskId,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        super::require_unreserved_task_transition(&state, identity)?;
        let running_publication = state.tasks.get(&identity).and_then(|task| {
            (task.task.class == MaintenanceTaskClass::RetentionPublication
                && task.phase == MaintenanceTaskPhase::Running)
                .then(|| task.clone())
        });
        if let Some(publication) = running_publication
            && durable_retention_publication_pair_exists(catalog, &publication)?
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let running_compaction = state.tasks.get(&identity).and_then(|task| {
            (task.task.class == MaintenanceTaskClass::Compaction
                && task.phase == MaintenanceTaskPhase::Running)
                .then(|| task.clone())
        });
        if let Some(compaction) = running_compaction
            && durable_compaction_completion_exists(
                catalog,
                &compaction,
                state.next_terminal_order,
            )?
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let mut next = state.clone();
        let terminal = {
            let task = next
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
            assign_terminal_order(&mut next, identity)?;
        }
        let task = next
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }

    /// Recovers the complete bounded task registry from authenticated Catalog
    /// objects. Running work never owns durable capacity after a process exit,
    /// so it is returned to its queued checkpoint before any handler resumes.
    pub fn restore_from_catalog(catalog: &Catalog<'_>) -> Result<Self, MaintenanceFailure> {
        let snapshot = catalog.pin().map_err(map_catalog_failure)?;
        let mut identities = BTreeSet::new();
        let mut records = Vec::new();
        let mut window = None;
        records
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        for bytes in snapshot.plaintext_objects() {
            if let Some(identity) = record::record_identity(bytes)? {
                if !identities.insert(identity) {
                    return Err(MaintenanceFailure::CatalogUnavailable);
                }
                records.push(MaintenanceTaskRecord(bytes.to_vec()));
                continue;
            }
            if let Some(candidate) = record::window_record(bytes)?
                && window.replace(candidate).is_some()
            {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
        }
        let coordinator = Self::restore(records)?;
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let verified_legacy = state
            .tasks
            .values()
            .filter(|reclamation| {
                reclamation.task.class == MaintenanceTaskClass::RetentionReclamation
                    && reclamation.task.trigger == MaintenanceTrigger::AgeDerived
                    && reclamation.phase == MaintenanceTaskPhase::Queued
            })
            .filter_map(|reclamation| {
                state
                    .tasks
                    .values()
                    .find(|publication| {
                        publication.task.class == MaintenanceTaskClass::RetentionPublication
                            && canonical_retention_publication_pair(
                                publication,
                                publication,
                                reclamation,
                            )
                            .unwrap_or(false)
                    })
                    .map(|publication| (publication, reclamation))
            })
            .try_fold(
                BTreeSet::new(),
                |mut verified, (publication, reclamation)| {
                    if crate::active_segment_ledger::reclamation_eligibility_is_durably_established(
                        &snapshot,
                        &publication.task,
                        &reclamation.task,
                        publication.checkpoint.as_ref(),
                    )
                    .map_err(|_| MaintenanceFailure::CatalogUnavailable)?
                    {
                        verified.insert(reclamation.task.identity);
                    }
                    Ok::<_, MaintenanceFailure>(verified)
                },
            )?;
        state.clock_uncertain_durable_eligibility = verified_legacy;
        state.window = window;
        drop(state);
        Ok(coordinator)
    }

    /// Initializes an otherwise empty coordinator from the authenticated
    /// Catalog source. Live dispatches and pending transitions remain owned by
    /// the current coordinator, so replacing either state would lose its
    /// authoritative reservation or completion handoff.
    pub fn replace_from_catalog(&self, catalog: &Catalog<'_>) -> Result<(), MaintenanceFailure> {
        let restored = Self::restore_from_catalog(catalog)?;
        let recovered = restored
            .state
            .into_inner()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if self.live_executions.load(Ordering::Acquire) != 0
            || !state.pending_submissions.is_empty()
            || !state.pending_terminal_reclamations.is_empty()
            || !state.pending_task_transitions.is_empty()
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        *state = recovered;
        Ok(())
    }

    /// Publishes the bounded, finite maintenance-window intent before it
    /// defers optional work.
    pub fn set_window_and_persist(
        &self,
        catalog: &Catalog<'_>,
        deferred: impl IntoIterator<Item = MaintenanceTaskClass>,
        until: u64,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        if until <= now {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut classes = BTreeSet::new();
        for class in deferred {
            if !class.deferrable() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            classes.insert(class);
        }
        let window = MaintenanceWindow {
            deferred: classes,
            until,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        persist_window(catalog, &window)?;
        state.window = Some(window);
        Ok(())
    }

    /// Publishes one operator-attributed finite window and its audit intent in
    /// the same Catalog generation. The Catalog generation precondition is
    /// evaluated by the commit path while the coordinator lock prevents the
    /// in-memory scheduler view from preceding durable publication.
    pub fn set_window_and_persist_audited(
        &self,
        catalog: &Catalog<'_>,
        deferred: impl IntoIterator<Item = MaintenanceTaskClass>,
        expected_catalog_generation: u64,
        until: u64,
        now: u64,
        audit: crate::AuditIntent,
    ) -> Result<u64, MaintenanceFailure> {
        if until <= now || expected_catalog_generation == 0 {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut classes = BTreeSet::new();
        for class in deferred {
            if !class.deferrable() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            classes.insert(class);
        }
        if classes.is_empty() {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let window = MaintenanceWindow {
            deferred: classes,
            until,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let generation =
            persist_window_audited(catalog, &window, expected_catalog_generation, audit)?;
        state.window = Some(window);
        Ok(generation)
    }
}
