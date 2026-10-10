//! Re-verification discards stale cursors through the same durable task owner.
use super::super::*;
use super::catalog::persist_task_state_from_snapshot;

impl MaintenanceCoordinator {
    /// Requeues this exact authenticated verifier contract; never publishes
    /// verification success. The unchanged basis is compared at publication.
    pub fn restart_envelope_verification_at_basis(
        &self,
        catalog: &crate::Catalog<'_>,
        basis: &crate::CatalogSnapshot,
        identity: MaintenanceTaskId,
        epoch: u64,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, identity)?;
        let current = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        let stale_failure = current.phase == MaintenanceTaskPhase::Failed
            && current.terminal_failure == Some(MaintenanceTerminalFailure::StaleGeneration);
        if current.task.class != MaintenanceTaskClass::EnvelopeVerification
            || current.task.reservations != crate::integrity_scrub_resource_claim()
            || current.task.trigger != MaintenanceTrigger::Event
            || current.task.preconditions.resource_generation != 1
            || !(matches!(
                current.phase,
                MaintenanceTaskPhase::Succeeded
                    | MaintenanceTaskPhase::Queued
                    | MaintenanceTaskPhase::Deferred
            ) || stale_failure)
            || current.active_dispatch.is_some()
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let tenant = current
            .task
            .scope
            .tenant_id()
            .ok_or(MaintenanceFailure::InvalidInput)?;
        if current.task.scope != MaintenanceScope::tenant(tenant) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let reservation = scheduling::reserve_task(catalog.resource_authority(), &current.task)
            .map_err(|_| MaintenanceFailure::ResourceAdmissionRefused)?;
        // Verifies the exact immutable contract in its durable owner before
        // parsing or copying checkpoint state under the existing full grant.
        basis
            .envelope_verification_source_identity(catalog.instance(), &current.task)
            .map_err(|_| MaintenanceFailure::PreconditionFailed)?;
        if let Some(checkpoint) = current.checkpoint.as_ref() {
            let progress = EnvelopeVerificationCheckpoint::from_checkpoint(
                checkpoint,
                catalog.instance(),
                tenant,
                epoch,
            )?;
            if (current.phase == MaintenanceTaskPhase::Succeeded) != progress.is_complete() {
                return Err(MaintenanceFailure::InvalidInput);
            }
        } else if current.phase != MaintenanceTaskPhase::Queued {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut next = current.clone();
        next.phase = MaintenanceTaskPhase::Queued;
        next.checkpoint = None;
        next.terminal_failure = None;
        next.terminal_order = None;
        next.last_progress_at = None;
        next.pause_until = None;
        next.cancellation_requested = false;
        persist_task_state_from_snapshot(catalog, &next, None, Some(&reservation), None, basis)?;
        let current = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        *current = next;
        Ok(())
    }
}
