//! Exact-basis completion of one admitted envelope-verification pass.
use super::super::*;
use super::catalog::persist_task_state_from_snapshot;

impl MaintenanceExecution<'_> {
    /// Atomically persists one bounded pass and releases its dispatch to the
    /// durable queue, or marks verification successful. Retirement is separate.
    pub(crate) fn checkpoint_envelope_verification_at_basis(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &crate::Catalog<'_>,
        basis: &crate::CatalogSnapshot,
        publication: super::envelope_traversal::EnvelopeVerificationPublication,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::EnvelopeVerification
            || self.dispatch.coordinator_id != coordinator.coordinator_id
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let tenant = self
            .task
            .scope
            .tenant_id()
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let progress = EnvelopeVerificationCheckpoint::from_checkpoint(
            &checkpoint,
            catalog.instance(),
            tenant,
            publication.epoch,
        )?;
        if progress.source_identity()
            != basis
                .envelope_verification_source_identity(catalog.instance(), &self.task)
                .map_err(|_| MaintenanceFailure::PreconditionFailed)?
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, self.dispatch.identity)?;
        let current = state
            .tasks
            .get(&self.dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if current.task != self.task
            || current.phase != MaintenanceTaskPhase::Running
            || current.active_dispatch != Some(self.dispatch)
            || current.cancellation_requested
            || current
                .checkpoint
                .as_ref()
                .is_some_and(|previous| previous.sequence >= checkpoint.sequence)
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut next = state.clone();
        let task = next
            .tasks
            .get_mut(&self.dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        task.checkpoint = Some(checkpoint);
        task.active_dispatch = None;
        task.last_progress_at = None;
        if progress.is_complete() {
            task.phase = MaintenanceTaskPhase::Succeeded;
            assign_terminal_order(&mut next, self.dispatch.identity)?;
        } else {
            task.phase = MaintenanceTaskPhase::Queued;
        }
        let task = next
            .tasks
            .get(&self.dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        let audit = if progress.is_complete() {
            publication.audit
        } else {
            None
        };
        persist_task_state_from_snapshot(
            catalog,
            task,
            None,
            Some(self.reservation()),
            audit,
            basis,
        )?;
        *state = next;
        Ok(())
    }
}
