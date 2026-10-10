//! Existing coordinator ownership fences new retained work during retirement.
use super::*;

pub struct RootRetirementReferenceGuard<'a> {
    _state: std::sync::MutexGuard<'a, CoordinatorState>,
    _session: &'a crate::RootRewrapSession<'a>,
}
impl MaintenanceCoordinator {
    pub fn guard_root_retirement_references<'a>(
        &'a self,
        session: &'a crate::RootRewrapSession<'a>,
        catalog: &crate::Catalog<'_>,
        basis: &crate::CatalogSnapshot,
    ) -> Result<RootRetirementReferenceGuard<'a>, MaintenanceFailure> {
        if !std::ptr::eq(session.resource_authority(), catalog.resource_authority()) {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let state = self
            .state
            .try_lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if !state.pending_submissions.is_empty() || !state.pending_terminal_reclamations.is_empty()
        {
            return Err(MaintenanceFailure::ConcurrentAccess);
        }
        let mut count = 0_usize;
        for bytes in basis.plaintext_objects() {
            let Some(identity) = record::record_identity(bytes)? else {
                continue;
            };
            let current = state
                .tasks
                .get(&identity)
                .ok_or(MaintenanceFailure::PreconditionFailed)?;
            require_unreserved_task_transition(&state, identity)?;
            if durable_task_retains_unproved_root_reference(bytes)?
                || encode_record(current)?.as_bytes() != bytes
            {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            count = count
                .checked_add(1)
                .ok_or(MaintenanceFailure::CapacityExceeded)?;
        }
        if count != state.tasks.len() {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(RootRetirementReferenceGuard {
            _state: state,
            _session: session,
        })
    }
}
