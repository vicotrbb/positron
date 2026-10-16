//! Existing coordinator ownership fences new retained work during retirement.
use super::*;

pub struct RootRetirementReferenceGuard<'a> {
    _state: std::sync::MutexGuard<'a, CoordinatorState>,
    basis: crate::CatalogGenerationId,
    owned_task: Option<MaintenanceTaskId>,
    _session: &'a crate::RootRewrapSession<'a>,
}
impl MaintenanceCoordinator {
    pub fn guard_root_retirement_references<'a>(
        &'a self,
        session: &'a crate::RootRewrapSession<'a>,
        catalog: &crate::Catalog<'_>,
        basis: &crate::CatalogSnapshot,
    ) -> Result<RootRetirementReferenceGuard<'a>, MaintenanceFailure> {
        self.guard_root_retirement_inner(session, catalog, basis, None)
    }

    /// Only the exact admitted root-migration dispatch may prove its own
    /// reference-free association. Other opaque work retains its ordinary fence.
    pub fn guard_root_retirement_for_migration<'a>(
        &'a self,
        session: &'a crate::RootRewrapSession<'a>,
        catalog: &crate::Catalog<'_>,
        basis: &crate::CatalogSnapshot,
        execution: &MaintenanceExecution<'_>,
        binding: RootProviderMigrationBinding,
    ) -> Result<RootRetirementReferenceGuard<'a>, MaintenanceFailure> {
        if execution.dispatch.coordinator_id != self.coordinator_id
            || RootProviderMigrationBinding::from_execution(execution)? != binding
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        self.guard_root_retirement_inner(session, catalog, basis, Some((execution, binding)))
    }

    fn guard_root_retirement_inner<'a>(
        &'a self,
        session: &'a crate::RootRewrapSession<'a>,
        catalog: &crate::Catalog<'_>,
        basis: &crate::CatalogSnapshot,
        own: Option<(&MaintenanceExecution<'_>, RootProviderMigrationBinding)>,
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
            let owned = if let Some((execution, binding)) =
                own.filter(|(execution, _)| execution.task.identity == identity)
            {
                if current.phase != MaintenanceTaskPhase::Running
                    || current.active_dispatch != Some(execution.dispatch)
                    || root_provider_migration::RootProviderMigrationBinding::from_task(
                        &current.task,
                        current.checkpoint.as_ref(),
                    )? != binding
                {
                    return Err(MaintenanceFailure::PreconditionFailed);
                }
                true
            } else {
                false
            };
            if (!owned
                && !queued_digest_scrub_is_reference_free(current)
                && (current.task.class == MaintenanceTaskClass::Migration
                    || durable_task_retains_unproved_root_reference(bytes)?))
                || !matches_root_retirement_record(current, bytes)?
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
            basis: basis.identity(),
            owned_task: own.map(|(execution, _)| execution.task.identity),
            _state: state,
            _session: session,
        })
    }
}

impl RootRetirementReferenceGuard<'_> {
    pub(crate) fn proves_reference_free_record(
        &self,
        authority: &crate::StorageKernelResourceAuthority,
        basis: crate::CatalogGenerationId,
        bytes: &[u8],
    ) -> Result<bool, MaintenanceFailure> {
        if !std::ptr::eq(authority, self._session.resource_authority()) || basis != self.basis {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let Some(identity) = record::record_identity(bytes)? else {
            return Ok(false);
        };
        let current = self
            ._state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::PreconditionFailed)?;
        Ok(
            (self.owned_task == Some(identity) || queued_digest_scrub_is_reference_free(current))
                && matches_root_retirement_record(current, bytes)?,
        )
    }
}

fn queued_digest_scrub_is_reference_free(state: &TaskState) -> bool {
    state.phase == MaintenanceTaskPhase::Queued
        && state.active_dispatch.is_none()
        && canonical_digest_only_integrity_scrub(state)
}

fn matches_root_retirement_record(
    current: &TaskState,
    bytes: &[u8],
) -> Result<bool, MaintenanceFailure> {
    if queued_digest_scrub_is_reference_free(current) {
        persistence::matches_catalog_reclamation_predecessor(&decode_record(bytes)?, bytes, current)
    } else {
        Ok(encode_record(current)?.as_bytes() == bytes)
    }
}
