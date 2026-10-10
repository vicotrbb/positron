//! Single-use consumption in a caller-owned, audited Catalog transaction.
use super::super::*;
use super::catalog::map_catalog_failure;

impl MaintenanceCoordinator {
    /// Consumes the exact completed verifier while publishing its owner's
    /// proposal. This coordinates task state; the caller still owns retirement
    /// authorization, reference admission and the canonical envelope change.
    pub fn consume_envelope_verification_with_catalog_proposal(
        &self,
        catalog: &crate::Catalog<'_>,
        basis: &crate::CatalogSnapshot,
        tenant: positron_domain::identity::TenantId,
        epoch: u64,
        proposal: crate::CatalogProposal,
        audit: crate::AuditIntent,
    ) -> Result<crate::CatalogCommit, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut selected = None;
        for current in state.tasks.values() {
            if current.task.class != MaintenanceTaskClass::EnvelopeVerification
                || current.task.scope != MaintenanceScope::tenant(tenant)
            {
                continue;
            }
            require_unreserved_task_transition(&state, current.task.identity)?;
            if selected.replace(current.task.identity).is_some() {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
        }
        let identity = selected.ok_or(MaintenanceFailure::PreconditionFailed)?;
        let current = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if current.phase != MaintenanceTaskPhase::Succeeded
            || current.active_dispatch.is_some()
            || current.task.reservations != crate::integrity_scrub_resource_claim()
            || current.task.trigger != MaintenanceTrigger::Event
            || current.task.preconditions.resource_generation != 1
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let _work = scheduling::reserve_task(catalog.resource_authority(), &current.task)
            .map_err(|_| MaintenanceFailure::ResourceAdmissionRefused)?;
        let checkpoint = current
            .checkpoint
            .as_ref()
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let progress = EnvelopeVerificationCheckpoint::from_checkpoint(
            checkpoint,
            catalog.instance(),
            tenant,
            epoch,
        )?;
        if !progress.is_complete()
            || progress.source_identity()
                != basis
                    .envelope_verification_source_identity(catalog.instance(), &current.task)
                    .map_err(|_| MaintenanceFailure::PreconditionFailed)?
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let record = encode_record(current)?.catalog_object()?;
        let (transaction, format, mut proposal_objects) = proposal.into_parts();
        if Some(format) != basis.format_epoch() {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let before = proposal_objects.len();
        proposal_objects.retain(|object| object.identity() != record.identity());
        if before.checked_sub(proposal_objects.len()) != Some(1) {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let mut expected = Vec::new();
        expected
            .try_reserve_exact(proposal_objects.len())
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        expected.extend(proposal_objects.iter().map(crate::CatalogObject::identity));
        let proposal = crate::CatalogProposal::new(transaction, format, proposal_objects)
            .map_err(map_catalog_failure)?;
        match catalog.commit(basis.identity(), proposal, Some(audit)) {
            Ok(commit) => {
                scheduling::remove_task_and_clear_empty_scope(&mut state, identity)?;
                Ok(commit)
            },
            Err(failure) => {
                // Only this exact authenticated transaction may reconcile an
                // acknowledgement-ambiguous publication. Never refresh proof.
                let visible = match catalog.confirm_committed_transaction(transaction) {
                    Ok(commit) => commit,
                    // A second sync failure cannot undo an authenticated
                    // visible marker. Adopt its exact task removal in memory,
                    // but preserve failure until a later durability retry.
                    Err(_) => catalog
                        .committed_transaction(transaction)
                        .map_err(map_catalog_failure)?,
                };
                if let Some(commit) = visible
                    && commit.predecessor() == basis.identity()
                    && commit.snapshot().format_epoch() == Some(format)
                    && commit
                        .snapshot()
                        .object_identities()
                        .eq(expected.iter().copied())
                {
                    scheduling::remove_task_and_clear_empty_scope(&mut state, identity)?;
                }
                Err(map_catalog_failure(failure))
            },
        }
    }
}
