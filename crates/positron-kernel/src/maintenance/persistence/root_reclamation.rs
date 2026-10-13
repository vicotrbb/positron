//! Explicit key-lifecycle reclamation uses the existing terminal task owner.
use super::*;
use crate::CatalogProposal;

impl MaintenanceCoordinator {
    /// Removes only authenticated terminal task descriptors. Pending work,
    /// snapshots, and retained artifacts keep their independent reference owners.
    pub fn reclaim_terminal_records_for_root_retirement(
        &self,
        session: &crate::RootRewrapSession<'_>,
        catalog: &Catalog<'_>,
    ) -> Result<usize, MaintenanceFailure> {
        if !std::ptr::eq(session.resource_authority(), catalog.resource_authority()) {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let _barrier = session
            .resource_authority()
            .snapshot_barrier()
            .try_write()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let pending = self
            .state
            .try_lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?
            .pending_root_reclamation
            .clone();
        if let Some(pending) = pending {
            let installed = self.confirm_root_reclamation(catalog, &pending)?;
            return self.install_root_reclamation(&pending, installed);
        }
        let basis = catalog.pin().map_err(map_catalog_failure)?;
        let _copy = catalog
            .reserve_catalog_proposal_copy(&basis)
            .map_err(map_catalog_failure)?;
        let mut removed = Vec::new();
        removed
            .try_reserve_exact(MAX_MAINTENANCE_TASKS)
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(basis.object_count())
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        let mut material = Vec::new();
        material
            .try_reserve_exact(32 + MAX_MAINTENANCE_TASKS * 32)
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        material.extend_from_slice(b"root-terminal-reclamation-v1");
        let (transaction, proposal) = {
            let mut state = self
                .state
                .try_lock()
                .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
            if !state.pending_submissions.is_empty()
                || !state.pending_terminal_reclamations.is_empty()
            {
                return Err(MaintenanceFailure::ConcurrentAccess);
            }
            let mut seen = BTreeSet::new();
            for bytes in basis.plaintext_objects() {
                let remove = if let Some(identity) = record::record_identity(bytes)? {
                    if !seen.insert(identity) {
                        return Err(MaintenanceFailure::PreconditionFailed);
                    }
                    let live = state
                        .tasks
                        .get(&identity)
                        .ok_or(MaintenanceFailure::PreconditionFailed)?;
                    require_unreserved_task_transition(&state, identity)?;
                    let durable = decode_record(bytes)?;
                    if !matches_catalog_reclamation_predecessor(&durable, bytes, live)? {
                        return Err(MaintenanceFailure::PreconditionFailed);
                    }
                    let terminal = matches!(
                        live.phase,
                        MaintenanceTaskPhase::Succeeded
                            | MaintenanceTaskPhase::Cancelled
                            | MaintenanceTaskPhase::Failed
                    );
                    let completed_publication = live.phase == MaintenanceTaskPhase::Succeeded
                        && live.task.class == MaintenanceTaskClass::RetentionPublication;
                    let reference_free_scrub = if live.task.class
                        == MaintenanceTaskClass::IntegrityScrub
                        && live.checkpoint.is_none()
                    {
                        live.task.integrity_scrub_source.is_some_and(|source| {
                            MaintenanceTask::integrity_scrub(
                                live.task.identity,
                                live.task.scope,
                                live.task.trigger,
                                live.task.preconditions,
                                source.to_bytes(),
                                live.task.not_before,
                            )
                            .is_ok_and(|expected| expected == live.task)
                        })
                    } else {
                        false
                    };
                    let released_lease = if live.task.class
                        == MaintenanceTaskClass::SnapshotLeaseExpiry
                        && live.checkpoint.is_none()
                        && live.task.inputs.len() == 1
                        && matches!(live.task.scope, MaintenanceScope::Segment { .. })
                    {
                        let input = live
                            .task
                            .inputs
                            .first()
                            .ok_or(MaintenanceFailure::InvalidInput)?;
                        let expected = MaintenanceTask::with_contract_not_before(
                            live.task.identity,
                            MaintenanceTaskClass::SnapshotLeaseExpiry,
                            live.task.scope,
                            MaintenanceTrigger::Scheduled,
                            MaintenancePreconditions::new(
                                live.task.preconditions.catalog_generation,
                                1,
                            )?,
                            vec![*input],
                            Vec::new(),
                            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
                            live.task.not_before,
                        )?;
                        expected == live.task
                            && !basis
                                .object_identities()
                                .any(|identity| identity.to_bytes() == input.to_bytes())
                    } else {
                        false
                    };
                    let completed_reclamation = if live.phase == MaintenanceTaskPhase::Succeeded
                        && live.task.class == MaintenanceTaskClass::RetentionReclamation
                    {
                        validate_retention_reclamation_state(live)?;
                        crate::ActiveSegmentLedger::completed_reclamation_references_absent(
                            session.resource_authority(),
                            &basis,
                            &live.task,
                        )
                        .map_err(|_| MaintenanceFailure::PreconditionFailed)?
                    } else {
                        false
                    };
                    if completed_publication {
                        // This checkpoint has a typed completed frontier; opaque
                        // task progress is never a reference-retirement proof.
                        retention_publication_frontier(live.checkpoint.as_ref())?;
                    }
                    if terminal
                        && (completed_publication
                            || completed_reclamation
                            || reference_free_scrub
                            || released_lease
                            || !durable_task_retains_unproved_root_reference(bytes)?)
                    {
                        removed.push(identity);
                        material.extend_from_slice(
                            &CatalogObject::new(bytes.to_vec())
                                .map_err(map_catalog_failure)?
                                .identity()
                                .to_bytes(),
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if !remove {
                    objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
                }
            }
            if seen.len() != state.tasks.len() {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            if removed.is_empty() {
                return Ok(0);
            }
            let digest = CatalogObject::new(material)
                .map_err(map_catalog_failure)?
                .identity()
                .to_bytes();
            let transaction = record_transaction(basis.identity().to_bytes(), digest)?;
            let epoch = basis
                .format_epoch()
                .ok_or(MaintenanceFailure::CatalogUnavailable)?;
            let proposal =
                CatalogProposal::new(transaction, epoch, objects).map_err(map_catalog_failure)?;
            for identity in &removed {
                state.pending_terminal_reclamations.insert(*identity);
                state.pending_task_transitions.insert(*identity);
            }
            state.pending_root_reclamation = Some(PendingRootReclamation {
                transaction,
                basis: basis.identity(),
                removed: removed.clone(),
            });
            (transaction, proposal)
        };
        let result = match catalog.commit(basis.identity(), proposal, None) {
            Ok(_) => Ok(true),
            Err(_) => match catalog.confirm_committed_transaction(transaction) {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(_) => Err(MaintenanceFailure::CatalogUnavailable),
            },
        };
        let installed = result?;
        self.install_root_reclamation(
            &PendingRootReclamation {
                transaction,
                basis: basis.identity(),
                removed,
            },
            installed,
        )
    }

    fn confirm_root_reclamation(
        &self,
        catalog: &Catalog<'_>,
        pending: &PendingRootReclamation,
    ) -> Result<bool, MaintenanceFailure> {
        let Some(commit) = catalog
            .confirm_committed_transaction(pending.transaction)
            .map_err(map_catalog_failure)?
        else {
            return Ok(false);
        };
        let basis = catalog.pin().map_err(map_catalog_failure)?;
        if commit.predecessor() != pending.basis || basis.identity() != commit.identity() {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        for bytes in basis.plaintext_objects() {
            if record::record_identity(bytes)?
                .is_some_and(|identity| pending.removed.contains(&identity))
            {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
        }
        Ok(true)
    }

    fn install_root_reclamation(
        &self,
        pending: &PendingRootReclamation,
        installed: bool,
    ) -> Result<usize, MaintenanceFailure> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let owner = state
            .pending_root_reclamation
            .as_ref()
            .ok_or(MaintenanceFailure::PreconditionFailed)?;
        if owner.transaction != pending.transaction
            || owner.basis != pending.basis
            || owner.removed != pending.removed
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        for identity in &pending.removed {
            if !state.pending_terminal_reclamations.contains(identity)
                || !state.pending_task_transitions.contains(identity)
            {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            if !state.tasks.contains_key(identity) {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
        }
        for identity in &pending.removed {
            if installed {
                remove_task_and_clear_empty_scope(&mut state, *identity)?;
            }
            state.pending_terminal_reclamations.remove(identity);
            state.pending_task_transitions.remove(identity);
        }
        state.pending_root_reclamation = None;
        if !installed {
            return Err(MaintenanceFailure::CatalogUnavailable);
        }
        Ok(pending.removed.len())
    }
}
