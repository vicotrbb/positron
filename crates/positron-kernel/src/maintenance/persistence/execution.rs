//! Public execution operations backed by the coordinator persistence authority.

use super::super::*;
use super::*;

impl MaintenanceExecution<'_> {
    pub(crate) fn verify_running_catalog_reclamation(
        &self,
        coordinator: &MaintenanceCoordinator,
        durable_record: &[u8],
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::CatalogReclamation {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.verify_running_catalog_reclamation_dispatch(self.dispatch, durable_record)
    }

    pub(crate) fn complete_catalog_reclamation_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::CatalogReclamation {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.complete_catalog_reclamation_and_persist_dispatch(catalog, self.dispatch)
    }

    pub(crate) fn requeue_catalog_reclamation_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::CatalogReclamation {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.requeue_catalog_reclamation_and_persist_dispatch(catalog, self.dispatch)
    }

    pub(crate) fn reconcile_cancelled_catalog_reclamation_after_terminal_failure(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::CatalogReclamation {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator
            .restore_cancelled_catalog_reclamation_after_terminal_failure(catalog, self.dispatch)
    }

    pub(crate) fn catalog_reclamation_cancellation_requested(
        &self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<bool, MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::CatalogReclamation {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.catalog_reclamation_cancellation_requested_dispatch(self.dispatch)
    }
    pub(crate) fn prepare_running_retention_reclamation_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        durable_record: &[u8],
    ) -> Result<RetentionReclamationTaskReplacement, MaintenanceFailure> {
        coordinator.prepare_running_retention_reclamation_completion(self.dispatch, durable_record)
    }

    pub(crate) fn reconcile_running_retention_reclamation_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        terminal_record: &[u8],
    ) -> Result<RetentionReclamationTaskReplacement, MaintenanceFailure> {
        coordinator
            .reconcile_running_retention_reclamation_completion(self.dispatch, terminal_record)
    }

    pub(crate) fn cancel_running_retention_publication_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
    ) -> Result<(), MaintenanceFailure> {
        coordinator
            .cancel_running_retention_publication_and_persist_dispatch(catalog, self.dispatch)
    }

    pub(crate) fn requeue_running_retention_reclamation_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        durable_record: &[u8],
    ) -> Result<(), MaintenanceFailure> {
        coordinator.requeue_running_retention_reclamation_and_persist_dispatch(
            catalog,
            self.dispatch,
            durable_record,
        )
    }

    pub(crate) fn reconcile_running_retention_publication_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        publication_record: &[u8],
        reclamation_record: &[u8],
    ) -> Result<RetentionPublicationTaskCompletion, MaintenanceFailure> {
        coordinator.reconcile_running_retention_publication_completion(
            self.dispatch,
            publication_record,
            reclamation_record,
        )
    }

    pub(crate) fn prepare_running_retention_publication_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        binding: RetentionPublicationBinding<'_, '_>,
    ) -> Result<RetentionPublicationTaskCompletion, MaintenanceFailure> {
        coordinator.prepare_running_retention_publication_completion(self.dispatch, binding)
    }

    pub(crate) fn prepare_running_compaction_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        durable_record: &[u8],
    ) -> Result<CompactionTaskReplacement, MaintenanceFailure> {
        coordinator.prepare_running_compaction_completion(self.dispatch, durable_record)
    }

    pub(crate) fn reconcile_running_compaction_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        durable_record: &[u8],
    ) -> Result<CompactionTaskReplacement, MaintenanceFailure> {
        coordinator.reconcile_running_compaction_completion(self.dispatch, durable_record)
    }

    pub(crate) fn reconcile_running_snapshot_lease_expiry_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        durable_record: &[u8],
    ) -> Result<SnapshotLeaseExpiryTaskReplacement, MaintenanceFailure> {
        coordinator
            .reconcile_running_snapshot_lease_expiry_completion(self.dispatch, durable_record)
    }
    pub(crate) fn prepare_running_snapshot_lease_expiry_completion(
        &self,
        coordinator: &MaintenanceCoordinator,
        binding: SnapshotLeaseExpiryBinding<'_>,
    ) -> Result<SnapshotLeaseExpiryTaskReplacement, MaintenanceFailure> {
        coordinator.prepare_running_snapshot_lease_expiry_completion(self.dispatch, binding)
    }

    /// Durably advances a handler checkpoint through the sole Catalog Writer.
    /// A failed or ambiguous publication leaves the in-memory state unchanged
    /// until the exact retry resolves against the Catalog record.
    pub fn checkpoint_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        if matches!(
            self.task.class,
            MaintenanceTaskClass::Compaction | MaintenanceTaskClass::CatalogReclamation
        ) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        coordinator.checkpoint_and_persist_dispatch(catalog, self.dispatch, checkpoint, None)
    }

    /// Commits a checkpoint with the server lifecycle instant at which it was
    /// observed. Only a successful Catalog publication of semantic progress
    /// resets the running no-progress deadline.
    pub fn checkpoint_and_persist_at(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        checkpoint: MaintenanceCheckpoint,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        if matches!(
            self.task.class,
            MaintenanceTaskClass::Compaction | MaintenanceTaskClass::CatalogReclamation
        ) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        coordinator.checkpoint_and_persist_dispatch(catalog, self.dispatch, checkpoint, Some(now))
    }

    /// Durably publishes the terminal coordinator outcome before releasing the
    /// execution and its governor reservation.
    pub fn complete_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        if matches!(
            self.task.class,
            MaintenanceTaskClass::Compaction
                | MaintenanceTaskClass::GovernanceAuditCheckpoint
                | MaintenanceTaskClass::CatalogReclamation
        ) {
            if matches!(
                self.task.class,
                MaintenanceTaskClass::Compaction | MaintenanceTaskClass::CatalogReclamation
            ) {
                return Err(MaintenanceFailure::InvalidTransition);
            }
            coordinator.complete_and_persist_admitted_dispatch(
                catalog,
                self.dispatch,
                succeeded,
                self,
            )
        } else {
            coordinator.complete_and_persist_dispatch(catalog, self.dispatch, succeeded)
        }
    }

    /// Publishes a permanent, typed terminal failure before releasing the
    /// execution and its governor reservation. Availability failures remain
    /// on the running descriptor for retry and must not use this transition.
    pub fn fail_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        failure: MaintenanceTerminalFailure,
    ) -> Result<(), MaintenanceFailure> {
        if matches!(
            self.task.class,
            MaintenanceTaskClass::Compaction | MaintenanceTaskClass::CatalogReclamation
        ) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        if self.task.class == MaintenanceTaskClass::GovernanceAuditCheckpoint {
            coordinator.fail_and_persist_admitted_dispatch(catalog, self.dispatch, failure, self)
        } else {
            coordinator.fail_and_persist_dispatch(catalog, self.dispatch, failure)
        }
    }

    /// Terminalizes an authenticated retention publication whose current plan
    /// no longer matches its durable pre-mutation binding. It intentionally
    /// cannot complete a reclamation or reconcile an ambiguous publication.
    pub fn fail_rejected_retention_publication_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        proof: &crate::LedgerFailure,
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::RetentionPublication {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.fail_rejected_retention_publication_and_persist_dispatch(
            catalog,
            self.dispatch,
            proof,
        )
    }

    /// Terminalizes a dispatched Compaction whose authenticated selected bucket
    /// contains no blocks. This commits only its exact PMTC successor; it must
    /// not invent a replacement segment or manifest publication.
    pub(crate) fn complete_empty_compaction_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::Compaction {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.complete_and_persist_dispatch(catalog, self.dispatch, true)
    }

    /// Records an authenticated Compaction binding rejected before it can
    /// mutate output. This is deliberately unavailable to other task classes:
    /// Compaction publication has separate post-mutation reconciliation.
    pub fn fail_rejected_compaction_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
    ) -> Result<(), MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::Compaction {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.fail_and_persist_dispatch(
            catalog,
            self.dispatch,
            MaintenanceTerminalFailure::StaleGeneration,
        )
    }

    /// Returns an audit-checkpoint execution to its durable queue while its
    /// existing reservation is still live. This is used only after its signed
    /// artifact has committed but the terminal task record remains unavailable.
    pub fn requeue_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
    ) -> Result<(), MaintenanceFailure> {
        if !matches!(
            self.task.class,
            MaintenanceTaskClass::GovernanceAuditCheckpoint | MaintenanceTaskClass::IntegrityScrub
        ) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.requeue_admitted_dispatch(catalog, self.dispatch, self)
    }

    /// Releases a failed audit-checkpoint owner for a later exact same-process
    /// recovery when even its durable requeue publication was unavailable.
    pub fn release_for_same_process_recovery(
        &self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        if !matches!(
            self.task.class,
            MaintenanceTaskClass::GovernanceAuditCheckpoint | MaintenanceTaskClass::IntegrityScrub
        ) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        coordinator.release_admitted_dispatch_for_recovery(self.dispatch)
    }
}
