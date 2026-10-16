//! Fresh restore persists one exact offline target intent and publication receipt.
use super::*;

impl DurableOperationAdministration {
    /// A changed authenticated source plan cannot publish the previously staged
    /// target. Retain its terminal failure and offline ownership for inspection.
    pub fn fail_backup_restore(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = restore_authorized(catalog, actor, id)?;
        if operation.status() == DurableOperationStatus::Failed {
            return Ok(operation);
        }
        publish(
            catalog,
            &snapshot,
            operation.failed(now, DurableOperationTerminalError::HandlerRejected)?,
        )
    }
    pub fn accept_backup_restore_registered(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: BackupRestoreParameters,
        registration: CatalogObjectId,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::BackupRestore
            || request.operation_request_digest != Some(parameters.intent_digest())
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(existing) = find_by_key(&snapshot, request.idempotency)? {
            return match existing {
                OperationKeyLookup::Operation(operation) => exact_replay(*operation, request),
                OperationKeyLookup::Expired(binding) => {
                    binding.exact_replay(request)?;
                    Err(DurableOperationFailure::CompletedLookupExpired)
                },
            };
        }
        if snapshot
            .object(registration)
            .map_err(map_catalog)?
            .is_none()
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        if snapshot.number() != request.accepted_generation() {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        let mut operation = DurableOperation::accepted(request);
        operation.backup_parameters = Some(BackupOperationParameters::Restore(parameters));
        publish(catalog, &snapshot, operation)
    }
    pub fn advance_backup_restore(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        stage: BackupRestoreStage,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = restore_authorized(catalog, actor, id)?;
        let (phase, rank, progress) = match stage {
            BackupRestoreStage::Transferring => (DurableOperationPhase::BackupTransfer, 1, 40),
            BackupRestoreStage::Verifying => (DurableOperationPhase::BackupVerification, 2, 80),
            BackupRestoreStage::Publishing => (DurableOperationPhase::CatalogPublication, 3, 95),
        };
        let current = match operation.phase {
            DurableOperationPhase::Preflight => 0,
            DurableOperationPhase::BackupTransfer => 1,
            DurableOperationPhase::BackupVerification => 2,
            DurableOperationPhase::CatalogPublication => 3,
            _ => return Err(DurableOperationFailure::InvalidState),
        };
        if operation.status != DurableOperationStatus::Running
            || now < operation.updated_at_unix_seconds
            || rank < current
            || rank > current + 1
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if current == rank {
            return Ok(operation);
        }
        operation.phase = phase;
        operation.progress_percent = progress;
        operation.cancellation = if rank == 3 {
            DurableOperationCancellation::NotAllowedAfterDrain
        } else {
            DurableOperationCancellation::AllowedBeforeDrain
        };
        operation.updated_at_unix_seconds = now;
        operation.revision = operation
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        publish(catalog, &snapshot, operation)
    }
    /// The Backup owner authenticates signed report contents before this atomic
    /// report-object, operation-receipt and audit publication.
    pub fn succeed_backup_restore(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        report: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = restore_authorized(catalog, actor, id)?;
        let identity = report.identity().to_bytes();
        if operation.status == DurableOperationStatus::Succeeded {
            return if operation.backup_restore_report() == Some(identity)
                && snapshot
                    .object(report.identity())
                    .map_err(map_catalog)?
                    .is_some()
            {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if operation.phase != DurableOperationPhase::CatalogPublication {
            return Err(DurableOperationFailure::InvalidState);
        }
        let mut completed = operation.succeeded(now)?;
        completed.backup_evidence = Some(
            backup_parameters::BackupOperationEvidence::RestoreReport(identity),
        );
        publish_with_additions(catalog, &snapshot, completed, vec![report])
    }
    pub fn cancel_backup_restore(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        key: AdministrativeIdempotencyKey,
        revision: u64,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = restore_authorized(catalog, actor, id)?;
        if operation.cancellation_idempotency_key() == Some(key) {
            return Ok(operation);
        }
        if has_other_cancellation_key(&snapshot, id, key)? {
            return Err(DurableOperationFailure::IdempotencyConflict);
        }
        if operation.revision != revision {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        publish(catalog, &snapshot, operation.cancelled(now, key)?)
    }
}
fn restore_authorized(
    catalog: &Catalog<'_>,
    actor: crate::AuthorizedContext,
    id: OperationId,
) -> Result<(CatalogSnapshot, DurableOperation), DurableOperationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    let operation = find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
    validate_system_actor(actor, operation.request.principal)?;
    if operation.kind() != DurableOperationKind::BackupRestore {
        return Err(DurableOperationFailure::InvalidState);
    }
    Ok((snapshot, operation))
}
pub(super) fn legal_state(operation: DurableOperation) -> bool {
    let Some(parameters) = operation.backup_restore_parameters() else {
        return false;
    };
    if operation.request.operation_request_digest != Some(parameters.intent_digest())
        || operation.key_provider_migration_parameters.is_some()
        || operation.repository_parameters.is_some()
        || operation.repository_policy.is_some()
        || operation.backup_receipt().is_some()
        || operation.backup_cleanup_receipt().is_some()
        || operation.backup_retention_claim().is_some()
        || operation.backup_restore_report() == Some([0; 32])
    {
        return false;
    }
    let common_active = operation.boundary == DurableOperationBoundary::NotCrossed
        && operation.backup_evidence.is_none()
        && operation.completed_at_unix_seconds.is_none()
        && operation.terminal_error.is_none()
        && operation.cancellation_idempotency.is_none()
        && operation.retry == DurableOperationRetry::InspectByOperationId;
    match operation.status {
        DurableOperationStatus::Pending => {
            common_active
                && operation.phase == DurableOperationPhase::Accepted
                && operation.progress_percent == 0
                && operation.cancellation == DurableOperationCancellation::AllowedBeforeDrain
        },
        DurableOperationStatus::Running => {
            common_active
                && match operation.phase {
                    DurableOperationPhase::Preflight => {
                        operation.progress_percent == 10
                            && operation.cancellation
                                == DurableOperationCancellation::AllowedBeforeDrain
                    },
                    DurableOperationPhase::BackupTransfer => {
                        operation.progress_percent == 40
                            && operation.cancellation
                                == DurableOperationCancellation::AllowedBeforeDrain
                    },
                    DurableOperationPhase::BackupVerification => {
                        operation.progress_percent == 80
                            && operation.cancellation
                                == DurableOperationCancellation::AllowedBeforeDrain
                    },
                    DurableOperationPhase::CatalogPublication => {
                        operation.progress_percent == 95
                            && operation.cancellation
                                == DurableOperationCancellation::NotAllowedAfterDrain
                    },
                    _ => false,
                }
        },
        DurableOperationStatus::Succeeded => {
            operation.phase == DurableOperationPhase::Published
                && operation.progress_percent == 100
                && operation.boundary == DurableOperationBoundary::CatalogGenerationPublished
                && operation.backup_restore_report().is_some()
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.terminal_error.is_none()
                && operation.cancellation_idempotency.is_none()
                && operation.retry == DurableOperationRetry::Never
                && operation.cancellation == DurableOperationCancellation::NotAllowedAfterDrain
        },
        DurableOperationStatus::Cancelled => {
            operation.phase == DurableOperationPhase::Cancelled
                && operation.progress_percent == 0
                && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.backup_evidence.is_none()
                && operation.cancellation_idempotency.is_some()
                && operation.cancellation == DurableOperationCancellation::Cancelled
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.terminal_error.is_none()
                && operation.retry == DurableOperationRetry::Never
        },
        DurableOperationStatus::Failed => {
            matches!(
                operation.phase,
                DurableOperationPhase::Preflight
                    | DurableOperationPhase::BackupTransfer
                    | DurableOperationPhase::BackupVerification
                    | DurableOperationPhase::CatalogPublication
            ) && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.backup_evidence.is_none()
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.terminal_error.is_some()
                && operation.retry == DurableOperationRetry::Never
                && operation.cancellation_idempotency.is_none()
        },
    }
}
