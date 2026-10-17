//! Independent verification publishes immutable evidence through the Catalog owner.
use super::*;

impl DurableOperationAdministration {
    pub fn accept_backup_verification_registered(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: BackupVerificationParameters,
        registration: CatalogObjectId,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::BackupVerification
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
        operation.backup_parameters = Some(BackupOperationParameters::Verification(parameters));
        publish(catalog, &snapshot, operation)
    }
    pub fn advance_backup_verification(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        publishing: bool,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = verification_authorized(catalog, actor, id)?;
        let phase = if publishing {
            DurableOperationPhase::BackupPublication
        } else {
            DurableOperationPhase::BackupVerification
        };
        if operation.status != DurableOperationStatus::Running
            || now < operation.updated_at_unix_seconds
            || operation.phase.code() > phase.code()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if operation.phase == phase {
            return Ok(operation);
        }
        operation.phase = phase;
        operation.progress_percent = if publishing { 95 } else { 50 };
        operation.cancellation = if publishing {
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
    pub fn succeed_backup_verification(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        report: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = verification_authorized(catalog, actor, id)?;
        let identity = report.identity().to_bytes();
        if operation.status == DurableOperationStatus::Succeeded {
            return if operation.backup_verification_report() == Some(identity)
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
        if operation.phase != DurableOperationPhase::BackupPublication {
            return Err(DurableOperationFailure::InvalidState);
        }
        let mut completed = operation.succeeded(now)?;
        completed.backup_evidence =
            Some(backup_parameters::BackupOperationEvidence::VerificationReport(identity));
        publish_with_additions(catalog, &snapshot, completed, vec![report])
    }
    pub fn cancel_backup_verification(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        key: AdministrativeIdempotencyKey,
        revision: u64,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = verification_authorized(catalog, actor, id)?;
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
fn verification_authorized(
    catalog: &Catalog<'_>,
    actor: crate::AuthorizedContext,
    id: OperationId,
) -> Result<(CatalogSnapshot, DurableOperation), DurableOperationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    let operation = find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
    validate_system_actor(actor, operation.request.principal)?;
    if operation.kind() != DurableOperationKind::BackupVerification {
        return Err(DurableOperationFailure::InvalidState);
    }
    Ok((snapshot, operation))
}
pub(super) fn legal_state(operation: &DurableOperation) -> bool {
    let Some(parameters) = operation.backup_verification_parameters() else {
        return false;
    };
    if operation.request.operation_request_digest != Some(parameters.intent_digest())
        || operation.key_provider_migration_parameters.is_some()
        || operation.repository_parameters.is_some()
        || operation.repository_policy.is_some()
        || operation.backup_receipt().is_some()
        || operation.backup_cleanup_receipt().is_some()
        || operation.backup_retention_claim().is_some()
        || operation.backup_verification_report() == Some([0; 32])
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
                    DurableOperationPhase::BackupVerification => {
                        operation.progress_percent == 50
                            && operation.cancellation
                                == DurableOperationCancellation::AllowedBeforeDrain
                    },
                    DurableOperationPhase::BackupPublication => {
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
                && operation.boundary == DurableOperationBoundary::VerificationReportPublished
                && operation.backup_verification_report().is_some()
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
                    | DurableOperationPhase::BackupVerification
                    | DurableOperationPhase::BackupPublication
            ) && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.backup_evidence.is_none()
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.terminal_error.is_some()
                && operation.retry == DurableOperationRetry::Never
                && operation.cancellation_idempotency.is_none()
        },
    }
}
