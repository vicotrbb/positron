//! Retention owns signed unpublication and subsequent object cleanup receipts.
use super::*;

impl DurableOperationAdministration {
    /// The admitted Backup owner has authenticated a deadline later than trusted now.
    pub fn reject_backup_retention_not_due(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        if operation.status == DurableOperationStatus::Failed
            && operation.terminal_error
                == Some(DurableOperationTerminalError::BackupRetentionNotDue)
        {
            return Ok(operation);
        }
        if operation.phase != DurableOperationPhase::BackupRetentionScan
            || operation.boundary != DurableOperationBoundary::NotCrossed
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(
            catalog,
            &snapshot,
            operation.failed(now, DurableOperationTerminalError::BackupRetentionNotDue)?,
        )
    }
    pub fn accept_backup_retention_registered(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: BackupRetentionParameters,
        registration: CatalogObjectId,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::BackupRetention
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
        operation.backup_parameters = Some(BackupOperationParameters::Retention(parameters));
        publish(catalog, &snapshot, operation)
    }
    pub fn advance_backup_retention(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        stage: BackupRetentionStage,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        let (phase, progress, cancellation) = match stage {
            BackupRetentionStage::Scanning => (
                DurableOperationPhase::BackupRetentionScan,
                20,
                DurableOperationCancellation::AllowedBeforeDrain,
            ),
            BackupRetentionStage::Publishing => (
                DurableOperationPhase::BackupRetentionPublication,
                60,
                DurableOperationCancellation::NotAllowedAfterDrain,
            ),
        };
        if operation.status != DurableOperationStatus::Running
            || operation.backup_evidence.is_some()
            || now < operation.updated_at_unix_seconds
            || operation.phase.code() > phase.code()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if operation.phase == phase {
            return Ok(operation);
        }
        operation.phase = phase;
        operation.progress_percent = progress;
        operation.cancellation = cancellation;
        touch(&mut operation, now)?;
        publish(catalog, &snapshot, operation)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn publish_backup_retention_claim_with_registration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        receipt: BackupRetentionClaimReceipt,
        previous: CatalogObjectId,
        registration: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        if operation.backup_retention_claim() == Some(receipt) {
            return Ok(operation);
        }
        if operation.status != DurableOperationStatus::Running
            || operation.phase != DurableOperationPhase::BackupRetentionPublication
            || operation.backup_evidence.is_some()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        operation.phase = DurableOperationPhase::BackupRetentionCleanup;
        operation.progress_percent = 90;
        operation.boundary = DurableOperationBoundary::BackupRegistryExpired;
        operation.backup_evidence = Some(
            backup_parameters::BackupOperationEvidence::RetentionClaim(receipt),
        );
        touch(&mut operation, now)?;
        publish_with_objects(
            catalog,
            &snapshot,
            operation,
            vec![registration],
            Some(previous),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn succeed_backup_retention_with_registration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        receipt: BackupCleanupReceipt,
        previous: CatalogObjectId,
        registration: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        let parameters = operation
            .backup_retention_parameters()
            .ok_or(DurableOperationFailure::InvalidState)?;
        if receipt.snapshot_id() != parameters.snapshot_id()
            || receipt.manifest_checksum() != parameters.manifest_checksum()
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        if operation.status == DurableOperationStatus::Succeeded {
            return if operation.backup_cleanup_receipt() == Some(receipt) {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if operation.status != DurableOperationStatus::Running
            || operation.phase != DurableOperationPhase::BackupRetentionCleanup
            || operation.backup_retention_claim().is_none()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        operation.status = DurableOperationStatus::Succeeded;
        operation.phase = DurableOperationPhase::Published;
        operation.progress_percent = 100;
        operation.retry = DurableOperationRetry::Never;
        operation.completed_at_unix_seconds = Some(now);
        operation.backup_evidence =
            Some(backup_parameters::BackupOperationEvidence::Cleanup(receipt));
        touch(&mut operation, now)?;
        publish_with_objects(
            catalog,
            &snapshot,
            operation,
            vec![registration],
            Some(previous),
        )
    }
}
fn touch(operation: &mut DurableOperation, now: u64) -> Result<(), DurableOperationFailure> {
    if now < operation.updated_at_unix_seconds {
        return Err(DurableOperationFailure::InvalidState);
    }
    operation.updated_at_unix_seconds = now;
    operation.revision = operation
        .revision
        .checked_add(1)
        .ok_or(DurableOperationFailure::CapacityExceeded)?;
    Ok(())
}
fn authorized(
    catalog: &Catalog<'_>,
    actor: crate::AuthorizedContext,
    id: OperationId,
) -> Result<(CatalogSnapshot, DurableOperation), DurableOperationFailure> {
    validate_system_actor(actor, actor.principal_id())?;
    let snapshot = catalog.pin().map_err(map_catalog)?;
    let operation = find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::InvalidState)?;
    if operation.kind() != DurableOperationKind::BackupRetention
        || operation.request.principal() != actor.principal_id()
    {
        return Err(DurableOperationFailure::InvalidState);
    }
    Ok((snapshot, operation))
}
pub(super) fn legal_state(operation: DurableOperation) -> bool {
    let Some(parameters) = operation.backup_retention_parameters() else {
        return false;
    };
    if operation.request.operation_request_digest != Some(parameters.intent_digest())
        || operation.key_provider_migration_parameters.is_some()
        || operation.repository_parameters.is_some()
        || operation.repository_policy.is_some()
        || operation.backup_verification_report().is_some()
    {
        return false;
    }
    match operation.status {
        DurableOperationStatus::Pending => {
            operation.phase == DurableOperationPhase::Accepted
                && operation.progress_percent == 0
                && operation.backup_evidence.is_none()
                && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.completed_at_unix_seconds.is_none()
                && operation.cancellation_idempotency.is_none()
                && operation.cancellation == DurableOperationCancellation::AllowedBeforeDrain
                && operation.retry == DurableOperationRetry::InspectByOperationId
                && operation.terminal_error.is_none()
        },
        DurableOperationStatus::Running => {
            let expected = match operation.phase {
                DurableOperationPhase::Preflight => Some((
                    10,
                    DurableOperationCancellation::AllowedBeforeDrain,
                    DurableOperationBoundary::NotCrossed,
                )),
                DurableOperationPhase::BackupRetentionScan => Some((
                    20,
                    DurableOperationCancellation::AllowedBeforeDrain,
                    DurableOperationBoundary::NotCrossed,
                )),
                DurableOperationPhase::BackupRetentionPublication => Some((
                    60,
                    DurableOperationCancellation::NotAllowedAfterDrain,
                    DurableOperationBoundary::NotCrossed,
                )),
                DurableOperationPhase::BackupRetentionCleanup => Some((
                    90,
                    DurableOperationCancellation::NotAllowedAfterDrain,
                    DurableOperationBoundary::BackupRegistryExpired,
                )),
                DurableOperationPhase::BackupCancellation => Some((
                    0,
                    DurableOperationCancellation::Requested,
                    DurableOperationBoundary::NotCrossed,
                )),
                _ => None,
            };
            expected
                == Some((
                    operation.progress_percent,
                    operation.cancellation,
                    operation.boundary,
                ))
                && (operation.backup_retention_claim().is_some()
                    == (operation.phase == DurableOperationPhase::BackupRetentionCleanup))
                && operation.backup_receipt().is_none()
                && operation.backup_cleanup_receipt().is_none()
                && operation.completed_at_unix_seconds.is_none()
                && operation.retry == DurableOperationRetry::InspectByOperationId
                && operation.terminal_error.is_none()
                && (operation.cancellation_idempotency.is_some()
                    == (operation.phase == DurableOperationPhase::BackupCancellation))
        },
        DurableOperationStatus::Succeeded => {
            operation.phase == DurableOperationPhase::Published
                && operation.progress_percent == 100
                && operation.boundary == DurableOperationBoundary::BackupRegistryExpired
                && operation.backup_cleanup_receipt().is_some_and(|receipt| {
                    receipt.snapshot_id() == parameters.snapshot_id()
                        && receipt.manifest_checksum() == parameters.manifest_checksum()
                })
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.retry == DurableOperationRetry::Never
                && operation.cancellation == DurableOperationCancellation::NotAllowedAfterDrain
                && operation.terminal_error.is_none()
                && operation.cancellation_idempotency.is_none()
        },
        DurableOperationStatus::Cancelled => {
            operation.phase == DurableOperationPhase::Cancelled
                && operation.progress_percent == 0
                && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.backup_evidence.is_none()
                && operation.cancellation == DurableOperationCancellation::Cancelled
                && operation.cancellation_idempotency.is_some()
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.retry == DurableOperationRetry::Never
                && operation.terminal_error.is_none()
        },
        DurableOperationStatus::Failed => {
            matches!(
                operation.phase,
                DurableOperationPhase::Preflight
                    | DurableOperationPhase::BackupRetentionScan
                    | DurableOperationPhase::BackupRetentionPublication
            ) && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.backup_evidence.is_none()
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.retry == DurableOperationRetry::Never
                && operation.terminal_error.is_some()
                && operation.cancellation_idempotency.is_none()
        },
    }
}
