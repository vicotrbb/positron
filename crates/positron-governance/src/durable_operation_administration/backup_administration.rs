//! Administration owns Backup acceptance, audited phases and terminal lookup.
use super::*;
impl DurableOperationAdministration {
    pub fn accept_backup(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: BackupSnapshotParameters,
        registration_binding: [u8; 32],
        registration: CatalogObject,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::BackupSnapshot
            || request.operation_request_digest != Some(parameters.intent_digest())
            || registration_binding != parameters.registration_identity()
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
        let mut operation = DurableOperation::accepted(request);
        operation.backup_parameters = Some(BackupOperationParameters::Snapshot(parameters));
        if let Some(resumed) = resume_prepared_operation(
            catalog,
            transition_transaction(operation)?,
            transition_request_digest(operation),
            operation.operation_id(),
        )? {
            return Ok(resumed);
        }
        if snapshot.number() != request.accepted_generation() {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        // Backup owns native Repository admission and authenticates this stable
        // binding before supplying an anchored registration. The anchor changes
        // its Catalog address without changing the accepted Repository intent.
        publish_with_additions(catalog, &snapshot, operation, vec![registration])
    }
    /// Backup's registration owner authenticates the canonical row and its
    /// stable logical binding. Governance requires that exact row to remain in
    /// the current Catalog; operation/audit lookup retention is independent.
    pub fn accept_backup_registered(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: BackupSnapshotParameters,
        registration: CatalogObjectId,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::BackupSnapshot
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
        operation.backup_parameters = Some(BackupOperationParameters::Snapshot(parameters));
        publish(catalog, &snapshot, operation)
    }
    pub fn advance_backup(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        stage: BackupOperationStage,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        if operation.kind() != DurableOperationKind::BackupSnapshot
            || operation.status != DurableOperationStatus::Running
            || now < operation.updated_at_unix_seconds
            || operation.phase.code() > stage.phase().code()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if operation.phase == stage.phase() {
            return Ok(operation);
        }
        operation.phase = stage.phase();
        operation.progress_percent = stage.progress();
        operation.cancellation = if stage == BackupOperationStage::Publishing {
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
    pub fn succeed_backup_with_registration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        receipt: BackupOperationReceipt,
        previous_registration: CatalogObjectId,
        registration: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        if operation.status == DurableOperationStatus::Succeeded {
            return if operation.backup_receipt() == Some(receipt) {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if operation.kind() != DurableOperationKind::BackupSnapshot
            || operation.phase != DurableOperationPhase::BackupPublication
            || receipt.retain_until() < operation.accepted_at_unix_seconds()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let mut completed = operation.succeeded(now)?;
        completed.backup_evidence = Some(backup_parameters::BackupOperationEvidence::Snapshot(
            receipt,
        ));
        publish_with_objects(
            catalog,
            &snapshot,
            completed,
            vec![registration],
            Some(previous_registration),
        )
    }
    pub fn fail_backup(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        publish(
            catalog,
            &snapshot,
            operation.failed(now, DurableOperationTerminalError::HandlerRejected)?,
        )
    }
    /// Runtime has proved no remote candidate or local capture remains. The
    /// existing failure and audit are authoritative; there is no new outcome.
    pub fn complete_backup_failure_cleanup(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (_, operation) = authorized(catalog, actor, id)?;
        validate_failed_backup_cleanup(operation, now)?;
        Ok(operation)
    }
    /// Publish authenticated remote cleanup without rewriting the primary
    /// failure as cancellation or changing its completion/lookup lifetime.
    pub fn complete_backup_failure_cleanup_with_registration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        receipt: super::BackupCleanupReceipt,
        previous: CatalogObjectId,
        registration: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        validate_failed_backup_cleanup(operation, now)?;
        if receipt.snapshot_id() != id.to_bytes() || previous == registration.identity() {
            return Err(DurableOperationFailure::InvalidInput);
        }
        if let Some(existing) = operation.backup_cleanup_receipt() {
            return if existing == receipt
                && snapshot
                    .object(registration.identity())
                    .map_err(map_catalog)?
                    .is_some()
                && snapshot.object(previous).map_err(map_catalog)?.is_none()
            {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        operation.backup_evidence =
            Some(backup_parameters::BackupOperationEvidence::Cleanup(receipt));
        operation.updated_at_unix_seconds = now;
        operation.revision = operation
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        publish_with_objects(
            catalog,
            &snapshot,
            operation,
            vec![registration],
            Some(previous),
        )
    }
    pub fn cancel_backup(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        idempotency: AdministrativeIdempotencyKey,
        expected_revision: u64,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        if operation.cancellation_idempotency_key() == Some(idempotency) {
            return Ok(operation);
        }
        if has_other_cancellation_key(&snapshot, id, idempotency)? {
            return Err(DurableOperationFailure::IdempotencyConflict);
        }
        // Validate the same cutoff/idempotency rules without claiming cleanup.
        operation.cancelled(now, idempotency)?;
        let mut requested = operation;
        requested.status = DurableOperationStatus::Running;
        requested.phase = DurableOperationPhase::BackupCancellation;
        requested.progress_percent = 0;
        requested.cancellation = DurableOperationCancellation::Requested;
        requested.cancellation_idempotency = Some(idempotency);
        requested.updated_at_unix_seconds = now;
        requested.revision = requested
            .revision
            .checked_add(1)
            .ok_or(DurableOperationFailure::CapacityExceeded)?;
        if operation.revision != expected_revision {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        publish(catalog, &snapshot, requested)
    }
    /// Called by the admitted Backup worker after remote claim cleanup and the
    /// final local capture directory removal have both completed.
    pub fn complete_backup_cancellation(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        if operation.status == DurableOperationStatus::Cancelled {
            return Ok(operation);
        }
        if operation.phase != DurableOperationPhase::BackupCancellation
            || operation.cancellation != DurableOperationCancellation::Requested
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let idempotency = operation
            .cancellation_idempotency
            .ok_or(DurableOperationFailure::InvalidState)?;
        publish(catalog, &snapshot, operation.cancelled(now, idempotency)?)
    }
    pub fn complete_backup_cancellation_with_registration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        receipt: super::BackupCleanupReceipt,
        previous: CatalogObjectId,
        registration: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        if operation.kind() != DurableOperationKind::BackupSnapshot
            || receipt.snapshot_id() != id.to_bytes()
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        if operation.status == DurableOperationStatus::Cancelled {
            return if operation.backup_cleanup_receipt() == Some(receipt) {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if operation.phase != DurableOperationPhase::BackupCancellation
            || operation.cancellation != DurableOperationCancellation::Requested
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let idempotency = operation
            .cancellation_idempotency
            .ok_or(DurableOperationFailure::InvalidState)?;
        let mut completed = operation.cancelled(now, idempotency)?;
        completed.backup_evidence =
            Some(backup_parameters::BackupOperationEvidence::Cleanup(receipt));
        publish_with_objects(
            catalog,
            &snapshot,
            completed,
            vec![registration],
            Some(previous),
        )
    }
    pub fn resume_backup_actor(
        catalog: &Catalog<'_>,
        id: OperationId,
        now: u64,
    ) -> Result<crate::AuthorizedContext, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        if !matches!(
            operation.kind(),
            DurableOperationKind::BackupSnapshot
                | DurableOperationKind::BackupRetention
                | DurableOperationKind::BackupVerification
        ) {
            return Err(DurableOperationFailure::InvalidState);
        }
        crate::Identity::open(&snapshot)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?
            .resume_system_operation_actor(
                operation.request.principal,
                operation
                    .target_identity()
                    .ok_or(DurableOperationFailure::InvalidState)?,
                now,
            )
            .map_err(|_| DurableOperationFailure::Unauthorized)
    }
    pub fn next_backup_operation(
        catalog: &Catalog<'_>,
        after: Option<OperationId>,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        let basis = catalog.pin().map_err(map_catalog)?;
        let mut next: Option<DurableOperation> = None;
        for identity in basis.object_identities() {
            let bytes = basis
                .object(identity)
                .map_err(map_catalog)?
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
            let Some(operation) = decode_operation(bytes)? else {
                continue;
            };
            if !matches!(
                operation.kind(),
                DurableOperationKind::BackupSnapshot
                    | DurableOperationKind::BackupRetention
                    | DurableOperationKind::BackupVerification
            ) || operation.status().is_terminal()
                || after
                    .is_some_and(|after| operation.operation_id().to_bytes() <= after.to_bytes())
            {
                continue;
            }
            if next.is_none_or(|next| {
                operation.operation_id().to_bytes() < next.operation_id().to_bytes()
            }) {
                next = Some(operation);
            }
        }
        Ok(next)
    }
}
pub(super) fn authorized(
    catalog: &Catalog<'_>,
    actor: crate::AuthorizedContext,
    id: OperationId,
) -> Result<(CatalogSnapshot, DurableOperation), DurableOperationFailure> {
    let snapshot = catalog.pin().map_err(map_catalog)?;
    let operation = find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
    validate_system_actor(actor, operation.request.principal)?;
    if !matches!(
        operation.kind(),
        DurableOperationKind::BackupSnapshot
            | DurableOperationKind::BackupRetention
            | DurableOperationKind::BackupVerification
    ) {
        return Err(DurableOperationFailure::InvalidState);
    }
    Ok((snapshot, operation))
}
pub(super) fn legal_state(operation: &DurableOperation) -> bool {
    let Some(parameters) = operation.backup_parameters() else {
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
    let progress = match operation.phase {
        DurableOperationPhase::Preflight => {
            Some((10, DurableOperationCancellation::AllowedBeforeDrain))
        },
        DurableOperationPhase::BackupCapture => {
            Some((20, DurableOperationCancellation::AllowedBeforeDrain))
        },
        DurableOperationPhase::BackupTransfer => {
            Some((50, DurableOperationCancellation::AllowedBeforeDrain))
        },
        DurableOperationPhase::BackupVerification => {
            Some((80, DurableOperationCancellation::AllowedBeforeDrain))
        },
        DurableOperationPhase::BackupPublication => {
            Some((95, DurableOperationCancellation::NotAllowedAfterDrain))
        },
        DurableOperationPhase::BackupCancellation => {
            Some((0, DurableOperationCancellation::Requested))
        },
        _ => None,
    };
    if operation.backup_cleanup_receipt().is_some_and(|receipt| {
        !matches!(
            operation.status,
            DurableOperationStatus::Cancelled | DurableOperationStatus::Failed
        ) || receipt.snapshot_id() != operation.operation_id().to_bytes()
    }) {
        return false;
    }
    match operation.status {
        DurableOperationStatus::Pending => {
            operation.phase == DurableOperationPhase::Accepted
                && operation.progress_percent == 0
                && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.cancellation == DurableOperationCancellation::AllowedBeforeDrain
                && operation.retry == DurableOperationRetry::InspectByOperationId
                && operation.backup_receipt().is_none()
                && operation.completed_at_unix_seconds.is_none()
                && operation.terminal_error.is_none()
                && operation.cancellation_idempotency.is_none()
        },
        DurableOperationStatus::Running => {
            progress.is_some_and(|(percent, cancellation)| {
                percent == operation.progress_percent && cancellation == operation.cancellation
            }) && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.retry == DurableOperationRetry::InspectByOperationId
                && operation.completed_at_unix_seconds.is_none()
                && operation.backup_receipt().is_none()
                && operation.terminal_error.is_none()
                && (operation.cancellation_idempotency.is_some()
                    == (operation.phase == DurableOperationPhase::BackupCancellation))
        },
        DurableOperationStatus::Succeeded => {
            operation.phase == DurableOperationPhase::Published
                && operation.progress_percent == 100
                && operation.boundary == DurableOperationBoundary::BackupRegistryPublished
                && (operation.backup_receipt().is_some()
                    ^ operation.restored_backup_publication().is_some())
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
                && operation.cancellation == DurableOperationCancellation::Cancelled
                && operation.cancellation_idempotency.is_some()
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.retry == DurableOperationRetry::Never
                && operation.backup_receipt().is_none()
                && operation.terminal_error.is_none()
        },
        DurableOperationStatus::Failed => {
            progress.is_some_and(|(percent, cancellation)| {
                percent == operation.progress_percent && cancellation == operation.cancellation
            }) && operation.boundary == DurableOperationBoundary::NotCrossed
                && operation.backup_receipt().is_none()
                && match operation.backup_cleanup_receipt() {
                    Some(_) => {
                        operation.terminal_error
                            == Some(DurableOperationTerminalError::HandlerRejected)
                            && operation
                                .completed_at_unix_seconds
                                .is_some_and(|completed| {
                                    completed >= operation.accepted_at_unix_seconds()
                                        && completed <= operation.updated_at_unix_seconds
                                })
                    },
                    None => {
                        operation.completed_at_unix_seconds
                            == Some(operation.updated_at_unix_seconds)
                    },
                }
                && operation.retry == DurableOperationRetry::Never
                && operation.terminal_error.is_some()
                && operation.cancellation_idempotency.is_none()
        },
    }
}

fn validate_failed_backup_cleanup(
    operation: DurableOperation,
    now: u64,
) -> Result<(), DurableOperationFailure> {
    if operation.kind() != DurableOperationKind::BackupSnapshot
        || operation.status != DurableOperationStatus::Failed
        || operation.terminal_error != Some(DurableOperationTerminalError::HandlerRejected)
        || operation.boundary != DurableOperationBoundary::NotCrossed
        || operation.cancellation_idempotency.is_some()
        || now < operation.updated_at_unix_seconds
    {
        return Err(DurableOperationFailure::InvalidState);
    }
    Ok(())
}
