//! Upgrade semantics use the existing jointly audited operation publication.
use super::upgrade_parameters::UpgradeProgress;
use super::*;

impl DurableOperationAdministration {
    /// The registration owner authenticates the stable binding in parameters;
    /// Governance requires its exact current Catalog row, as for Backup acceptance.
    pub fn accept_upgrade(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: UpgradeParameters,
        registration: CatalogObjectId,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::Upgrade
            || request.operation_request_digest != Some(parameters.intent_digest())
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if request.target_identity()
            != Some(
                snapshot
                    .governance_object()
                    .map_err(map_catalog)?
                    .1
                    .instance(),
            )
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
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
        operation.backup_parameters = Some(BackupOperationParameters::Upgrade(parameters));
        operation.upgrade_progress = Some(UpgradeProgress {
            report: None,
            rollback: None,
            stage: UpgradeStage::Preflight,
            drain: None,
            snapshot: None,
        });
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
        if snapshot.format_epoch().map(FormatEpoch::value) != Some(parameters.format_epoch())
            || snapshot
                .object(registration)
                .map_err(map_catalog)?
                .is_none()
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        if Self::current_upgrade_publication_snapshot(&snapshot)?
            .is_some_and(|current| current.release() != parameters.source())
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        if Self::next_upgrade_operation(catalog, None)?.is_some() {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(catalog, &snapshot, operation)
    }
    pub fn next_upgrade_operation(
        catalog: &Catalog<'_>,
        after: Option<OperationId>,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let mut next: Option<DurableOperation> = None;
        for id in snapshot.object_identities() {
            let Some(operation) = decode_operation(
                snapshot
                    .object(id)
                    .map_err(map_catalog)?
                    .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
            )?
            else {
                continue;
            };
            if operation.kind() != DurableOperationKind::Upgrade
                || operation.status().is_terminal()
                || after.is_some_and(|id| operation.operation_id().to_bytes() <= id.to_bytes())
            {
                continue;
            }
            if next.is_none_or(|previous| {
                operation.operation_id().to_bytes() < previous.operation_id().to_bytes()
            }) {
                next = Some(operation);
            }
        }
        Ok(next)
    }
    pub fn resume_upgrade_actor(
        catalog: &Catalog<'_>,
        id: OperationId,
        now: u64,
    ) -> Result<crate::AuthorizedContext, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        if operation.kind() != DurableOperationKind::Upgrade {
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
    /// Runtime owns real preflight, publication and startup verification. This
    /// checkpoint cannot skip their ordered evidence or undo published work.
    pub fn advance_upgrade(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        stage: UpgradeStage,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        let mut progress = operation
            .upgrade_progress
            .ok_or(DurableOperationFailure::InvalidState)?;
        if operation.status != DurableOperationStatus::Running
            || now < operation.updated_at_unix_seconds
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if stage == progress.stage {
            return Ok(operation);
        }
        if stage.code() != progress.stage.code() + 1
            || stage == UpgradeStage::Succeeded
            || (stage.code() >= 3 && progress.drain.is_none())
            || (stage.code() >= 4 && progress.snapshot.is_none())
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        progress.stage = stage;
        operation.upgrade_progress = Some(progress);
        operation.phase = stage.phase();
        operation.progress_percent = stage.progress();
        if stage.code() >= 5 {
            operation.boundary = DurableOperationBoundary::CatalogGenerationPublished;
            operation.cancellation = DurableOperationCancellation::NotAllowedAfterDrain;
        }
        update(&mut operation, now)?;
        if stage == UpgradeStage::AwaitingRestart {
            upgrade_publication::publish_current(catalog, &snapshot, operation)
        } else {
            publish(catalog, &snapshot, operation)
        }
    }
    /// The Runtime authenticates the final Graceful record. Governance binds its
    /// exact existing object and Catalog basis before allowing a snapshot stage.
    pub fn record_upgrade_drain(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        evidence: UpgradeDrainEvidence,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        let mut progress = operation
            .upgrade_progress
            .ok_or(DurableOperationFailure::InvalidState)?;
        if let Some(existing) = progress.drain {
            return if existing == evidence {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if operation.status != DurableOperationStatus::Running
            || progress.stage != UpgradeStage::Draining
            || snapshot.number() != evidence.catalog_generation()
            || snapshot.identity().to_bytes() != evidence.catalog_identity()
            || !snapshot
                .object_identities()
                .any(|id| id.to_bytes() == evidence.marker_identity())
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        progress.drain = Some(evidence);
        progress.stage = UpgradeStage::Snapshot;
        operation.upgrade_progress = Some(progress);
        operation.phase = UpgradeStage::Snapshot.phase();
        operation.progress_percent = UpgradeStage::Snapshot.progress();
        update(&mut operation, now)?;
        publish(catalog, &snapshot, operation)
    }
    /// Only succeeded Catalog-backed Backup and independent verification owners
    /// can supply the recovery receipt; callers cannot manufacture a receipt.
    pub fn record_upgrade_snapshot(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        backup_id: OperationId,
        verification_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        let mut progress = operation
            .upgrade_progress
            .ok_or(DurableOperationFailure::InvalidState)?;
        if let Some(existing) = progress.snapshot {
            return if existing.operation_id() == backup_id
                && existing.verification_operation_id() == verification_id
            {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if operation.status != DurableOperationStatus::Running
            || progress.stage != UpgradeStage::Snapshot
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let backup =
            find_by_id(&snapshot, backup_id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        let verification = find_by_id(&snapshot, verification_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        let expected = operation
            .upgrade_parameters()
            .ok_or(DurableOperationFailure::InvalidState)?
            .backup();
        let receipt = backup
            .backup_receipt()
            .ok_or(DurableOperationFailure::InvalidState)?;
        let verified = verification
            .backup_verification_parameters()
            .ok_or(DurableOperationFailure::InvalidState)?;
        let drain = progress
            .drain
            .ok_or(DurableOperationFailure::InvalidState)?;
        if backup.status() != DurableOperationStatus::Succeeded
            || verification.status() != DurableOperationStatus::Succeeded
            || backup.backup_parameters() != Some(expected)
            || verified.repository() != expected.repository()
            || verified.manifest_checksum() != receipt.manifest()
            || verification.backup_verification_report().is_none()
            || backup.target_identity() != operation.target_identity()
            || verification.target_identity() != operation.target_identity()
            || backup.request.accepted_generation() < drain.catalog_generation()
            || receipt.catalog_generation() < backup.request.accepted_generation()
            || !snapshot
                .object_identities()
                .any(|id| id.to_bytes() == drain.marker_identity())
            || (receipt.catalog_generation() == drain.catalog_generation()
                && receipt.catalog_identity() != drain.catalog_identity())
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        progress.snapshot = Some(UpgradeSnapshotEvidence {
            operation: backup_id,
            verification: verification_id,
            receipt,
        });
        operation.upgrade_progress = Some(progress);
        update(&mut operation, now)?;
        publish(catalog, &snapshot, operation)
    }
    pub fn fail_upgrade(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        if operation.status() == DurableOperationStatus::Failed {
            return Ok(operation);
        }
        let failed = operation.failed(now, DurableOperationTerminalError::HandlerRejected)?;
        if failed.irreversible_boundary() == DurableOperationBoundary::CatalogGenerationPublished {
            upgrade_publication::publish_current(catalog, &snapshot, failed)
        } else {
            publish(catalog, &snapshot, failed)
        }
    }
    pub fn cancel_upgrade(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        key: AdministrativeIdempotencyKey,
        revision: u64,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        if operation.cancellation_idempotency_key() == Some(key) {
            return Ok(operation);
        }
        if has_other_cancellation_key(&snapshot, id, key)? {
            return Err(DurableOperationFailure::IdempotencyConflict);
        }
        if operation.revision() != revision {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        if operation.status().is_terminal()
            || operation.boundary != DurableOperationBoundary::NotCrossed
        {
            return Err(DurableOperationFailure::CancellationUnavailable);
        }
        operation.status = DurableOperationStatus::Cancelled;
        operation.phase = DurableOperationPhase::Cancelled;
        operation.progress_percent = 0;
        operation.retry = DurableOperationRetry::Never;
        operation.cancellation = DurableOperationCancellation::Cancelled;
        operation.cancellation_idempotency = Some(key);
        operation.completed_at_unix_seconds = Some(now);
        update(&mut operation, now)?;
        publish(catalog, &snapshot, operation)
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
    if operation.kind() != DurableOperationKind::Upgrade {
        return Err(DurableOperationFailure::InvalidState);
    }
    Ok((snapshot, operation))
}
pub(super) fn update(
    operation: &mut DurableOperation,
    now: u64,
) -> Result<(), DurableOperationFailure> {
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
