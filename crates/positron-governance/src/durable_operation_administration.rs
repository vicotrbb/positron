//! Administration-owned durable-operation persistence and lifecycle transitions.
//!
//! Request/state types and the persisted codec live in focused child modules; this
//! module owns the Catalog publication authority and public administration seam.

use positron_domain::identity::{PrincipalId, Scope};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogObjectId, CatalogProposal,
    CatalogSnapshot, FormatEpoch, PreparedTransactionResolution, TransactionId,
};
use sha2::{Digest, Sha256};

mod abandonment;
mod backup_administration;
mod backup_parameters;
mod backup_retention_administration;
mod backup_verification_administration;
pub use backup_parameters::{
    BackupCleanupReceipt, BackupOperationParameters, BackupOperationReceipt, BackupOperationStage,
    BackupRetentionClaimReceipt, BackupRetentionParameters, BackupRetentionStage,
    BackupSnapshotParameters, BackupVerificationParameters,
};
mod codec;
mod provider_migration_parameters;
pub use provider_migration_parameters::{
    KeyProviderMigrationAction, KeyProviderMigrationParameters,
};
mod repository_administration;
mod repository_parameters;
mod repository_policy_codec;
pub use repository_parameters::{
    RepositoryAction, RepositoryOperationParameters, RepositoryProviderKind,
};
mod types;

#[cfg(fuzzing)]
pub use codec::fuzz_durable_operation_record;
#[cfg(test)]
pub(crate) use codec::pending_operation_fixture;
pub use types::{
    DurableOperation, DurableOperationBoundary, DurableOperationCancellation,
    DurableOperationFailure, DurableOperationKind, DurableOperationLookupRetention,
    DurableOperationPhase, DurableOperationRequest, DurableOperationRetry, DurableOperationStatus,
    DurableOperationTerminalError, DurableQueryBudgetDimension, DurableQueryExportFailure,
    DurableQueryExportFailureCode, OperationId,
};

use crate::AdministrativeIdempotencyKey;
use codec::{
    ExpiredOperationBinding, decode_expired_binding, decode_operation, encode_audit,
    encode_expired_binding, encode_operation,
};

const MAX_OPERATION_RECORDS: usize = 1_024;

/// Administration owns durable records; Catalog owns their sole publication point.
pub struct DurableOperationAdministration;

impl DurableOperationAdministration {
    /// Bounded recovery cursor over accepted root-provider work. The Catalog
    /// operation record remains the sole owner of the action and parameters.
    pub fn next_key_provider_migration_operation(
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
            if operation.kind() != DurableOperationKind::KeyProviderMigration
                || operation.status().is_terminal()
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
    /// Reattaches a background handler to its accepted Principal after restart.
    /// The authenticated Catalog operation and current durable credential grant
    /// are both checked before returning the narrow administration context.
    pub fn resume_key_provider_migration_actor(
        catalog: &Catalog<'_>,
        operation_id: OperationId,
        now: u64,
    ) -> Result<crate::AuthorizedContext, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        if operation.kind() != DurableOperationKind::KeyProviderMigration {
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
    /// Accepts or exactly replays a catalog-format operation before draining work.
    pub fn accept_catalog_format_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
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
        let operation = DurableOperation::accepted(request);
        if let Some(resumed) = resume_prepared_operation(
            catalog,
            transition_transaction(operation)?,
            transition_request_digest(operation),
            operation.operation_id(),
        )? {
            return Ok(resumed);
        }
        if snapshot.format_epoch() != Some(FormatEpoch::CATALOG_V1) {
            return Err(DurableOperationFailure::InvalidState);
        }
        if snapshot.number() != request.accepted_generation() {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        publish(catalog, &snapshot, operation)
    }

    /// Accepts or exactly replays a root-provider phase before provider work.
    pub fn accept_key_provider_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: KeyProviderMigrationParameters,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind != DurableOperationKind::KeyProviderMigration
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
        let mut operation = DurableOperation::accepted(request);
        operation.key_provider_migration_parameters = Some(parameters);
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
        publish(catalog, &snapshot, operation)
    }

    /// Atomically accepts exact native Repository work before provider access.
    /// Accepts or exactly replays an authenticated tenant Query export.
    ///
    /// The Query module owns the typed plan, snapshot, output receipt, and
    /// resume checkpoint. Administration owns the durable operation lifecycle
    /// and its jointly committed governance evidence.
    pub fn accept_query_export(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_query_actor(actor, request.principal, request.applicable_tenant)?;
        if request.kind != DurableOperationKind::QueryExport {
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
        let operation = DurableOperation::accepted(request);
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
        publish(catalog, &snapshot, operation)
    }

    /// Reattaches after restart without inferring a failed caller outcome.
    pub fn inspect(
        catalog: &Catalog<'_>,
        operation_id: OperationId,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        find_by_id(&catalog.pin().map_err(map_catalog)?, operation_id)
    }

    /// Returns one operation only to its system-administration creator.
    pub fn inspect_authorized(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        let operation = Self::inspect(catalog, operation_id)?;
        if let Some(operation) = operation {
            validate_system_actor(actor, operation.request.principal)?;
        }
        Ok(operation)
    }

    /// Resolves a stable accepted operation before callers construct a retry.
    pub fn inspect_by_idempotency(
        catalog: &Catalog<'_>,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        match find_by_key(&catalog.pin().map_err(map_catalog)?, idempotency)? {
            Some(OperationKeyLookup::Operation(operation)) => Ok(Some(*operation)),
            Some(OperationKeyLookup::Expired(_)) | None => Ok(None),
        }
    }

    /// Persists preflight and the actual upcoming Catalog reservation requirement.
    pub fn begin(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.begin(now)?)
    }

    /// Begins an accepted tenant Query export after its caller has supplied a
    /// current tenant-query authorization context.
    pub fn begin_query_export(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_query_actor(
            actor,
            operation.request.principal,
            operation.request.applicable_tenant,
        )?;
        if operation.request.kind != DurableOperationKind::QueryExport {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(catalog, &snapshot, operation.begin(now)?)
    }

    /// Crosses the Query-export cancellation boundary immediately before the
    /// first protected result batch becomes durable. This transition contains
    /// no payload; the Query module retains ownership of payload writes.
    pub fn drain_query_export(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_query_actor(
            actor,
            operation.request.principal,
            operation.request.applicable_tenant,
        )?;
        if operation.request.kind != DurableOperationKind::QueryExport {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(catalog, &snapshot, operation.draining(now)?)
    }

    /// Persists that the handler is closing admission before waiting for its drain.
    pub fn mark_draining(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.draining(now)?)
    }

    /// Records completion of admission drain before Catalog publication begins.
    pub fn mark_drained(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.drained(now)?)
    }

    /// Records the existing handler's published V2 Catalog generation as the irreversible boundary.
    pub fn succeed_catalog_format_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if snapshot.format_epoch() != Some(FormatEpoch::CATALOG_V2) {
            return Err(DurableOperationFailure::InvalidState);
        }
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.succeeded(now)?)
    }

    /// Records a root-provider phase's authenticated Catalog publication.
    pub fn succeed_key_provider_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::KeyProviderMigration {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(catalog, &snapshot, operation.succeeded(now)?)
    }

    /// Binds one signed Backup Registry publication to its owning root phase.
    /// Backup authenticates the registration format; Governance owns the exact
    /// replacement, current authorization and immutable operation audit record.
    pub fn publish_key_provider_backup_registry(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        previous: CatalogObjectId,
        registration: CatalogObject,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let mut operation =
            find_by_id(&snapshot, id)?.ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::KeyProviderMigration
            || operation.status != DurableOperationStatus::Running
            || operation.phase != DurableOperationPhase::Draining
            || !operation
                .key_provider_migration_parameters
                .is_some_and(|parameters| {
                    matches!(
                        parameters.action(),
                        KeyProviderMigrationAction::Verify | KeyProviderMigrationAction::Retire
                    )
                })
            || snapshot.object(previous).map_err(map_catalog)?.is_none()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if now < operation.updated_at_unix_seconds {
            return Err(DurableOperationFailure::InvalidState);
        }
        operation.boundary = DurableOperationBoundary::BackupRegistryPublished;
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

    /// Commits the terminal success transition after the Query module has
    /// durably published its signed output manifest.
    pub fn succeed_query_export(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_query_actor(
            actor,
            operation.request.principal,
            operation.request.applicable_tenant,
        )?;
        if operation.request.kind != DurableOperationKind::QueryExport {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(catalog, &snapshot, operation.succeeded(now)?)
    }

    /// Fails only an accepted root operation whose original grant is currently
    /// denied. This cannot mint an authorization context or reject valid work.
    pub fn reject_key_provider_migration_authorization(
        catalog: &Catalog<'_>,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        if operation.kind() != DurableOperationKind::KeyProviderMigration
            || operation.target_identity()
                != Some(
                    snapshot
                        .governance_object()
                        .map_err(map_catalog)?
                        .1
                        .instance(),
                )
            || operation.status().is_terminal()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let identity = crate::Identity::open(&snapshot)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        if identity
            .resume_system_operation_actor(
                operation.request.principal,
                snapshot
                    .governance_object()
                    .map_err(map_catalog)?
                    .1
                    .instance(),
                now,
            )
            .is_ok()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let operation = if operation.status() == DurableOperationStatus::Pending {
            operation.begin(now)?
        } else {
            operation
        };
        publish(
            catalog,
            &snapshot,
            operation.failed(now, DurableOperationTerminalError::HandlerRejected)?,
        )
    }

    /// Records a definite root-migration precondition rejection. Transport and
    /// publication ambiguity must remain nonterminal for receipt reconciliation.
    pub fn fail_key_provider_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::KeyProviderMigration {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(
            catalog,
            &snapshot,
            operation.failed(now, DurableOperationTerminalError::HandlerRejected)?,
        )
    }

    /// Persists a known terminal handler rejection. Ambiguous persistence and
    /// crash outcomes remain non-terminal so restart can reattach safely.
    pub fn fail_catalog_format_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
        error: DurableOperationTerminalError,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        publish(catalog, &snapshot, operation.failed(now, error)?)
    }

    /// Persists a known terminal Query-export failure without converting an
    /// ambiguous output acknowledgement into a false terminal result.
    pub fn fail_query_export(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
        error: DurableOperationTerminalError,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_query_actor(
            actor,
            operation.request.principal,
            operation.request.applicable_tenant,
        )?;
        if operation.request.kind != DurableOperationKind::QueryExport {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(catalog, &snapshot, operation.failed(now, error)?)
    }

    /// Commits an incomplete terminal Query export only after its signed
    /// manifest is durable, preserving that crossed publication boundary in
    /// the public operation record.
    pub fn fail_published_query_export(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
        error: DurableOperationTerminalError,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_query_actor(
            actor,
            operation.request.principal,
            operation.request.applicable_tenant,
        )?;
        if operation.request.kind != DurableOperationKind::QueryExport {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(
            catalog,
            &snapshot,
            operation.failed_after_manifest_publication(now, error)?,
        )
    }

    /// Cancels a root migration phase with exact generation-bound replay.
    pub fn cancel_key_provider_migration(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        idempotency: AdministrativeIdempotencyKey,
        expected_generation: u64,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::KeyProviderMigration
            || operation.target_identity()
                != Some(
                    snapshot
                        .governance_object()
                        .map_err(map_catalog)?
                        .1
                        .instance(),
                )
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if operation.cancellation_idempotency_key() == Some(idempotency) {
            let commit = catalog
                .confirm_committed_transaction(transition_transaction(operation)?)
                .map_err(map_catalog)?
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
            if commit.number().checked_sub(1) != Some(expected_generation) {
                return Err(DurableOperationFailure::IdempotencyConflict);
            }
            return Ok(operation);
        }
        if snapshot.number() != expected_generation {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        Self::cancel(catalog, actor, operation_id, idempotency, now)
    }

    /// Cancels only at the documented pre-drain cancellation point.
    pub fn cancel(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        idempotency: AdministrativeIdempotencyKey,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if matches!(
            operation.kind(),
            DurableOperationKind::BackupSnapshot | DurableOperationKind::BackupVerification
        ) {
            return Err(DurableOperationFailure::InvalidState);
        }
        let cancelled = operation.cancelled(now, idempotency)?;
        if cancelled == operation {
            return Ok(operation);
        }
        if has_other_cancellation_key(&snapshot, operation_id, idempotency)? {
            return Err(DurableOperationFailure::IdempotencyConflict);
        }
        publish(catalog, &snapshot, cancelled)
    }

    /// Cancels a tenant Query export only before its irreversible output
    /// publication boundary, with the same durable idempotency semantics.
    pub fn cancel_query_export(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        idempotency: AdministrativeIdempotencyKey,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_query_actor(
            actor,
            operation.request.principal,
            operation.request.applicable_tenant,
        )?;
        if operation.request.kind != DurableOperationKind::QueryExport {
            return Err(DurableOperationFailure::InvalidState);
        }
        let cancelled = operation.cancelled(now, idempotency)?;
        if cancelled == operation {
            return Ok(operation);
        }
        if has_other_cancellation_key(&snapshot, operation_id, idempotency)? {
            return Err(DurableOperationFailure::IdempotencyConflict);
        }
        publish(catalog, &snapshot, cancelled)
    }
}

fn has_other_cancellation_key(
    snapshot: &CatalogSnapshot,
    operation_id: OperationId,
    idempotency: AdministrativeIdempotencyKey,
) -> Result<bool, DurableOperationFailure> {
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let Some(operation) = decode_operation(bytes)? else {
            continue;
        };
        if operation.operation_id() != operation_id
            && operation.cancellation_idempotency_key() == Some(idempotency)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_system_actor(
    actor: crate::AuthorizedContext,
    principal: PrincipalId,
) -> Result<(), DurableOperationFailure> {
    if actor.principal_id() != principal
        || actor.scope() != Scope::SystemAdministration
        || actor.tenant_attribution().is_some()
    {
        return Err(DurableOperationFailure::Unauthorized);
    }
    Ok(())
}

fn validate_query_actor(
    actor: crate::AuthorizedContext,
    principal: PrincipalId,
    tenant: Option<positron_domain::identity::TenantId>,
) -> Result<(), DurableOperationFailure> {
    if actor.principal_id() != principal
        || actor.scope() != Scope::Query
        || actor
            .tenant_attribution()
            .map(|attribution| attribution.tenant_id())
            != tenant
    {
        return Err(DurableOperationFailure::Unauthorized);
    }
    Ok(())
}

fn exact_replay(
    existing: DurableOperation,
    request: DurableOperationRequest,
) -> Result<DurableOperation, DurableOperationFailure> {
    existing
        .request
        .has_same_semantics(request)
        .then_some(existing)
        .ok_or(DurableOperationFailure::IdempotencyConflict)
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> DurableOperationFailure {
    match failure.code() {
        CatalogFailureCode::StaleGeneration => DurableOperationFailure::StaleGeneration,
        CatalogFailureCode::IdempotencyConflict => DurableOperationFailure::IdempotencyConflict,
        CatalogFailureCode::LimitExceeded => DurableOperationFailure::CapacityExceeded,
        _ => DurableOperationFailure::PersistenceUnavailable,
    }
}

fn publish(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    operation: DurableOperation,
) -> Result<DurableOperation, DurableOperationFailure> {
    publish_with_additions(catalog, snapshot, operation, Vec::new())
}
fn publish_with_additions(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    operation: DurableOperation,
    additional: Vec<CatalogObject>,
) -> Result<DurableOperation, DurableOperationFailure> {
    publish_with_objects(catalog, snapshot, operation, additional, None)
}
fn publish_with_objects(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    operation: DurableOperation,
    additional: Vec<CatalogObject>,
    replacement: Option<CatalogObjectId>,
) -> Result<DurableOperation, DurableOperationFailure> {
    let transaction = transition_transaction(operation)?;
    let mut request_digest = transition_request_digest(operation);
    if let Some(previous) = replacement {
        if additional.len() != 1 || snapshot.object(previous).map_err(map_catalog)?.is_none() {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let mut hash = Sha256::new();
        hash.update(b"positron.backup.registration-publication.v1\0");
        hash.update(request_digest);
        hash.update(previous.to_bytes());
        for object in &additional {
            hash.update(object.identity().to_bytes());
        }
        request_digest = hash.finalize().into();
    }
    if let Some(resumed) = resume_prepared_operation(
        catalog,
        transaction,
        request_digest,
        operation.operation_id(),
    )? {
        return Ok(resumed);
    }
    let mut objects = retained_objects(
        snapshot,
        operation.operation_id(),
        operation.updated_at_unix_seconds,
    )?;
    if let Some(previous) = replacement {
        objects.retain(|object| object.identity() != previous);
    }
    objects
        .try_reserve(1)
        .map_err(|_| DurableOperationFailure::CapacityExceeded)?;
    for object in additional {
        if snapshot
            .object(object.identity())
            .map_err(map_catalog)?
            .is_none()
        {
            objects.push(object);
        }
    }
    objects.push(CatalogObject::new(encode_operation(operation)).map_err(map_catalog)?);
    let audit = AuditIntent::new(encode_audit(operation)?).map_err(map_catalog)?;
    let proposal = CatalogProposal::new(
        transaction,
        snapshot
            .format_epoch()
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        objects,
    )
    .map_err(map_catalog)?;
    match catalog.commit_prepared(snapshot.identity(), proposal, audit, request_digest) {
        Ok(commit) => operation_from_snapshot(commit.snapshot(), operation.operation_id()),
        Err(failure) if failure.code() == CatalogFailureCode::IdempotencyConflict => {
            resume_prepared_operation(
                catalog,
                transaction,
                request_digest,
                operation.operation_id(),
            )?
            .ok_or(DurableOperationFailure::IdempotencyConflict)
        },
        Err(failure) => Err(map_catalog(failure)),
    }
}

fn resume_prepared_operation(
    catalog: &Catalog<'_>,
    transaction: TransactionId,
    request_digest: [u8; 32],
    operation_id: OperationId,
) -> Result<Option<DurableOperation>, DurableOperationFailure> {
    match catalog
        .resume_prepared(transaction, request_digest)
        .map_err(map_catalog)?
    {
        PreparedTransactionResolution::Absent => Ok(None),
        PreparedTransactionResolution::Unavailable => {
            Err(DurableOperationFailure::PersistenceUnavailable)
        },
        PreparedTransactionResolution::Resumed(commit) => {
            operation_from_snapshot(commit.snapshot(), operation_id).map(Some)
        },
    }
}

fn operation_from_snapshot(
    snapshot: &CatalogSnapshot,
    operation_id: OperationId,
) -> Result<DurableOperation, DurableOperationFailure> {
    find_by_id(snapshot, operation_id)?.ok_or(DurableOperationFailure::PersistenceUnavailable)
}

fn transition_request_digest(operation: DurableOperation) -> [u8; 32] {
    // The prepared proposal owns its first transition timestamp. Bind every
    // semantic transition field while leaving that timestamp free to reattach
    // the exact staged payload after an acknowledgement-ambiguous failure.
    let mut hasher = Sha256::new();
    hasher.update(b"positron.durable-operation.transition-request.v1\0");
    hasher.update(operation.operation_id().to_bytes());
    hasher.update(operation.revision.to_be_bytes());
    hasher.update(operation.request.canonical_digest());
    if let Some(receipt) = operation.backup_receipt() {
        let mut bytes = Vec::new();
        receipt.encode(&mut bytes);
        hasher.update(bytes);
    }
    if let Some(receipt) = operation.backup_cleanup_receipt() {
        let mut bytes = Vec::new();
        receipt.encode(&mut bytes);
        hasher.update([2]);
        hasher.update(bytes);
    }
    if let Some(report) = operation.backup_verification_report() {
        hasher.update([4]);
        hasher.update(report);
    }
    if let Some(receipt) = operation.backup_retention_claim() {
        hasher.update([3]);
        hasher.update(receipt.registry_generation());
    }
    hasher.update([operation.status.code()]);
    hasher.update([operation.phase.code()]);
    hasher.update([operation.progress_percent]);
    hasher.update([operation.retry.code()]);
    hasher.update([operation.cancellation.code()]);
    hasher.update([operation.boundary.code()]);
    let (terminal_error, terminal_detail) = operation
        .terminal_error
        .map_or((0, 0), DurableOperationTerminalError::encoded);
    hasher.update([terminal_error, terminal_detail]);
    match operation.cancellation_idempotency {
        Some(idempotency) => {
            hasher.update([1]);
            hasher.update(idempotency.to_bytes());
        },
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn retained_objects(
    snapshot: &CatalogSnapshot,
    replace: OperationId,
    now: u64,
) -> Result<Vec<CatalogObject>, DurableOperationFailure> {
    let mut objects = Vec::new();
    objects
        .try_reserve(snapshot.object_count())
        .map_err(|_| DurableOperationFailure::CapacityExceeded)?;
    let mut operation_count = 0_usize;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        if let Some(operation) = decode_operation(bytes)? {
            if operation.operation_id() == replace {
                continue;
            }
            if operation
                .earliest_lookup_expiry_unix_seconds()
                .is_some_and(|expiry| expiry <= now)
            {
                let live_backup_owner = match operation.backup_binding() {
                    Some(parameters) => positron_kernel::RepositoryOperationBinding::new(
                        operation.operation_id().to_bytes(),
                        parameters.intent_digest(),
                    )
                    .and_then(|binding| binding.has_live_backup_owner(snapshot))
                    .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?,
                    None => false,
                };
                if !live_backup_owner {
                    objects.push(
                        CatalogObject::new(encode_expired_binding(operation.request))
                            .map_err(map_catalog)?,
                    );
                    continue;
                }
            }
            operation_count = operation_count
                .checked_add(1)
                .ok_or(DurableOperationFailure::CapacityExceeded)?;
            if operation_count >= MAX_OPERATION_RECORDS {
                return Err(DurableOperationFailure::CapacityExceeded);
            }
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog)?);
    }
    Ok(objects)
}

fn find_by_id(
    snapshot: &CatalogSnapshot,
    operation_id: OperationId,
) -> Result<Option<DurableOperation>, DurableOperationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let Some(operation) = decode_operation(bytes)? else {
            continue;
        };
        if operation.operation_id() == operation_id && found.replace(operation).is_some() {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

enum OperationKeyLookup {
    Operation(Box<DurableOperation>),
    Expired(ExpiredOperationBinding),
}

fn find_by_key(
    snapshot: &CatalogSnapshot,
    key: AdministrativeIdempotencyKey,
) -> Result<Option<OperationKeyLookup>, DurableOperationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        if let Some(operation) = decode_operation(bytes)? {
            if operation.request.idempotency == key
                && found
                    .replace(OperationKeyLookup::Operation(Box::new(operation)))
                    .is_some()
            {
                return Err(DurableOperationFailure::PersistenceUnavailable);
            }
            continue;
        }
        if let Some(binding) = decode_expired_binding(bytes)?
            && binding.request.idempotency == key
            && found
                .replace(OperationKeyLookup::Expired(binding))
                .is_some()
        {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
    }
    Ok(found)
}

fn transition_transaction(
    operation: DurableOperation,
) -> Result<TransactionId, DurableOperationFailure> {
    TransactionId::new(transition_transaction_bytes(
        operation.operation_id(),
        operation.revision,
    )?)
    .map_err(map_catalog)
}

/// Returns the canonical transaction identity for one durable-operation transition.
pub(crate) fn transition_transaction_bytes(
    operation_id: OperationId,
    revision: u64,
) -> Result<[u8; 16], DurableOperationFailure> {
    let mut hasher = Sha256::new();
    hasher.update(b"positron.durable-operation.transition.v1\0");
    hasher.update(operation_id.to_bytes());
    hasher.update(revision.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let Some(bytes) = digest.first_chunk::<16>() else {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    };
    Ok(*bytes)
}
