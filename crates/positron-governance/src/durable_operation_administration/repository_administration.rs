//! Administration lifecycle for the closed Repository handler.
use super::*;
impl DurableOperationAdministration {
    pub fn next_repository_operation(
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
            if operation.kind() != DurableOperationKind::RepositoryInspection
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
    pub fn resume_repository_actor(
        catalog: &Catalog<'_>,
        operation_id: OperationId,
        now: u64,
    ) -> Result<crate::AuthorizedContext, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        if operation.kind() != DurableOperationKind::RepositoryInspection {
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
    pub fn accept_repository(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
        parameters: RepositoryOperationParameters,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind != DurableOperationKind::RepositoryInspection
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
        operation.repository_parameters = Some(parameters);
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

    pub fn succeed_repository(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::RepositoryInspection {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(catalog, &snapshot, operation.succeeded(now)?)
    }

    pub fn reject_repository_authorization(
        catalog: &Catalog<'_>,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        if operation.kind() != DurableOperationKind::RepositoryInspection
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

    pub fn fail_repository(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        operation_id: OperationId,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let operation = find_by_id(&snapshot, operation_id)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.kind() != DurableOperationKind::RepositoryInspection {
            return Err(DurableOperationFailure::InvalidState);
        }
        publish(
            catalog,
            &snapshot,
            operation.failed(now, DurableOperationTerminalError::HandlerRejected)?,
        )
    }

    pub fn cancel_repository(
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
        if operation.kind() != DurableOperationKind::RepositoryInspection
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
}
