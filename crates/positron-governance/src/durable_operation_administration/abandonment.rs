//! One bounded irreversible publication, with the operation and audit in the
//! same Catalog transaction as removal of the live segment reference.

use super::*;
use positron_kernel::{SegmentAbandonmentPlan, SegmentId, SegmentScope};

impl DurableOperationAdministration {
    pub fn abandon_segment(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        scope: SegmentScope,
        request: DurableOperationRequest,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind != DurableOperationKind::SegmentAbandonment
            || request.applicable_tenant != Some(scope.tenant_id())
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        if let Some(existing) = find_by_key(&snapshot, request.idempotency)? {
            return match existing {
                OperationKeyLookup::Operation(operation) => exact_replay(operation, request),
                OperationKeyLookup::Expired(binding) => {
                    binding.exact_replay(request)?;
                    Err(DurableOperationFailure::CompletedLookupExpired)
                },
            };
        }
        let now = request.accepted_at_unix_seconds;
        let operation = DurableOperation::accepted(request)
            .begin(now)?
            .succeeded(now)?;
        let transaction = transition_transaction(operation)?;
        let request_digest = transition_request_digest(operation);
        if let Some(resumed) = resume_prepared_operation(
            catalog,
            transaction,
            request_digest,
            operation.operation_id(),
        )? {
            return Ok(resumed);
        }
        if snapshot.number() != request.accepted_generation {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        let segment = SegmentId::from_bytes(
            request
                .target_identity
                .ok_or(DurableOperationFailure::InvalidInput)?,
        )
        .map_err(|_| DurableOperationFailure::InvalidInput)?;
        let plan = SegmentAbandonmentPlan::preflight(&snapshot, scope, segment)
            .map_err(|_| DurableOperationFailure::InvalidState)?;
        // Reuse the operation registry's bounded admission and expiry rules.
        let finding = plan.finding();
        let retained = retained_objects(&snapshot, operation.operation_id(), now)?;
        let mut objects = plan
            .confirm(
                request
                    .query_export_request_digest
                    .ok_or(DurableOperationFailure::InvalidInput)?,
            )
            .map_err(|_| DurableOperationFailure::InvalidInput)?;
        // Replace only durable-operation records by their registry-selected
        // retained forms. All other objects remain the kernel's exact proposal.
        let mut registry_ids = std::collections::BTreeSet::new();
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(map_catalog)?
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
            if decode_operation(bytes)?.is_some() || decode_expired_binding(bytes)?.is_some() {
                registry_ids.insert(id);
            }
        }
        objects.retain(|object| !registry_ids.contains(&object.identity()));
        for object in retained {
            let original = snapshot.object(object.identity()).map_err(map_catalog)?;
            if original.is_none() || registry_ids.contains(&object.identity()) {
                objects.push(object);
            }
        }
        objects
            .try_reserve(1)
            .map_err(|_| DurableOperationFailure::CapacityExceeded)?;
        objects.push(CatalogObject::new(encode_operation(operation)).map_err(map_catalog)?);
        let encoded = encode_audit(operation);
        let length =
            u16::try_from(encoded.len()).map_err(|_| DurableOperationFailure::CapacityExceeded)?;
        let evidence = finding
            .encode_evidence()
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        let audit = AuditIntent::new(
            [
                b"POSABL01".as_slice(),
                &length.to_be_bytes(),
                &encoded,
                &evidence,
            ]
            .concat(),
        )
        .map_err(map_catalog)?;
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
}
