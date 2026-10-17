//! Resolve accepted Upgrade intent without requiring a still-live repository row.
use super::*;

impl DurableOperationAdministration {
    pub fn replay_upgrade(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        request: DurableOperationRequest,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        validate_system_actor(actor, request.principal)?;
        if request.kind() != DurableOperationKind::Upgrade {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let snapshot = catalog.pin().map_err(map_catalog)?;
        match find_by_key(&snapshot, request.idempotency)? {
            Some(OperationKeyLookup::Operation(operation)) => exact_replay(*operation, request),
            Some(OperationKeyLookup::Expired(binding)) => {
                binding.exact_replay(request)?;
                Err(DurableOperationFailure::CompletedLookupExpired)
            },
            None => Err(DurableOperationFailure::UnknownOperation),
        }
    }
}
