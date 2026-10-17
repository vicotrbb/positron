//! Explicit same-format source-artifact recovery uses the original operation.
use super::upgrade_administration::{authorized, update};
use super::*;
impl DurableOperationAdministration {
    /// Runtime must authenticate the installed source artifact and unchanged
    /// quiescent frontiers before requesting this audited release selection.
    pub fn rollback_upgrade(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        key: AdministrativeIdempotencyKey,
        revision: u64,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, mut operation) = authorized(catalog, actor, id)?;
        if let Some(existing) = operation.upgrade_rollback_key() {
            return if existing == key {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if find_by_key(&snapshot, key)?.is_some() || has_other_cancellation_key(&snapshot, id, key)?
        {
            return Err(DurableOperationFailure::IdempotencyConflict);
        }
        if operation.revision() != revision {
            return Err(DurableOperationFailure::StaleGeneration);
        }
        let current = Self::current_upgrade_publication_snapshot(&snapshot)?
            .ok_or(DurableOperationFailure::InvalidState)?;
        if current.operation_id() != id
            || current.is_rollback()
            || !operation.upgrade_rollback_available()
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if operation.status() == DurableOperationStatus::Running {
            operation = operation.failed(now, DurableOperationTerminalError::HandlerRejected)?;
        } else {
            update(&mut operation, now)?;
            operation.completed_at_unix_seconds = Some(now);
        }
        let mut progress = operation
            .upgrade_progress
            .ok_or(DurableOperationFailure::InvalidState)?;
        progress.rollback = Some(key);
        operation.upgrade_progress = Some(progress);
        upgrade_publication::publish_current(catalog, &snapshot, operation)
    }
}
