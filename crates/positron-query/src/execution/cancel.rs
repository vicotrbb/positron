use crate::{
    QueryCancellationFailure, QueryCursor, QueryFailure, QueryFailureCode, QueryService, cursor,
};
use positron_governance::AuthorizedContext;
use positron_kernel::SnapshotLeaseId;

impl QueryService<'_, '_, '_> {
    /// Authenticates current authority and idempotently releases the cursor's
    /// original snapshot leases. No query is executed and no cursor is advanced.
    pub fn cancel_cursor(
        &self,
        context: AuthorizedContext,
        cursor: &QueryCursor,
    ) -> Result<(), QueryCancellationFailure> {
        let (tenant, _, _) = self.current_query_catalog(context)?;
        let state = cursor::decode_for_admission(&self.ledger.control_tokens(), cursor)?;
        crate::execution_state::validate_authorization(
            state.principal,
            state.tenant,
            state.authorization_generation,
            context.principal_id(),
            tenant,
            context.authorization_generation(),
        )?;
        let source = SnapshotLeaseId::new(state.lease_identity)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let target = if let Some(identity) = state.trace_lease_identity {
            let ledger = self
                .trace_ledger
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            if ledger.scope().tenant_id() != tenant
                || ledger.scope().signal_kind() != positron_domain::routing::SignalKind::Traces
            {
                return Err(QueryFailure::new(QueryFailureCode::Unauthorized).into());
            }
            Some((
                ledger,
                SnapshotLeaseId::new(identity)
                    .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
            ))
        } else {
            None
        };
        let target_released = target.is_some();
        if let Some((ledger, identity)) = target {
            release_cancelled_lease(ledger, self.maintenance, identity)?;
        }
        release_cancelled_lease(self.ledger, self.maintenance, source).map_err(|failure| {
            if target_released {
                failure.after_partial_effect()
            } else {
                failure
            }
        })
    }
}

pub(crate) fn release_cancelled_lease(
    ledger: &positron_kernel::ActiveSegmentLedger<'_, '_>,
    maintenance: Option<&positron_kernel::MaintenanceCoordinator>,
    identity: SnapshotLeaseId,
) -> Result<(), QueryCancellationFailure> {
    let result = match maintenance {
        Some(coordinator) => ledger.release_snapshot_lease_with_expiry_task(coordinator, identity),
        None => ledger.release_snapshot_lease(identity),
    };
    result.map_err(|failure| {
        let completion = failure.completion_state();
        QueryCancellationFailure::new(
            crate::execution_support::map_ledger_failure(failure).code(),
            completion,
        )
    })
}
