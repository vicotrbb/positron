//! Reuse requires the exact authenticated source and durable owning transaction.
use super::{Catalog, CatalogRootRotationStage, LocalKeyRotationFailure, State, TransactionId};
use positron_governance::GovernanceAuditEntry;
use positron_kernel::CatalogSnapshot;

pub(super) fn confirm_existing(
    catalog: &Catalog<'_>,
    basis: &CatalogSnapshot,
    state: &State,
) -> Result<bool, LocalKeyRotationFailure> {
    let records = catalog
        .governance_audit_records()
        .map_err(|_| LocalKeyRotationFailure::Authentication)?;
    for record in records.iter().rev() {
        let decoded = GovernanceAuditEntry::decode(record)
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let Some(entry) = decoded.as_catalog_root_rotation() else {
            continue;
        };
        if entry.stage() != CatalogRootRotationStage::Verified
            || entry.provider_key_reference() != state.active.identity.key_id()
            || entry.key_epoch() != state.active.epoch
        {
            return Ok(false);
        }
        let transaction = TransactionId::new(entry.transaction_id())
            .map_err(|_| LocalKeyRotationFailure::Authentication)?;
        let committed = catalog
            .committed_transaction(transaction)
            .map_err(|_| LocalKeyRotationFailure::Storage)?
            .ok_or(LocalKeyRotationFailure::Authentication)?;
        if committed.governance_audit_record() != Some(record)
            || State::find(committed.snapshot())?.as_ref() != Some(state)
            || !committed
                .snapshot()
                .object_identities()
                .eq(basis.object_identities())
        {
            return Ok(false);
        }
        let confirmed = catalog
            .confirm_committed_transaction(transaction)
            .map_err(|_| LocalKeyRotationFailure::Storage)?
            .ok_or(LocalKeyRotationFailure::Authentication)?;
        if confirmed.identity() != committed.identity()
            || catalog
                .pin()
                .map_err(|_| LocalKeyRotationFailure::Storage)?
                .identity()
                != basis.identity()
        {
            return Err(LocalKeyRotationFailure::Busy);
        }
        return Ok(true);
    }
    Ok(false)
}
