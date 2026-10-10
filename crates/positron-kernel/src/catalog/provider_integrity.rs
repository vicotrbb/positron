//! Data Protection integrity events use the existing governed Catalog commit.
use super::*;
use crate::data_protection::DataProtection;
use crate::data_protection::key_provider::{EnvelopeContext, KeyProviderFailure, KeyScope};
impl Catalog<'_> {
    pub(crate) fn provider_reservation_matches(
        &self,
        reservation: &crate::ResourceReservation<'_>,
    ) -> bool {
        reservation.belongs_to(self.authority.governor())
    }
    pub(crate) fn publish_provider_integrity_failure(
        &self,
        context: EnvelopeContext,
        failure: KeyProviderFailure,
    ) -> Result<u64, CatalogFailure> {
        let classification = match failure {
            KeyProviderFailure::ContextMismatch => 1,
            KeyProviderFailure::WrongKey => 2,
            _ => return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput)),
        };
        let snapshot = self.pin()?;
        let format = snapshot
            .format_epoch()
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?;
        let _proposal_reservation = self.reserve_catalog_proposal_copy(&snapshot)?;
        let mut event = Vec::with_capacity(96);
        event.extend_from_slice(b"PKEYAUD1");
        event.extend_from_slice(&self.instance.to_bytes());
        match context.scope {
            KeyScope::System => event.extend_from_slice(&[0; 17]),
            KeyScope::Tenant(tenant) => {
                event.push(1);
                event.extend_from_slice(&tenant.to_bytes());
            },
        }
        event.extend_from_slice(&context.key_id);
        event.extend_from_slice(&context.epoch.to_be_bytes());
        event.extend_from_slice(&context.format.to_be_bytes());
        event.push(classification);
        let random = DataProtection::random_identifier()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        let transaction = TransactionId::new(
            random
                .get(..16)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?,
        )?;
        let objects = snapshot
            .plaintext_objects()
            .map(|object| CatalogObject::new(object.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        let commit = self.commit(
            snapshot.identity(),
            CatalogProposal::new(transaction, format, objects)?,
            Some(AuditIntent::new(event)?),
        )?;
        commit
            .governance_audit_record()
            .map(GovernanceAuditRecord::position)
            .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
    }
}
