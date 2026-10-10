//! One admitted immutable header and one additive Catalog envelope per request.
use super::envelope_overlay;
use super::format::{SegmentMetadata, SegmentState, decode_metadata};
use super::storage::LedgerStorage;
use super::{
    ActiveSegmentLedger, LedgerFailure, LedgerFailureCode, SegmentProtectionKey, SegmentScope,
};
use crate::{
    AuditIntent, Catalog, CatalogObject, CatalogProposal, RootRewrapSession,
    StorageKernelResourceAuthority, TransactionId,
};

impl ActiveSegmentLedger<'_, '_> {
    /// Adds exactly one successor envelope, preserving every immutable frame and header.
    pub fn migrate_next_envelope(
        authority: &StorageKernelResourceAuthority,
        catalog: &Catalog<'_>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        transaction: TransactionId,
        audit: Option<AuditIntent>,
    ) -> Result<bool, LedgerFailure> {
        let _work = RootRewrapSession::admit(authority)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let basis = catalog.pin()?;
        let mut selected = None;
        for bytes in basis.plaintext_objects() {
            let Some(metadata) = decode_metadata(bytes)? else {
                continue;
            };
            if metadata.scope != scope || metadata.state == SegmentState::Retired {
                continue;
            }
            if envelope_overlay::find(&basis, metadata, catalog.instance(), protection.route)?
                .is_some()
            {
                continue;
            }
            if selected.is_none_or(|current: SegmentMetadata| metadata.id < current.id) {
                selected = Some(metadata);
            }
        }
        let Some(metadata) = selected else {
            return Ok(false);
        };
        let _copy = catalog.reserve_catalog_proposal_copy(&basis)?;
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open_observed(volume)?;
        let (encoded, migrated) =
            storage.successor_envelope(metadata, &protection, catalog.instance(), &basis)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(
                basis
                    .object_count()
                    .checked_add(1)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        for id in basis.object_identities() {
            let bytes = basis
                .object(id)?
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
        objects.push(CatalogObject::new(encoded)?);
        let proposal = CatalogProposal::new(
            transaction,
            basis
                .format_epoch()
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))?,
            objects,
        )?;
        catalog.commit(
            basis.identity(),
            proposal,
            if migrated { audit } else { None },
        )?;
        Ok(migrated)
    }
}
