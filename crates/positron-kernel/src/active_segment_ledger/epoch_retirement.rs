//! Historical reader bindings are inspected under the existing acquisition barrier.
use super::envelope_overlay;
use super::format::decode_metadata;
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode, SegmentProtectionKey};
use crate::{Catalog, RootRewrapSession, StorageKernelResourceAuthority};

/// Pins the existing snapshot-acquisition barrier while managed reader references are inspected.
/// This guard does not constitute migration verification or retirement authorization.
pub struct KeyEpochRetirementGuard<'a> {
    _barrier: std::sync::RwLockWriteGuard<'a, ()>,
    basis: crate::CatalogSnapshot,
    _work: RootRewrapSession<'a>,
}
pub type TenantEpochRetirementGuard<'a> = KeyEpochRetirementGuard<'a>;
impl ActiveSegmentLedger<'_, '_> {
    pub fn guard_local_root_retirement<'a>(
        authority: &'a StorageKernelResourceAuthority,
        catalog: &Catalog<'_>,
    ) -> Result<KeyEpochRetirementGuard<'a>, LedgerFailure> {
        let work = RootRewrapSession::admit(authority)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let barrier = authority
            .snapshot_barrier()
            .try_write()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let basis = catalog.pin()?;
        let _inspection = catalog.reserve_catalog_proposal_copy(&basis)?;
        for bytes in basis.plaintext_objects() {
            if crate::maintenance::durable_task_retains_unproved_root_reference(bytes)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            {
                return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
            }
        }
        Ok(KeyEpochRetirementGuard {
            _barrier: barrier,
            basis,
            _work: work,
        })
    }
    pub fn guard_tenant_epoch_retirement<'a>(
        authority: &'a StorageKernelResourceAuthority,
        catalog: &Catalog<'_>,
        tenant: positron_domain::identity::TenantId,
        protection: &SegmentProtectionKey,
    ) -> Result<TenantEpochRetirementGuard<'a>, LedgerFailure> {
        let work = RootRewrapSession::admit(authority)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let barrier = authority
            .snapshot_barrier()
            .try_write()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let basis = catalog.pin()?;
        let _inspection = catalog.reserve_catalog_proposal_copy(&basis)?;
        // Durable leases retain their original authenticated Catalog basis even
        // after the in-process reader is dropped. Expiry alone is not release.
        for bytes in basis.plaintext_objects() {
            if let Some(metadata) = decode_metadata(bytes)?
                && metadata.scope.tenant_id() == tenant
            {
                // Retired manifests remain managed until the existing
                // reclamation owner durably removes them.
                if metadata.state == super::format::SegmentState::Retired
                    || envelope_overlay::find(
                        &basis,
                        metadata,
                        catalog.instance(),
                        protection.route,
                    )?
                    .is_none()
                {
                    return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
                }
            }
            if crate::maintenance::durable_task_retains_unproved_tenant_reference(
                bytes,
                tenant,
                catalog.instance(),
                protection.route.provider_key_epoch,
                &basis,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            {
                return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
            }
            let Some(record) = super::snapshot_lease_codec::decode(bytes)? else {
                continue;
            };
            if record.scope.tenant_id() != tenant {
                continue;
            }
            let historical = catalog.pin_historical_generation(
                &basis,
                record.catalog_identity,
                record.catalog_generation,
            )?;
            for block in record.blocks {
                require_successor_reference(
                    &historical,
                    catalog.instance(),
                    tenant,
                    block.segment.to_bytes(),
                    protection,
                )?;
            }
        }
        let registry = authority.snapshot_protection();
        let bindings = registry
            .try_lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        for (binding, count) in bindings.iter() {
            if *count == 0 {
                continue;
            }
            let (segment, identity, number) = match binding {
                super::snapshot_protection::SnapshotProtectionBinding::TenantEpoch(
                    owner,
                    epoch,
                ) => {
                    if *owner == tenant.to_bytes() && *epoch != protection.route.provider_key_epoch
                    {
                        return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
                    }
                    continue;
                },
                super::snapshot_protection::SnapshotProtectionBinding::Segment(
                    segment,
                    identity,
                    number,
                ) => (segment, identity, number),
            };
            let historical = catalog.pin_historical_generation(
                &basis,
                crate::CatalogGenerationId::from_authenticated_bytes(*identity),
                *number,
            )?;
            require_successor_reference(
                &historical,
                catalog.instance(),
                tenant,
                *segment,
                protection,
            )?;
        }
        drop(bindings);
        Ok(TenantEpochRetirementGuard {
            _barrier: barrier,
            basis,
            _work: work,
        })
    }
}
fn require_successor_reference(
    basis: &crate::CatalogSnapshot,
    instance: crate::InstanceId,
    tenant: positron_domain::identity::TenantId,
    segment: [u8; 16],
    protection: &SegmentProtectionKey,
) -> Result<(), LedgerFailure> {
    for bytes in basis.plaintext_objects() {
        let Some(metadata) = decode_metadata(bytes)? else {
            continue;
        };
        if metadata.id.to_bytes() != segment {
            continue;
        }
        if metadata.scope.tenant_id() != tenant {
            return Ok(());
        }
        if envelope_overlay::find(basis, metadata, instance, protection.route)?.is_none() {
            return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
        }
        return Ok(());
    }
    Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}

impl KeyEpochRetirementGuard<'_> {
    /// The exact authenticated basis that publication must still match.
    pub fn catalog_basis(&self) -> &crate::CatalogSnapshot {
        &self.basis
    }
}
