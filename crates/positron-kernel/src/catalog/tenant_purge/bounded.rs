use super::*;
use crate::TransferredResourceReservation;

/// Retained bounded directory traversal; drop/restart before publication is safe.
pub struct TenantKeyInventory {
    instance: InstanceId,
    tenant: TenantId,
    proof: [u8; 32],
    scan: storage::tenant_purge_inventory::KeyInventory,
    _reservation: TransferredResourceReservation,
}
pub enum TenantKeyInventoryStep {
    Pending { visited: u64 },
    Complete { objects: Vec<CatalogObject> },
}
pub enum TenantKeyReclamationStep {
    Pending { cursor: Vec<u8> },
    Complete(TenantKeyReclamationProof),
}
const DOMAIN: &[u8] = b"positron.live-purge.cursor.v1";
impl Catalog<'_> {
    pub fn tenant_key_reclamation_prepared(
        &self,
        tenant: TenantId,
        proof: [u8; 32],
    ) -> Result<bool, CatalogFailure> {
        let records = records(&self.pin()?)?;
        if records
            .iter()
            .any(|r| r.tenant == tenant && r.proof != proof)
        {
            return Err(fail(CatalogFailureCode::IdempotencyConflict));
        }
        Ok(records
            .iter()
            .any(|r| r.tenant == tenant && r.proof == proof))
    }
    pub fn begin_tenant_key_inventory(
        &self,
        tenant: TenantId,
        proof: [u8; 32],
    ) -> Result<TenantKeyInventory, CatalogFailure> {
        if proof == [0; 32] {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        // Transfer the existing governor grant; retained work owns its release.
        let claim =
            RecoveryWorkClaim::tenant(tenant, RecoveryWorkKind::Purge, recovery_resource_claim())
                .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        let reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?
            .transfer();
        Ok(TenantKeyInventory {
            instance: self.instance,
            tenant,
            proof,
            scan: self.storage.begin_key_inventory()?,
            _reservation: reservation,
        })
    }
    /// One exact authorized unlink and directory synchronization per turn.
    /// The MAC only permits progress previously issued after durable removal.
    pub fn reclaim_tenant_key_objects_step(
        &self,
        tenant: TenantId,
        proof: [u8; 32],
        cursor: Option<&[u8]>,
    ) -> Result<TenantKeyReclamationStep, CatalogFailure> {
        let claim =
            RecoveryWorkClaim::tenant(tenant, RecoveryWorkKind::Purge, recovery_resource_claim())
                .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let _barrier = self
            .authority
            .snapshot_barrier()
            .try_write()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        if self.has_backup_capture_references()? {
            return Err(fail(CatalogFailureCode::ConcurrentWriter));
        }
        let _operation = self
            .operation
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let snapshot = self.pin()?;
        let selected = records(&snapshot)?
            .into_iter()
            .filter(|record| record.tenant == tenant && record.proof == proof)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let mut binding = Vec::new();
        binding.extend_from_slice(&self.instance.to_bytes());
        binding.extend_from_slice(&tenant.to_bytes());
        binding.extend_from_slice(&proof);
        let mut count = 0u64;
        let mut digest = Sha256::new();
        for record in &selected {
            for location in &record.ids {
                if snapshot.object(location.id)?.is_some() {
                    return Err(fail(CatalogFailureCode::InvalidInput));
                }
                digest.update([location.kind]);
                digest.update(location.transaction);
                digest.update(location.epoch.to_be_bytes());
                digest.update(location.id.to_bytes());
                count = count
                    .checked_add(1)
                    .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
            }
        }
        binding.extend_from_slice(&digest.finalize());
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let index = if let Some(cursor) = cursor {
            if cursor.len() != 40 {
                return Err(fail(CatalogFailureCode::InvalidInput));
            }
            let number: [u8; 8] = cursor
                .get(..8)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?;
            let mac = cursor
                .get(8..)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?;
            let mut payload = binding.clone();
            payload.extend_from_slice(&number);
            secret.verify_opaque_digest(DOMAIN, &payload, &mac)?;
            u64::from_be_bytes(number)
        } else {
            0
        };
        if index > count {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        if index == count {
            return Ok(TenantKeyReclamationStep::Complete(
                TenantKeyReclamationProof {
                    tenant,
                    instance: self.instance,
                    proof,
                    generation: snapshot.identity(),
                },
            ));
        }
        let location = selected
            .iter()
            .flat_map(|r| r.ids.iter())
            .nth(usize::try_from(index).map_err(|_| fail(CatalogFailureCode::LimitExceeded))?)
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
        self.storage.reclaim_key_location(location)?;
        let number = (index + 1).to_be_bytes();
        binding.extend_from_slice(&number);
        let mut cursor = number.to_vec();
        cursor.extend_from_slice(&secret.opaque_digest(DOMAIN, &binding)?);
        Ok(TenantKeyReclamationStep::Pending { cursor })
    }
}
impl TenantKeyInventory {
    pub fn step<E>(
        &mut self,
        catalog: &Catalog<'_>,
        selector: impl Fn(&[u8]) -> Result<bool, E>,
    ) -> Result<TenantKeyInventoryStep, CatalogFailure> {
        if self.instance != catalog.instance {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let secret = catalog
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        match self.scan.step(&secret, self.instance, &|bytes| {
            selector(bytes).map_err(|_| fail(CatalogFailureCode::IntegrityCorruption))
        })? {
            Some(locations) => Ok(TenantKeyInventoryStep::Complete {
                objects: encode(self.tenant, self.proof, &locations)?,
            }),
            None => Ok(TenantKeyInventoryStep::Pending {
                visited: self.scan.visited(),
            }),
        }
    }
}
