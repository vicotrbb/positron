//! Exact, authenticated authority for reclaiming historical live key objects.
use super::*;
use positron_domain::identity::TenantId;
const MAGIC: &[u8; 8] = b"PKEYPUR2";
// Each exact directory/transaction/epoch/object location consumes 53 bytes.
// Inventories larger than the Catalog's complete 16 MiB object budget cannot
// be published atomically; refuse before deletion instead of dropping proof.
pub(super) const MAX_KEYS: usize = MAX_CATALOG_TOTAL_BYTES / 53;
const KEYS_PER_OBJECT: usize = (types::MAX_CATALOG_OBJECT_BYTES - 62) / 53;
/// Produced only after the exact Catalog-authorized live key files are absent.
#[derive(Debug)]
pub struct TenantKeyReclamationProof {
    tenant: TenantId,
    instance: InstanceId,
    proof: [u8; 32],
}
impl TenantKeyReclamationProof {
    pub const fn instance_id(&self) -> InstanceId {
        self.instance
    }
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.proof
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct KeyLocation {
    pub(super) kind: u8,
    pub(super) transaction: [u8; 16],
    pub(super) epoch: u32,
    pub(super) id: CatalogObjectId,
}
mod bounded;
pub use bounded::{TenantKeyInventory, TenantKeyInventoryStep, TenantKeyReclamationStep};

struct ReclamationRecord {
    tenant: TenantId,
    proof: [u8; 32],
    part: u16,
    parts: u16,
    ids: Vec<KeyLocation>,
}
fn fail(code: CatalogFailureCode) -> CatalogFailure {
    CatalogFailure::new(code)
}
fn decode_with_limit(bytes: &[u8], remaining: usize) -> Result<ReclamationRecord, CatalogFailure> {
    let bad = || fail(CatalogFailureCode::IntegrityCorruption);
    if bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(bad());
    }
    let tenant = TenantId::from_bytes(
        bytes
            .get(8..24)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(bad)?,
    )
    .map_err(|_| bad())?;
    let proof = bytes
        .get(24..56)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(bad)?;
    let number = |at| -> Result<u16, CatalogFailure> {
        Ok(u16::from_be_bytes(
            bytes
                .get(at..at + 2)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(bad)?,
        ))
    };
    let part = number(56)?;
    let parts = number(58)?;
    let count = usize::from(number(60)?);
    if proof == [0; 32]
        || parts == 0
        || part >= parts
        || count > KEYS_PER_OBJECT
        || bytes.len() != 62 + 53 * count
    {
        return Err(bad());
    }
    if count > remaining {
        return Err(fail(CatalogFailureCode::LimitExceeded));
    }
    let mut ids = Vec::new();
    for value in bytes.get(62..).ok_or_else(bad)?.chunks_exact(53) {
        let id = KeyLocation {
            kind: *value.first().ok_or_else(bad)?,
            transaction: value
                .get(1..17)
                .and_then(|v| v.try_into().ok())
                .ok_or_else(bad)?,
            epoch: u32::from_be_bytes(
                value
                    .get(17..21)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(bad)?,
            ),
            id: CatalogObjectId(
                value
                    .get(21..53)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(bad)?,
            ),
        };
        if id.kind > 2 || (id.kind != 2 && id.transaction != [0; 16]) {
            return Err(bad());
        }
        if ids.last().is_some_and(|last| *last >= id) {
            return Err(bad());
        }
        ids.push(id);
    }
    Ok(ReclamationRecord {
        tenant,
        proof,
        part,
        parts,
        ids,
    })
}
fn decode(bytes: &[u8]) -> Result<ReclamationRecord, CatalogFailure> {
    decode_with_limit(bytes, MAX_KEYS)
}
fn records(snapshot: &CatalogSnapshot) -> Result<Vec<ReclamationRecord>, CatalogFailure> {
    let mut groups = BTreeMap::<(TenantId, [u8; 32]), Vec<ReclamationRecord>>::new();
    let mut remaining = MAX_KEYS;
    for bytes in snapshot
        .plaintext_objects()
        .filter(|b| b.starts_with(MAGIC))
    {
        let record = decode_with_limit(bytes, remaining)?;
        remaining -= record.ids.len();
        groups
            .entry((record.tenant, record.proof))
            .or_default()
            .push(record);
    }
    let mut all = Vec::new();
    for mut group in groups.into_values() {
        group.sort_by_key(|record| record.part);
        let count = group
            .first()
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?
            .parts;
        if group.len() != usize::from(count)
            || group
                .iter()
                .enumerate()
                .any(|(i, record)| usize::from(record.part) != i || record.parts != count)
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        all.extend(group);
    }
    Ok(all)
}
pub(super) fn reclaimed_ids(
    snapshot: &CatalogSnapshot,
) -> Result<Vec<CatalogObjectId>, CatalogFailure> {
    let mut ids = records(snapshot)?
        .into_iter()
        .flat_map(|record| record.ids.into_iter().map(|location| location.id))
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}
fn encode(
    tenant: TenantId,
    proof: [u8; 32],
    ids: &[KeyLocation],
) -> Result<Vec<CatalogObject>, CatalogFailure> {
    if ids.len() > MAX_KEYS {
        return Err(fail(CatalogFailureCode::LimitExceeded));
    }
    let parts = ids.len().max(1).div_ceil(KEYS_PER_OBJECT);
    let mut objects = Vec::new();
    for part in 0..parts {
        let selected = ids
            .get(part * KEYS_PER_OBJECT..ids.len().min((part + 1) * KEYS_PER_OBJECT))
            .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&tenant.to_bytes());
        bytes.extend_from_slice(&proof);
        bytes.extend_from_slice(&(part as u16).to_be_bytes());
        bytes.extend_from_slice(&(parts as u16).to_be_bytes());
        bytes.extend_from_slice(&(selected.len() as u16).to_be_bytes());
        for id in selected {
            bytes.push(id.kind);
            bytes.extend_from_slice(&id.transaction);
            bytes.extend_from_slice(&id.epoch.to_be_bytes());
            bytes.extend_from_slice(&id.id.to_bytes());
        }
        objects.push(CatalogObject::new(bytes)?);
    }
    Ok(objects)
}
impl Catalog<'_> {
    /// Governance supplies its canonical decoder. Publish every returned part
    /// jointly with its permanent reservation, live removal, and audit.
    pub fn prepare_tenant_key_reclamation<E>(
        &self,
        tenant: TenantId,
        proof: [u8; 32],
        selector: impl Fn(&[u8]) -> Result<bool, E>,
    ) -> Result<Vec<CatalogObject>, CatalogFailure> {
        if proof == [0; 32] {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let _operation = self
            .operation
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let snapshot = self.pin()?;
        let existing = records(&snapshot)?
            .into_iter()
            .filter(|record| record.tenant == tenant)
            .collect::<Vec<_>>();
        if !existing.is_empty() {
            if existing.iter().any(|record| record.proof != proof) {
                return Err(fail(CatalogFailureCode::IdempotencyConflict));
            }
            let mut objects = Vec::new();
            for bytes in snapshot
                .plaintext_objects()
                .filter(|bytes| bytes.starts_with(MAGIC))
            {
                if decode(bytes)?.tenant == tenant {
                    objects.push(CatalogObject::new(bytes.to_vec())?);
                }
            }
            return Ok(objects);
        }
        let claim = RecoveryWorkClaim::system(RecoveryWorkKind::Repair, recovery_resource_claim())
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let mut scan = self.storage.begin_key_inventory()?;
        loop {
            if let Some(locations) = scan.step(&secret, self.instance, &|bytes| {
                selector(bytes).map_err(|_| fail(CatalogFailureCode::IntegrityCorruption))
            })? {
                return encode(tenant, proof, &locations);
            }
        }
    }

    pub fn reclaim_tenant_key_objects(
        &self,
        tenant: TenantId,
        proof: [u8; 32],
    ) -> Result<TenantKeyReclamationProof, CatalogFailure> {
        let mut cursor = None;
        loop {
            match self.reclaim_tenant_key_objects_step(tenant, proof, cursor.as_deref())? {
                TenantKeyReclamationStep::Pending { cursor: next } => cursor = Some(next),
                TenantKeyReclamationStep::Complete(proof) => return Ok(proof),
            }
        }
    }
}
impl CatalogSnapshot {
    pub fn without_tenant_segment_objects(
        &self,
        objects: Vec<CatalogObject>,
        tenant: TenantId,
    ) -> Result<Vec<CatalogObject>, CatalogFailure> {
        let mut retained = Vec::new();
        for object in objects {
            if crate::active_segment_ledger::restore_object_tenant(&object.plaintext)?
                != Some(tenant)
            {
                retained.push(object);
            }
        }
        Ok(retained)
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_purge_descriptor(bytes: &[u8]) {
    let _ = decode(bytes);
    let _ = CatalogGovernanceObject::decode(bytes);
    let mut prefixed = MAGIC.to_vec();
    prefixed.extend_from_slice(bytes);
    let _ = decode(&prefixed);
}
