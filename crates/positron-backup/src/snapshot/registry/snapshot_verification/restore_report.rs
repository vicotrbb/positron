//! Signed restore verification distinguishes excluded tenants from recovered keys.
use super::*;
const MAX_BYTES: usize = 1024 + 16 * tombstone::MAX_TOMBSTONES;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRestoreReport {
    bytes: Vec<u8>,
    recovered: u32,
    excluded: Vec<[u8; 16]>,
}
impl BackupRestoreReport {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn checksum(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }
    pub const fn recovered_keys(&self) -> u32 {
        self.recovered
    }
    pub fn excluded_tenants(&self) -> &[[u8; 16]] {
        &self.excluded
    }
    pub fn verify(
        bytes: &[u8],
        repository: &RepositoryIdentity,
        integrity: BootstrapIntegrityIdentity,
    ) -> Result<Self, RepositoryFailure> {
        if bytes.len() > MAX_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut decoder = super::super::super::codec::Decoder::new(
            super::super::super::codec::verify(bytes, integrity)?,
        );
        if decoder.take(8)? != b"POSBRR02" {
            return Err(RepositoryFailure::CorruptState);
        }
        if decoder.array::<16>()? == [0; 16]
            || decoder.array::<32>()? == [0; 32]
            || RepositoryIdentity::decode(decoder.take(108)?)? != *repository
            || integrity.fingerprint() != repository.integrity_fingerprint()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        // Source manifest, current registry, source Catalog and verified target basis.
        for _ in 0..4 {
            if decoder.array::<32>()? == [0; 32] {
                return Err(RepositoryFailure::CorruptState);
            }
        }
        let source_generation = decoder.u64()?;
        let target_generation = decoder.u64()?;
        let epoch = decoder.u32()?;
        let _audit_frontier = decoder.u64()?;
        if source_generation == 0
            || target_generation < source_generation
            || !matches!(epoch, 1 | 2)
            || decoder.array::<32>()? == [0; 32]
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let recovered = decoder.u32()?;
        let count = decoder.u32()? as usize;
        if recovered as usize > MAX_KEY_ENVELOPES || count > tombstone::MAX_TOMBSTONES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut excluded = Vec::new();
        excluded
            .try_reserve_exact(count)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for _ in 0..count {
            let tenant = decoder.array()?;
            if tenant == [0; 16] || excluded.last().is_some_and(|last| *last >= tenant) {
                return Err(RepositoryFailure::CorruptState);
            }
            excluded.push(tenant);
        }
        // Complete source ciphertext, native target verification, exclusion applied.
        if decoder.take(3)? != [1, 1, 1] {
            return Err(RepositoryFailure::CorruptState);
        }
        decoder.finish()?;
        Ok(Self {
            bytes: bytes.to_vec(),
            recovered,
            excluded,
        })
    }
}
impl BackupPublisher<'_> {
    /// Runtime separately authenticates native target data. Exclusion counts
    /// derive only from the same signed current Registry that verified this
    /// snapshot; they never assert completed destruction of remote keys.
    pub async fn snapshot_restore_report(
        &self,
        state: &BackupSnapshotVerification,
        source: &positron_kernel::CatalogSnapshot,
        target: &positron_kernel::CatalogSnapshot,
        recovered_keys: usize,
    ) -> Result<BackupRestoreReport, RepositoryFailure> {
        if !state.complete()
            || !state.inventory_verified
            || source.number() != state.manifest.catalog_generation
            || source.identity().to_bytes() != state.manifest.catalog_identity
            || source.format_epoch().map(|epoch| epoch.value()) != Some(state.manifest.format_epoch)
            || source.governance_audit_frontier() != state.manifest.audit_frontier
            || target.number() < source.number()
            || target.governance_audit_frontier() < source.governance_audit_frontier()
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.require_identity().await?;
        let (head, generation, registry) = self.current().await?;
        if head != Some(state.check.head) || registry != Some(state.registry) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let generation = generation.ok_or(RepositoryFailure::CorruptState)?;
        let mut excluded = generation
            .tombstones
            .iter()
            .map(BackupPurgeTombstone::tenant)
            .collect::<Vec<_>>();
        excluded.sort_unstable();
        let required = state
            .check
            .keys
            .iter()
            .filter(|key| !excluded.contains(&key.tenant))
            .count();
        if required != recovered_keys {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let mut bytes = b"POSBRR02".to_vec();
        bytes.extend_from_slice(&state.owner);
        bytes.extend_from_slice(&state.request);
        bytes.extend_from_slice(&self.identity.encode());
        for value in [
            state.check.manifest,
            state.registry,
            source.identity().to_bytes(),
            target.identity().to_bytes(),
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&source.number().to_be_bytes());
        bytes.extend_from_slice(&target.number().to_be_bytes());
        bytes.extend_from_slice(&state.manifest.format_epoch.to_be_bytes());
        bytes.extend_from_slice(&source.governance_audit_frontier().to_be_bytes());
        bytes.extend_from_slice(&state.manifest.key_context);
        bytes.extend_from_slice(&(recovered_keys as u32).to_be_bytes());
        bytes.extend_from_slice(&(excluded.len() as u32).to_be_bytes());
        for tenant in &excluded {
            bytes.extend_from_slice(tenant);
        }
        bytes.extend_from_slice(&[1, 1, 1]);
        let bytes = super::super::super::codec::sign(bytes, self.signer)?;
        BackupRestoreReport::verify(&bytes, self.identity, self.signer.identity())
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "restore_report_tests.rs"]
mod tests;
