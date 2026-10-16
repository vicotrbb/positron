//! Immutable signed results of independent backup verification.
use super::*;
impl BackupPublisher<'_> {
    /// Signs immutable evidence after the trusted Runtime owner has separately
    /// authenticated native Catalog semantics and every required recovered key.
    pub async fn snapshot_verification_report(
        &self,
        state: &BackupSnapshotVerification,
        catalog: &positron_kernel::CatalogSnapshot,
        recovered_keys: usize,
    ) -> Result<BackupVerificationReport, RepositoryFailure> {
        if !state.complete()
            || !state.inventory_verified
            || recovered_keys != state.check.keys.len()
            || catalog.number() != state.manifest.catalog_generation
            || catalog.identity().to_bytes() != state.manifest.catalog_identity
            || catalog.format_epoch().map(|epoch| epoch.value())
                != Some(state.manifest.format_epoch)
            || catalog.governance_audit_frontier() != state.manifest.audit_frontier
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.require_identity().await?;
        let (head, _, registry) = self.current().await?;
        if head != Some(state.check.head) || registry != Some(state.registry) {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let mut bytes = b"POSBVR01".to_vec();
        bytes.extend_from_slice(&state.owner);
        bytes.extend_from_slice(&state.request);
        bytes.extend_from_slice(&self.identity.encode());
        bytes.extend_from_slice(&state.manifest.snapshot);
        bytes.extend_from_slice(&state.check.manifest);
        bytes.extend_from_slice(&state.registry);
        bytes.extend_from_slice(&state.manifest.catalog_generation.to_be_bytes());
        bytes.extend_from_slice(&state.manifest.catalog_identity);
        bytes.extend_from_slice(&state.manifest.format_epoch.to_be_bytes());
        bytes.extend_from_slice(&state.manifest.audit_frontier.to_be_bytes());
        bytes.extend_from_slice(&state.manifest.key_context);
        bytes.extend_from_slice(&(state.manifest.objects.len() as u32).to_be_bytes());
        let examined_bytes = state
            .manifest
            .objects
            .iter()
            .try_fold(0u64, |sum, object| {
                sum.checked_add(object.length)
                    .ok_or(RepositoryFailure::LimitExceeded)
            })?;
        bytes.extend_from_slice(&examined_bytes.to_be_bytes());
        bytes.extend_from_slice(&(recovered_keys as u32).to_be_bytes());
        // Version one is complete, has zero omissions/findings, and covers
        // native metadata and independent recovery readiness. Restore publication
        // and query execution on fresh storage belong to the restore workflow.
        bytes.extend_from_slice(&[1, 0, 0, 1, 1]);
        let bytes = super::super::super::codec::sign(bytes, self.signer)?;
        Ok(BackupVerificationReport { bytes })
    }
}
/// Signed immutable account of one completed independent verification run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerificationReport {
    bytes: Vec<u8>,
}
impl BackupVerificationReport {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn checksum(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }
    pub fn verify(
        bytes: &[u8],
        identity: &RepositoryIdentity,
        signer: BootstrapIntegrityIdentity,
    ) -> Result<Self, RepositoryFailure> {
        let payload = super::super::super::codec::verify(bytes, signer)?;
        if payload.len() != 349
            || payload.get(..8) != Some(b"POSBVR01")
            || payload.get(56..164) != Some(identity.encode().as_slice())
            || signer.fingerprint() != identity.integrity_fingerprint()
            || payload.get(344..) != Some(&[1, 0, 0, 1, 1])
        {
            return Err(RepositoryFailure::CorruptState);
        }
        for range in [
            8..24,
            24..56,
            164..180,
            180..212,
            212..244,
            252..284,
            296..328,
        ] {
            if payload
                .get(range)
                .is_none_or(|field| field.iter().all(|byte| *byte == 0))
            {
                return Err(RepositoryFailure::CorruptState);
            }
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}
