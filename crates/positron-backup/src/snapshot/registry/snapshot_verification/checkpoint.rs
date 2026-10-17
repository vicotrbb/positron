//! Signed progress retains complete native files; partial file hashes restart safely.
use super::*;
pub(super) fn inventory_digest(files: &[positron_kernel::BackupCaptureFile]) -> [u8; 32] {
    use positron_kernel::BackupCaptureFileKind;
    let mut hash = Sha256::new();
    hash.update(b"positron.backup.verified-inventory.v1\0");
    for file in files {
        hash.update(file.identity());
        hash.update(file.checksum());
        hash.update(file.size().to_be_bytes());
        hash.update([match file.kind() {
            BackupCaptureFileKind::CatalogObject => 1,
            BackupCaptureFileKind::GovernanceAudit => 2,
            BackupCaptureFileKind::Segment => 3,
            BackupCaptureFileKind::Index => 4,
            BackupCaptureFileKind::AuditCheckpoint => 5,
            BackupCaptureFileKind::SegmentFrontier => 6,
        }]);
    }
    hash.finalize().into()
}
impl BackupPublisher<'_> {
    pub fn snapshot_verification_checkpoint(
        &self,
        state: &BackupSnapshotVerification,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        let checkpoint = self.publication_checkpoint(&state.check)?;
        let mut bytes = b"POSBSV02".to_vec();
        bytes.extend_from_slice(&state.owner);
        bytes.extend_from_slice(&state.request);
        bytes.extend_from_slice(&state.manifest.snapshot);
        bytes.extend_from_slice(&state.registry);
        bytes.extend_from_slice(&(checkpoint.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&checkpoint);
        let (inventory, completed) = state.resumed_inventory.unwrap_or_else(|| {
            if state.inventory_verified {
                (inventory_digest(&state.files), state.next_file)
            } else {
                ([0; 32], 0)
            }
        });
        bytes.extend_from_slice(&inventory);
        bytes.extend_from_slice(
            &u32::try_from(completed)
                .map_err(|_| RepositoryFailure::LimitExceeded)?
                .to_be_bytes(),
        );
        crate::snapshot::codec::sign(bytes, self.signer)
    }
    pub async fn resume_snapshot_verification(
        &self,
        bytes: &[u8],
        owner: [u8; 16],
        request: [u8; 32],
    ) -> Result<BackupSnapshotVerification, RepositoryFailure> {
        if bytes.len() > 1024 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut decoder = crate::snapshot::codec::Decoder::new(crate::snapshot::codec::verify(
            bytes,
            self.signer.identity(),
        )?);
        let version = decoder.take(8)?;
        if (version != b"POSBSV01" && version != b"POSBSV02")
            || decoder.array::<16>()? != owner
            || decoder.array::<32>()? != request
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let snapshot = decoder.array()?;
        let registry = decoder.array::<32>()?;
        let length = decoder.u32()? as usize;
        let checkpoint = decoder.take(length)?;
        let inventory = if version == b"POSBSV02" {
            let digest = decoder.array::<32>()?;
            let completed = decoder.u32()? as usize;
            if completed > MAX_BACKUP_OBJECTS || (digest == [0; 32] && completed != 0) {
                return Err(RepositoryFailure::CorruptState);
            }
            (digest != [0; 32]).then_some((digest, completed))
        } else {
            None
        };
        decoder.finish()?;
        let mut state = self
            .begin_snapshot_verification(snapshot, owner, request)
            .await?;
        if state.registry == registry {
            state.check = self.resume_publication(&state.manifest, checkpoint).await?;
            state.resumed_inventory = inventory;
        }
        Ok(state)
    }
}
