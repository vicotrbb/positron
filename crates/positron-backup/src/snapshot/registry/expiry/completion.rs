//! A completed signed claim remains provable after its acknowledgement and
//! across local capture cleanup, without retaining provider capabilities.
use super::*;
impl BackupPublisher<'_> {
    pub fn cleanup_checkpoint(
        &self,
        progress: BackupCleanupProgress,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        self.ensure_control_memory(0, 0)?;
        if !progress.complete() {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let mut bytes = b"POSBCL01".to_vec();
        bytes.extend_from_slice(&self.identity.encode());
        bytes.extend_from_slice(&progress.owner);
        bytes.push(match progress.reason {
            BackupCleanupReason::Retention => 1,
            BackupCleanupReason::Cancellation => 2,
        });
        bytes.extend_from_slice(&progress.snapshot);
        bytes.extend_from_slice(&progress.manifest.checksum());
        bytes.extend_from_slice(&progress.registry);
        bytes.extend_from_slice(&progress.deleted.to_be_bytes());
        bytes.extend_from_slice(&progress.absent.to_be_bytes());
        bytes.extend_from_slice(&progress.shared.to_be_bytes());
        super::super::super::codec::sign(bytes, self.signer)
    }
    pub async fn verify_cleanup_checkpoint(
        &self,
        bytes: &[u8],
    ) -> Result<BackupCleanupProgress, RepositoryFailure> {
        self.require_identity().await?;
        let payload = super::super::super::codec::verify(bytes, self.signer.identity())?;
        let mut decoder = super::super::super::codec::Decoder::new(payload);
        if decoder.take(8)? != b"POSBCL01"
            || RepositoryIdentity::decode(decoder.take(108)?)? != *self.identity
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let owner = decoder.array()?;
        let reason = match decoder.take(1)? {
            [1] => BackupCleanupReason::Retention,
            [2] => BackupCleanupReason::Cancellation,
            _ => return Err(RepositoryFailure::CorruptState),
        };
        let progress = BackupCleanupProgress {
            owner,
            reason,
            snapshot: decoder.array()?,
            manifest: ObjectId::from_checksum(decoder.array()?),
            registry: decoder.array()?,
            remaining: 0,
            deleted: decoder.u32()?,
            absent: decoder.u32()?,
            shared: decoder.u32()?,
        };
        decoder.finish()?;
        let (head, _, _) = self.current().await?;
        let historical = self
            .read_control_object(ObjectId::from_checksum(progress.registry))
            .await?;
        let generation = Generation::verify(&historical, self.identity, self.signer.identity())?;
        let claim = generation
            .claims
            .iter()
            .find(|claim| claim.owner == owner)
            .ok_or(RepositoryFailure::CorruptState)?;
        if claim.progress(progress.registry) != progress {
            return Err(RepositoryFailure::CorruptState);
        }
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|head| head.version())
            != head
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(progress)
    }
}
