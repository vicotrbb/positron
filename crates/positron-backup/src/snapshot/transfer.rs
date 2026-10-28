use super::*;
use crate::{ObjectRange, Repository, UploadOutcome, UploadPart, UploadPlan};
use sha2::{Digest, Sha256};
/// Reads only immutable, Kernel-captured encrypted bytes. Implementations must
/// keep the captured files reachable until the operation explicitly releases them.
pub trait BackupSource {
    fn read(&self, file: [u8; 32], offset: u64, length: u64) -> Result<Vec<u8>, RepositoryFailure>;
}
/// Bounded progress checkpoint; the existing Durable Operation owns persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTransfer {
    manifest: [u8; 32],
    next: u32,
    count: u32,
    uploaded: u64,
    reused: u64,
}
impl BackupTransfer {
    pub fn start(manifest: &BackupManifest) -> Result<Self, RepositoryFailure> {
        Ok(Self {
            manifest: Sha256::digest(manifest.encode()?).into(),
            next: 0,
            count: manifest.objects.len() as u32,
            uploaded: 0,
            reused: 0,
        })
    }
    pub const fn complete(self) -> bool {
        self.next == self.count
    }
    pub const fn uploaded_bytes(self) -> u64 {
        self.uploaded
    }
    pub const fn reused_bytes(self) -> u64 {
        self.reused
    }
    pub const fn next_object(self) -> u32 {
        self.next
    }
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(b"POSBKT01");
        bytes.extend_from_slice(&self.manifest);
        bytes.extend_from_slice(&self.next.to_be_bytes());
        bytes.extend_from_slice(&self.count.to_be_bytes());
        bytes.extend_from_slice(&self.uploaded.to_be_bytes());
        bytes.extend_from_slice(&self.reused.to_be_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8], manifest: &BackupManifest) -> Result<Self, RepositoryFailure> {
        let mut decoder = super::codec::Decoder::new(bytes);
        if decoder.take(8)? != b"POSBKT01" {
            return Err(RepositoryFailure::CorruptState);
        }
        let value = Self {
            manifest: decoder.array()?,
            next: decoder.u32()?,
            count: decoder.u32()?,
            uploaded: decoder.u64()?,
            reused: decoder.u64()?,
        };
        decoder.finish()?;
        let initial = Self::start(manifest)?;
        let transferred =
            manifest
                .objects
                .iter()
                .take(value.next as usize)
                .try_fold(0u64, |total, object| {
                    total
                        .checked_add(object.length)
                        .ok_or(RepositoryFailure::LimitExceeded)
                })?;
        if value.manifest != initial.manifest
            || value.count != initial.count
            || value.next > value.count
            || value.uploaded.checked_add(value.reused) != Some(transferred)
        {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(value)
    }
}
/// Volatile SHA state for one object. Durable recovery redoes this object.
#[derive(Debug)]
pub struct BackupObjectVerification {
    object: crate::ObjectId,
    offset: u64,
    digest: Sha256,
    uploaded: bool,
}
impl BackupObjectVerification {
    pub const fn verified_bytes(&self) -> u64 {
        self.offset
    }
}
impl super::BackupPublisher<'_> {
    /// Convenience driver for callers without a long-lived worker. Runtime
    /// uses `transfer_step_bounded` so every range yields its admitted turn.
    pub async fn transfer_step(
        &self,
        manifest: &BackupManifest,
        source: &impl BackupSource,
        mut checkpoint: BackupTransfer,
    ) -> Result<BackupTransfer, RepositoryFailure> {
        let mut verification = None;
        loop {
            checkpoint = self
                .transfer_step_bounded(manifest, source, checkpoint, &mut verification)
                .await?;
            if verification.is_none() {
                return Ok(checkpoint);
            }
        }
    }
    /// Performs one native upload part or one 4MiB readback range.
    pub async fn transfer_step_bounded(
        &self,
        manifest: &BackupManifest,
        source: &impl BackupSource,
        mut checkpoint: BackupTransfer,
        verification: &mut Option<BackupObjectVerification>,
    ) -> Result<BackupTransfer, RepositoryFailure> {
        #[cfg(feature = "test-support")]
        let mut phase = "identity";
        let result = async {
            self.require_identity().await?;
            #[cfg(feature = "test-support")]
            {
                phase = "reservation";
            }
            self.require_reserved(manifest).await?;
            #[cfg(feature = "test-support")]
            {
                phase = "checkpoint";
            }
            BackupTransfer::decode(&checkpoint.encode(), manifest)?;
            if checkpoint.complete() {
                return Ok(checkpoint);
            }
            #[cfg(feature = "test-support")]
            {
                phase = "object";
            }
            let object = manifest
                .objects
                .get(checkpoint.next as usize)
                .ok_or(RepositoryFailure::CorruptState)?;
            #[cfg(feature = "test-support")]
            {
                phase = "object_hint";
            }
            match self.repository.object_size_hint(object.object()).await {
                Ok(size) => {
                    if size != object.length {
                        return Err(RepositoryFailure::ChecksumMismatch);
                    }
                    #[cfg(feature = "test-support")]
                    {
                        phase = "verification_cursor";
                    }
                    let state = verification.get_or_insert_with(|| BackupObjectVerification {
                        object: object.object(),
                        offset: 0,
                        digest: Sha256::new(),
                        uploaded: false,
                    });
                    if state.object != object.object() || state.offset >= object.length {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    let length = (object.length - state.offset).min(crate::MAX_RANGE_BYTES);
                    #[cfg(feature = "test-support")]
                    {
                        phase = "range";
                    }
                    let bytes = self
                        .repository
                        .read_range(
                            ObjectRange::new(object.object(), state.offset, length)?
                                .with_expected_size(object.length)?,
                        )
                        .await?;
                    if bytes.bytes().len() as u64 != length {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    state.digest.update(bytes.bytes());
                    state.offset += length;
                    if state.offset == object.length {
                        if <[u8; 32]>::from(state.digest.clone().finalize()) != object.checksum {
                            return Err(RepositoryFailure::ChecksumMismatch);
                        }
                        if state.uploaded {
                            checkpoint.uploaded = checkpoint
                                .uploaded
                                .checked_add(object.length)
                                .ok_or(RepositoryFailure::LimitExceeded)?;
                        } else {
                            checkpoint.reused = checkpoint
                                .reused
                                .checked_add(object.length)
                                .ok_or(RepositoryFailure::LimitExceeded)?;
                        }
                        checkpoint.next += 1;
                        *verification = None;
                    }
                    return Ok(checkpoint);
                },
                Err(RepositoryFailure::NotFound) => {},
                Err(failure) => return Err(failure),
            }
            let plan = UploadPlan::new(object.object(), object.length)?;
            #[cfg(feature = "test-support")]
            {
                phase = "upload_state";
            }
            let state = match self.repository.inspect_upload(plan.id()).await? {
                Some(state) => state,
                None => self.repository.begin_upload(plan).await?,
            };
            if state.object() != object.object() || state.total_size() != object.length {
                return Err(RepositoryFailure::CorruptState);
            }
            let length = (object.length - state.uploaded_bytes()).min(crate::MAX_RANGE_BYTES);
            if length == 0 {
                return Err(RepositoryFailure::CorruptState);
            }
            #[cfg(feature = "test-support")]
            {
                phase = "source";
            }
            let bytes = source.read(object.file, object.offset + state.uploaded_bytes(), length)?;
            if bytes.len() as u64 != length {
                return Err(RepositoryFailure::CorruptState);
            }
            #[cfg(feature = "test-support")]
            {
                phase = "upload";
            }
            match self
                .repository
                .resume_upload(UploadPart::new(state, bytes)?)
                .await?
            {
                UploadOutcome::Pending(_) => {},
                UploadOutcome::Complete(_) => {
                    *verification = Some(BackupObjectVerification {
                        object: object.object(),
                        offset: 0,
                        digest: Sha256::new(),
                        uploaded: true,
                    });
                },
            }
            Ok(checkpoint)
        }
        .await;
        #[cfg(feature = "test-support")]
        if result == Err(RepositoryFailure::CorruptState) {
            let object = manifest.objects.get(checkpoint.next as usize);
            eprintln!(
                "backup_transfer_corrupt phase={phase} next={} count={} verification_present={} verification_offset={} expected_length={} object_equal={} failure=CorruptState",
                checkpoint.next,
                checkpoint.count,
                verification.is_some(),
                verification.as_ref().map_or(0, |state| state.offset),
                object.map_or(0, |object| object.length),
                verification
                    .as_ref()
                    .zip(object)
                    .is_some_and(|(state, object)| state.object == object.object())
            );
        }
        result
    }
}
pub(super) async fn verify_object(
    repository: &dyn Repository,
    object: crate::ObjectId,
    length: u64,
) -> Result<(), RepositoryFailure> {
    let size = repository.object_size_hint(object).await?;
    if size != length {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < length {
        let amount = (length - offset).min(crate::MAX_RANGE_BYTES);
        let bytes = repository
            .read_range(ObjectRange::new(object, offset, amount)?.with_expected_size(length)?)
            .await?;
        if bytes.bytes().len() as u64 != amount
            || <[u8; 32]>::from(Sha256::digest(bytes.bytes())) != bytes.checksum()
        {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        hash.update(bytes.bytes());
        offset += amount;
    }
    if <[u8; 32]>::from(hash.finalize()) != object.checksum() {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    Ok(())
}
