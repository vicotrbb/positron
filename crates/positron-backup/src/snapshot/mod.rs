//! Signed full-instance snapshots and authoritative Repository Key Registry.
mod read;
pub use read::BackupSnapshotReader;
mod capture;
mod codec;
mod context;
pub use context::{BackupCaptureContext, BackupRepositoryRegistration};
mod registry;
mod transfer;
use crate::{RepositoryFailure, RepositoryIdentity};
pub use capture::BackupManifestBuilder;
use positron_kernel::{BackupControlSigner, BootstrapIntegrityIdentity};
pub use registry::{
    BackupCleanupPlan, BackupCleanupProgress, BackupCleanupReason, BackupEnvelopeOverlay,
    BackupKeyEnvelope, BackupKeyIdentity, BackupListCursor, BackupPublication,
    BackupPublicationCheck, BackupPublisher, BackupPurgeTombstone, BackupReceipt,
    BackupRegistryVerification, BackupRestoreReport, BackupSnapshotPage,
    BackupSnapshotVerification, BackupTenantPurge, BackupVerificationReport, TenantKeyPurgeFence,
};
pub use transfer::{BackupObjectVerification, BackupSource, BackupTransfer};

pub const MAX_BACKUP_OBJECTS: usize = 65_536;
/// One bounded checksum-addressed extent of an immutable captured file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupObject {
    pub(crate) file: [u8; 32],
    pub(crate) file_size: u64,
    pub(crate) offset: u64,
    pub(crate) checksum: [u8; 32],
    pub(crate) length: u64,
}
impl BackupObject {
    pub fn new(
        file: [u8; 32],
        file_size: u64,
        offset: u64,
        checksum: [u8; 32],
        length: u64,
    ) -> Result<Self, RepositoryFailure> {
        if file == [0; 32]
            || checksum == [0; 32]
            || length == 0
            || length > crate::MAX_OBJECT_BYTES
            || offset.checked_add(length).is_none_or(|end| end > file_size)
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            file,
            file_size,
            offset,
            checksum,
            length,
        })
    }
    pub const fn file(self) -> [u8; 32] {
        self.file
    }
    pub const fn file_size(self) -> u64 {
        self.file_size
    }
    pub const fn offset(self) -> u64 {
        self.offset
    }
    pub const fn object(self) -> crate::ObjectId {
        crate::ObjectId::from_checksum(self.checksum)
    }
    pub const fn length(self) -> u64 {
        self.length
    }
}
/// Authenticated Kernel capture identity and its portable logical file index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupCatalogIdentity {
    generation: u64,
    identity: [u8; 32],
    epoch: u32,
    audit: u64,
    index: [u8; 32],
    binding: Option<([u8; 16], [u8; 32])>,
}
impl BackupCatalogIdentity {
    pub fn new(
        generation: u64,
        identity: [u8; 32],
        epoch: u32,
        audit: u64,
        index: [u8; 32],
    ) -> Result<Self, RepositoryFailure> {
        if generation == 0 || identity == [0; 32] || ![1, 2].contains(&epoch) || index == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            generation,
            identity,
            epoch,
            audit,
            index,
            binding: None,
        })
    }
}
impl BackupCatalogIdentity {
    pub fn with_capture_binding(
        mut self,
        operation: [u8; 16],
        request: [u8; 32],
    ) -> Result<Self, RepositoryFailure> {
        if operation == [0; 16] || request == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.binding = Some((operation, request));
        Ok(self)
    }
}
/// Explicit signed retention interval. Publication never infers a deadline from
/// the wall clock or provider lifecycle controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRetention {
    created: u64,
    retain_until: u64,
}
impl BackupRetention {
    pub fn new(created: u64, retain_until: u64) -> Result<Self, RepositoryFailure> {
        if created == 0 || retain_until < created {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            created,
            retain_until,
        })
    }
}
/// Immutable capture identity. Key envelopes live only in the separate registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifest {
    pub(crate) snapshot: [u8; 16],
    pub(crate) repository: RepositoryIdentity,
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_identity: [u8; 32],
    pub(crate) format_epoch: u32,
    pub(crate) audit_frontier: u64,
    pub(crate) capture_index: [u8; 32],
    pub(crate) capture_binding: Option<([u8; 16], [u8; 32])>,
    pub(crate) created: u64,
    pub(crate) retain_until: u64,
    pub(crate) key_context: [u8; 32],
    pub(crate) objects: Vec<BackupObject>,
}
impl BackupManifest {
    /// Heap retained by this immutable inventory outside a Publisher call.
    pub fn retained_memory_bytes(&self) -> Result<u64, RepositoryFailure> {
        self.objects
            .capacity()
            .checked_mul(std::mem::size_of::<BackupObject>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(RepositoryFailure::LimitExceeded)
    }

    pub fn new(
        snapshot: [u8; 16],
        repository: RepositoryIdentity,
        catalog: BackupCatalogIdentity,
        retention: BackupRetention,
        key_context: [u8; 32],
        objects: Vec<BackupObject>,
    ) -> Result<Self, RepositoryFailure> {
        if snapshot == [0; 16]
            || key_context == [0; 32]
            || objects.is_empty()
            || objects.len() > MAX_BACKUP_OBJECTS
            || !objects
                .iter()
                .any(|object| object.file == catalog.index && object.file_size <= 8 * 1024 * 1024)
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        let mut end = None;
        for object in &objects {
            match end {
                Some((file, size, offset)) if file == object.file => {
                    if size != object.file_size || offset != object.offset {
                        return Err(RepositoryFailure::InvalidInput);
                    }
                },
                Some((file, size, offset)) => {
                    if file >= object.file || size != offset || object.offset != 0 {
                        return Err(RepositoryFailure::InvalidInput);
                    }
                },
                None if object.offset != 0 => return Err(RepositoryFailure::InvalidInput),
                None => {},
            }
            end = Some((object.file, object.file_size, object.offset + object.length));
        }
        if end.is_none_or(|(_, size, offset)| size != offset) {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            snapshot,
            repository,
            catalog_generation: catalog.generation,
            catalog_identity: catalog.identity,
            format_epoch: catalog.epoch,
            audit_frontier: catalog.audit,
            capture_index: catalog.index,
            capture_binding: catalog.binding,
            created: retention.created,
            retain_until: retention.retain_until,
            key_context,
            objects,
        })
    }
    pub const fn snapshot_id(&self) -> [u8; 16] {
        self.snapshot
    }
    pub const fn format_epoch(&self) -> u32 {
        self.format_epoch
    }
    pub const fn audit_frontier(&self) -> u64 {
        self.audit_frontier
    }
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }
    pub const fn catalog_identity(&self) -> [u8; 32] {
        self.catalog_identity
    }
    pub const fn capture_binding(&self) -> Option<([u8; 16], [u8; 32])> {
        self.capture_binding
    }
    pub const fn capture_index(&self) -> [u8; 32] {
        self.capture_index
    }
    pub const fn created_at(&self) -> u64 {
        self.created
    }
    pub const fn retain_until(&self) -> u64 {
        self.retain_until
    }
    pub const fn key_context(&self) -> [u8; 32] {
        self.key_context
    }
    pub fn objects(&self) -> &[BackupObject] {
        &self.objects
    }
    pub fn repository(&self) -> &RepositoryIdentity {
        &self.repository
    }
    pub fn signed_bytes(&self, signer: &BackupControlSigner) -> Result<Vec<u8>, RepositoryFailure> {
        if signer.identity().fingerprint() != self.repository.integrity_fingerprint() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        codec::sign(self.encode()?, signer)
    }
    pub fn verify(
        bytes: &[u8],
        repository: &RepositoryIdentity,
        identity: BootstrapIntegrityIdentity,
    ) -> Result<Self, RepositoryFailure> {
        let payload = codec::verify(bytes, identity)?;
        let manifest = Self::decode(payload)?;
        if manifest.repository != *repository
            || identity.fingerprint() != repository.integrity_fingerprint()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(manifest)
    }
}

#[cfg(all(fuzzing, feature = "test-support"))]
pub(crate) use registry::fuzz_control_frames;
