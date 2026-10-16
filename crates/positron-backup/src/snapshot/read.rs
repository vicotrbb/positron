//! Public-pin reads before a recovered Catalog can yield signing custody.
use super::*;
use crate::{ObjectId, ObjectRange, Repository};
use positron_kernel::{NativeAwsResources, ResourceDimension};
use sha2::{Digest, Sha256};
const MAX_CONTROL_BYTES: u64 = 8 * 1024 * 1024;

/// Authenticated snapshot ciphertext, without authority to publish repository
/// control state. Current-head and key-registry verification remain mandatory
/// after independent key recovery and before any restore publication.
pub struct BackupSnapshotReader<'a> {
    repository: &'a dyn Repository,
    identity: &'a RepositoryIdentity,
    resources: &'a NativeAwsResources,
    external_retained: u64,
    manifest: BackupManifest,
    manifest_id: ObjectId,
    integrity: BootstrapIntegrityIdentity,
}
impl<'a> BackupSnapshotReader<'a> {
    pub async fn open(
        repository: &'a dyn Repository,
        identity: &'a RepositoryIdentity,
        integrity: BootstrapIntegrityIdentity,
        manifest: ObjectId,
        resources: &'a NativeAwsResources,
        external_retained: u64,
    ) -> Result<Self, RepositoryFailure> {
        if identity.integrity_fingerprint() != integrity.fingerprint() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        require_memory(resources, identity, 0, external_retained)?;
        if repository.identify().await? != *identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let bytes = object_bytes(repository, manifest, |size| {
            require_memory(resources, identity, size, external_retained)
        })
        .await?;
        let manifest_id = manifest;
        let manifest = BackupManifest::verify(&bytes, identity, integrity)?;
        Ok(Self {
            repository,
            identity,
            resources,
            external_retained,
            manifest,
            manifest_id,
            integrity,
        })
    }
    /// Discovers only a currently registered, signed recovery route. Full
    /// registry ancestry and recovered key authentication remain required.
    pub async fn recovery_overlay(
        &self,
        target: &positron_kernel::key_provider::ProviderKeyUri,
    ) -> Result<Option<BackupEnvelopeOverlay>, RepositoryFailure> {
        require_memory(
            self.resources,
            self.identity,
            MAX_CONTROL_BYTES,
            self.external_retained
                .checked_add(self.manifest.retained_memory_bytes()?)
                .ok_or(RepositoryFailure::LimitExceeded)?,
        )?;
        registry::recovery_overlay(
            self.repository,
            self.identity,
            self.integrity,
            &self.manifest,
            self.manifest_id,
            target,
        )
        .await
    }
    /// Charges metadata retained by the caller before its next bounded read.
    pub fn with_external_retained_memory(mut self, bytes: u64) -> Result<Self, RepositoryFailure> {
        let retained = bytes
            .checked_add(self.manifest.retained_memory_bytes()?)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        require_memory(self.resources, self.identity, 0, retained)?;
        self.external_retained = bytes;
        Ok(self)
    }
    pub fn manifest(&self) -> &BackupManifest {
        &self.manifest
    }
    pub async fn read_file(
        &self,
        file: [u8; 32],
        maximum: u64,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        let descriptor = self
            .manifest
            .objects
            .iter()
            .find(|object| object.file == file)
            .ok_or(RepositoryFailure::NotFound)?;
        if maximum > MAX_CONTROL_BYTES || descriptor.file_size > maximum {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let retained = self
            .external_retained
            .checked_add(self.manifest.retained_memory_bytes()?)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        require_memory(
            self.resources,
            self.identity,
            descriptor.file_size,
            retained,
        )?;
        if self.repository.identify().await? != *self.identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        file_bytes(self.repository, &self.manifest, file).await
    }
}
pub(super) fn native_memory(identity: &RepositoryIdentity) -> Result<u64, RepositoryFailure> {
    Ok(match identity.provider_kind() {
        "localFilesystem" => 0,
        "awsS3" => crate::AwsS3Repository::required_resources().get(ResourceDimension::MemoryBytes),
        "googleCloudStorage" => crate::GoogleCloudStorageRepository::required_resources()
            .get(ResourceDimension::MemoryBytes),
        "azureBlob" => {
            crate::AzureBlobRepository::required_resources().get(ResourceDimension::MemoryBytes)
        },
        _ => return Err(RepositoryFailure::InvalidInput),
    })
}
fn require_memory(
    resources: &NativeAwsResources,
    identity: &RepositoryIdentity,
    extent: u64,
    retained: u64,
) -> Result<(), RepositoryFailure> {
    if !resources.authorizes_repository_transport() {
        return Err(RepositoryFailure::PermissionDenied);
    }
    if extent > MAX_CONTROL_BYTES {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let memory_bytes = native_memory(identity)?
        .checked_add(MAX_CONTROL_BYTES)
        .and_then(|n| {
            extent
                .checked_mul(8)
                .and_then(|extent| n.checked_add(extent))
        })
        .and_then(|n| n.checked_add(retained))
        .ok_or(RepositoryFailure::LimitExceeded)?;
    if resources.granted().get(ResourceDimension::MemoryBytes) < memory_bytes {
        return Err(RepositoryFailure::ControlMemoryRequired { memory_bytes });
    }
    Ok(())
}
/// Complete immutable object read, admitted after the untrusted size hint and
/// before allocating. Native range-version fences and SHA-256 remain required.
pub(super) async fn object_bytes(
    repository: &dyn Repository,
    object: ObjectId,
    admit: impl Fn(u64) -> Result<(), RepositoryFailure>,
) -> Result<Vec<u8>, RepositoryFailure> {
    admit(0)?;
    let size = repository.object_size_hint(object).await?;
    if size > MAX_CONTROL_BYTES {
        return Err(RepositoryFailure::CorruptState);
    }
    admit(size)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size as usize)
        .map_err(|_| RepositoryFailure::LimitExceeded)?;
    while (bytes.len() as u64) < size {
        let offset = bytes.len() as u64;
        let length = (size - offset).min(crate::MAX_RANGE_BYTES);
        let part = repository
            .read_range(ObjectRange::new(object, offset, length)?.with_expected_size(size)?)
            .await?;
        if part.bytes().len() as u64 != length {
            return Err(RepositoryFailure::CorruptState);
        }
        bytes.extend_from_slice(part.bytes());
    }
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != object.checksum() {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    Ok(bytes)
}
pub(super) async fn file_bytes(
    repository: &dyn Repository,
    manifest: &BackupManifest,
    file: [u8; 32],
) -> Result<Vec<u8>, RepositoryFailure> {
    let first = manifest
        .objects
        .iter()
        .find(|object| object.file == file)
        .ok_or(RepositoryFailure::NotFound)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(first.file_size as usize)
        .map_err(|_| RepositoryFailure::LimitExceeded)?;
    for object in manifest.objects.iter().filter(|object| object.file == file) {
        if bytes.len() as u64 != object.offset {
            return Err(RepositoryFailure::CorruptState);
        }
        let mut offset = 0;
        let mut hash = Sha256::new();
        while offset < object.length {
            let length = (object.length - offset).min(crate::MAX_RANGE_BYTES);
            let part = repository
                .read_range(
                    ObjectRange::new(object.object(), offset, length)?
                        .with_expected_size(object.length)?,
                )
                .await?;
            if part.bytes().len() as u64 != length {
                return Err(RepositoryFailure::CorruptState);
            }
            hash.update(part.bytes());
            bytes.extend_from_slice(part.bytes());
            offset += length;
        }
        if <[u8; 32]>::from(hash.finalize()) != object.checksum {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
    }
    if bytes.len() as u64 != first.file_size {
        return Err(RepositoryFailure::CorruptState);
    }
    Ok(bytes)
}
