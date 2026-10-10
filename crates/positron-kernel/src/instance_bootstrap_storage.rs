//! Descriptor-relative storage capability for the instance-bootstrap protocol.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{self as unix_fs, AtFlags, Mode, OFlags, RenameFlags};

use crate::{
    BootstrapKeyCustody, BootstrapKeyFailure, CatalogFailureCode, CatalogSecret, InstanceId,
    MountQualification, OwnedPrimaryDataVolume, PrimaryDataVolume, VolumeOperation,
};

mod io;
mod root_retirement;
mod system_envelope;
#[cfg(test)]
mod tests;

use io::{canonical_root, map_open_error, open_verified_root, path_identity, scan, synchronize};

const MAX_ARTIFACT_BYTES: u64 = 2_097_152;

/// A durable bootstrap artifact selected without exposing a filesystem name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapArtifact {
    Pending,
    PendingReplacement,
    InitializedStaging,
    Initialized,
    Claim,
    SystemKeyEnvelope,
    SystemKeyEnvelopeStaging,
}

impl BootstrapArtifact {
    const fn name(self) -> &'static str {
        match self {
            Self::Pending => ".positron-bootstrap.pending",
            Self::PendingReplacement => ".positron-bootstrap.pending.replacement",
            Self::InitializedStaging => ".positron-bootstrap.initialized.new",
            Self::Initialized => ".positron-bootstrap.initialized",
            Self::Claim => "bootstrap-claim.v1",
            Self::SystemKeyEnvelope => ".positron-system-key-envelopes.v1",
            Self::SystemKeyEnvelopeStaging => ".positron-system-key-envelopes.v1.new",
        }
    }

    const fn root(self) -> BootstrapRoot {
        match self {
            Self::Claim => BootstrapRoot::Secrets,
            Self::Pending
            | Self::PendingReplacement
            | Self::InitializedStaging
            | Self::Initialized
            | Self::SystemKeyEnvelope
            | Self::SystemKeyEnvelopeStaging => BootstrapRoot::Data,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootstrapRoot {
    Data,
    Secrets,
}

/// One recognized entry in a bootstrap root.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum BootstrapEntry {
    VolumeLock,
    Pending,
    PendingReplacement,
    InitializedStaging,
    Initialized,
    Catalog,
    Segments,
    Diagnostics,
    LocalKey,
    LocalKeyStaging,
    LocalKeyEpoch,
    LocalKeyEpochStaging,
    SystemKeyEnvelope,
    SystemKeyEnvelopeStaging,
    Claim,
}

/// A bounded, typed observation of both bootstrap roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapLayout {
    data: Vec<BootstrapEntry>,
    secrets: Vec<BootstrapEntry>,
    unknown_or_unsafe: bool,
}

impl BootstrapLayout {
    /// Returns whether the selected recognized entry exists.
    #[must_use]
    pub fn contains(&self, entry: BootstrapEntry) -> bool {
        self.data.contains(&entry) || self.secrets.contains(&entry)
    }

    /// Returns whether the root contained any unknown or unsafe entry.
    #[must_use]
    pub const fn unknown_or_unsafe(&self) -> bool {
        self.unknown_or_unsafe
    }

    /// Returns whether data contains only its ownership lock and secrets is empty.
    #[must_use]
    pub fn is_empty_instance(&self) -> bool {
        (self.data.is_empty() || self.data.as_slice() == [BootstrapEntry::VolumeLock])
            && self.secrets.is_empty()
    }

    /// Returns whether secrets contains no final key and only an optional staged key.
    #[must_use]
    pub fn has_at_most_staged_key(&self) -> bool {
        self.secrets.is_empty() || self.secrets.as_slice() == [BootstrapEntry::LocalKeyStaging]
    }

    /// Returns whether data contains only the ownership lock and pending intent.
    #[must_use]
    pub fn has_only_raw_pending_data(&self) -> bool {
        self.data.as_slice() == [BootstrapEntry::Pending]
            || self.data.as_slice() == [BootstrapEntry::VolumeLock, BootstrapEntry::Pending]
    }
}

/// Closed failure surface for bootstrap storage operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapStorageFailure {
    InvalidRoots,
    OwnershipLocked,
    Unavailable,
    UnsafeOrCorrupt,
    BoundIdentityMismatch,
    AlreadyExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootIdentity {
    device: u64,
    inode: u64,
}

/// Opaque authority for locating and acquiring the bootstrap roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceBootstrapStorage {
    data: PathBuf,
    secrets: PathBuf,
    data_identity: RootIdentity,
    secrets_identity: RootIdentity,
    qualification: MountQualification,
}

impl InstanceBootstrapStorage {
    /// Binds distinct existing roots to stable identities.
    pub fn new(
        data: &Path,
        secrets: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapStorageFailure> {
        let data = canonical_root(data)?;
        let secrets = canonical_root(secrets)?;
        if data == secrets || data.starts_with(&secrets) || secrets.starts_with(&data) {
            return Err(BootstrapStorageFailure::InvalidRoots);
        }
        Ok(Self {
            data_identity: path_identity(&data)?,
            secrets_identity: path_identity(&secrets)?,
            data,
            secrets,
            qualification,
        })
    }

    /// Opens both roots without following symbolic links.
    pub fn inspect(&self) -> Result<BootstrapArtifactAccess, BootstrapStorageFailure> {
        Ok(BootstrapArtifactAccess {
            data: open_verified_root(&self.data, self.data_identity)?,
            secrets: open_verified_root(&self.secrets, self.secrets_identity)?,
        })
    }

    /// Acquires the PDV and returns a descriptor-relative artifact capability.
    pub fn acquire(
        &self,
    ) -> Result<(OwnedPrimaryDataVolume, BootstrapArtifactAccess), BootstrapStorageFailure> {
        let expected = crate::VolumeRootIdentity {
            device: self.data_identity.device,
            inode: self.data_identity.inode,
        };
        let volume = PrimaryDataVolume::acquire_bound(&self.data, self.qualification, expected)
            .map_err(|failure| {
                if failure.operation() == VolumeOperation::AcquireOwnershipLock {
                    BootstrapStorageFailure::OwnershipLocked
                } else if failure.operation() == VolumeOperation::VerifyRootIdentity {
                    BootstrapStorageFailure::BoundIdentityMismatch
                } else {
                    BootstrapStorageFailure::Unavailable
                }
            })?;
        let data = volume
            ._root
            .try_clone()
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let secrets = open_verified_root(&self.secrets, self.secrets_identity)?;
        Ok((volume, BootstrapArtifactAccess { data, secrets }))
    }

    /// Acquires existing ownership for read-only offline inspection. Missing
    /// ownership artifacts are rejected rather than initialized.
    pub fn acquire_read_only(
        &self,
    ) -> Result<(OwnedPrimaryDataVolume, BootstrapArtifactAccess), BootstrapStorageFailure> {
        let expected = crate::VolumeRootIdentity {
            device: self.data_identity.device,
            inode: self.data_identity.inode,
        };
        let volume =
            PrimaryDataVolume::acquire_bound_read_only(&self.data, self.qualification, expected)
                .map_err(|failure| match failure.operation() {
                    VolumeOperation::AcquireOwnershipLock => {
                        BootstrapStorageFailure::OwnershipLocked
                    },
                    VolumeOperation::VerifyRootIdentity => {
                        BootstrapStorageFailure::BoundIdentityMismatch
                    },
                    _ => BootstrapStorageFailure::Unavailable,
                })?;
        let data = volume
            ._root
            .try_clone()
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let secrets = open_verified_root(&self.secrets, self.secrets_identity)?;
        Ok((volume, BootstrapArtifactAccess { data, secrets }))
    }

    /// Binds a separate Recovery Bundle location outside both protected instance roots.
    pub fn recovery_bundle_location(
        &self,
        path: &Path,
    ) -> Result<PathBuf, BootstrapStorageFailure> {
        if path.as_os_str().len() > 4096 {
            return Err(BootstrapStorageFailure::InvalidRoots);
        }
        let _access = self.inspect()?;
        let parent = canonical_root(path.parent().ok_or(BootstrapStorageFailure::InvalidRoots)?)?;
        if parent.starts_with(&self.data) || parent.starts_with(&self.secrets) {
            return Err(BootstrapStorageFailure::InvalidRoots);
        }
        Ok(parent.join(
            path.file_name()
                .ok_or(BootstrapStorageFailure::InvalidRoots)?,
        ))
    }

    /// Returns the trusted mount provenance attached to this authority.
    #[must_use]
    pub const fn qualification(&self) -> MountQualification {
        self.qualification
    }
}

/// Held descriptor capability for bootstrap artifacts.
pub struct BootstrapArtifactAccess {
    data: File,
    secrets: File,
}

impl BootstrapArtifactAccess {
    pub(crate) fn prepare_successor_key(
        &self,
        epoch: u64,
    ) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        BootstrapKeyCustody::initialize_epoch_in(&self.secrets, epoch)
    }
    pub(crate) fn open_successor_key(
        &self,
        epoch: u64,
    ) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        BootstrapKeyCustody::open_epoch_in(&self.secrets, epoch)
    }

    pub(crate) fn require_recovery_target_absent(
        &self,
        key: &BootstrapKeyCustody,
    ) -> Result<(), BootstrapKeyFailure> {
        let epoch = key.active_root_epoch()?;
        let name = if epoch == 1 {
            "local-root-key.v1".to_owned()
        } else {
            format!("local-root-key.epoch-{epoch}.v1")
        };
        match unix_fs::statat(&self.secrets, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {},
            _ => return Err(BootstrapKeyFailure::Custody),
        }
        let existing_route = if self
            .exists(BootstrapArtifact::SystemKeyEnvelope)
            .map_err(|_| BootstrapKeyFailure::Custody)?
        {
            let bytes = self.read_system_key_envelope()?;
            key.verify_recovery_envelope(&bytes)?;
            Some(bytes)
        } else {
            None
        };
        if epoch > 1 {
            match unix_fs::statat(
                &self.secrets,
                "local-root-key.v1",
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(_) => {
                    let original = BootstrapKeyCustody::open_in(&self.secrets)?;
                    if original.identity() != key.bootstrap_identity() {
                        return Err(BootstrapKeyFailure::Authentication);
                    }
                    let original = match existing_route.as_ref() {
                        Some(bytes) => original.open_root_envelope(bytes)?,
                        None => original,
                    };
                    key.verify_recovered_system_matches(&original)?;
                },
                Err(rustix::io::Errno::NOENT) => {},
                Err(_) => return Err(BootstrapKeyFailure::Custody),
            }
        }
        Ok(())
    }

    pub(crate) fn publish_recovered_key(
        &self,
        key: &BootstrapKeyCustody,
    ) -> Result<(), BootstrapKeyFailure> {
        self.require_recovery_target_absent(key)?;
        if let Some(envelope) = key.root_recovery_envelope()? {
            if self
                .exists(BootstrapArtifact::SystemKeyEnvelope)
                .map_err(|_| BootstrapKeyFailure::Custody)?
            {
                let existing = self.read_system_key_envelope()?;
                key.verify_recovery_envelope(&existing)?;
                self.publish_recovered_system_envelope(&existing)?;
            } else {
                self.publish_recovered_system_envelope(&envelope)?;
            }
        }
        key.publish_recovered_in(&self.secrets)
    }

    /// Opens the local bootstrap key relative to the held secrets root.
    pub fn open_key(&self) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        let main_exists = match unix_fs::statat(
            &self.secrets,
            "local-root-key.v1",
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(_) => return Err(BootstrapKeyFailure::Custody),
        };
        let artifact = BootstrapArtifact::SystemKeyEnvelope;
        if self
            .exists(artifact)
            .map_err(|_| BootstrapKeyFailure::Custody)?
        {
            let envelope = self.read_system_key_envelope()?;
            if main_exists {
                BootstrapKeyCustody::open_in(&self.secrets)?.open_root_envelope(&envelope)
            } else {
                BootstrapKeyCustody::open_successor_candidate(&self.secrets, &envelope)
            }
        } else {
            BootstrapKeyCustody::open_in(&self.secrets)
        }
    }

    /// Initializes the local bootstrap key relative to the held secrets root.
    pub fn initialize_key(&self) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        BootstrapKeyCustody::initialize_in(&self.secrets)
    }

    /// Scans recognized root entries and rejects unsafe entry kinds.
    pub fn layout(&self) -> Result<BootstrapLayout, BootstrapStorageFailure> {
        let (mut data, data_unsafe) = scan(&self.data, BootstrapRoot::Data)?;
        let (mut secrets, secrets_unsafe) = scan(&self.secrets, BootstrapRoot::Secrets)?;
        data.sort_unstable();
        secrets.sort_unstable();
        Ok(BootstrapLayout {
            data,
            secrets,
            unknown_or_unsafe: data_unsafe || secrets_unsafe,
        })
    }

    /// Authenticates the complete visible Catalog chain without recovery mutation.
    pub fn inspect_catalog(
        &self,
        instance: InstanceId,
        secret: CatalogSecret,
    ) -> Result<u64, BootstrapStorageFailure> {
        crate::catalog::inspect_read_only(&self.data, instance, secret).map_err(|failure| {
            if failure.code() == CatalogFailureCode::StorageUnavailable {
                BootstrapStorageFailure::Unavailable
            } else {
                BootstrapStorageFailure::UnsafeOrCorrupt
            }
        })
    }

    /// Reads a bounded regular artifact through its held root descriptor.
    pub fn read(&self, artifact: BootstrapArtifact) -> Result<Vec<u8>, BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        let mut file = unix_fs::openat(
            directory,
            artifact.name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(map_open_error)?;
        let metadata = file
            .metadata()
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let maximum = if artifact == BootstrapArtifact::SystemKeyEnvelope {
            16_384
        } else {
            MAX_ARTIFACT_BYTES
        };
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > maximum
        {
            return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
        }
        let length = usize::try_from(metadata.len())
            .map_err(|_| BootstrapStorageFailure::UnsafeOrCorrupt)?;
        let mut bytes = vec![0_u8; length];
        file.read_exact(&mut bytes)
            .map_err(|_| BootstrapStorageFailure::UnsafeOrCorrupt)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| BootstrapStorageFailure::Unavailable)?
            != 0
        {
            return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
        }
        Ok(bytes)
    }

    /// Creates and durably synchronizes a new artifact.
    pub fn write_new(
        &self,
        artifact: BootstrapArtifact,
        bytes: &[u8],
    ) -> Result<(), BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        let mut file = unix_fs::openat(
            directory,
            artifact.name(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(map_open_error)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        synchronize(directory)
    }

    /// Publishes a synchronized pending replacement over the raw intent.
    pub fn publish_pending_replacement(&self) -> Result<(), BootstrapStorageFailure> {
        unix_fs::renameat(
            &self.data,
            BootstrapArtifact::PendingReplacement.name(),
            &self.data,
            BootstrapArtifact::Pending.name(),
        )
        .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        synchronize(&self.data)
    }

    /// Removes an artifact and synchronizes its parent directory.
    pub fn remove(&self, artifact: BootstrapArtifact) -> Result<(), BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        unix_fs::unlinkat(directory, artifact.name(), AtFlags::empty())
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        synchronize(directory)
    }

    /// Publishes the initialized marker without replacing a racing final marker.
    pub fn publish_initialized(&self) -> Result<(), BootstrapStorageFailure> {
        unix_fs::renameat_with(
            &self.data,
            BootstrapArtifact::InitializedStaging.name(),
            &self.data,
            BootstrapArtifact::Initialized.name(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                BootstrapStorageFailure::AlreadyExists
            } else {
                BootstrapStorageFailure::Unavailable
            }
        })?;
        synchronize(&self.data)
    }

    /// Tests the exact entry kind without following symbolic links.
    pub fn exists(&self, artifact: BootstrapArtifact) -> Result<bool, BootstrapStorageFailure> {
        let directory = self.directory(artifact);
        match unix_fs::statat(directory, artifact.name(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => {
                if unix_fs::FileType::from_raw_mode(metadata.st_mode).is_file()
                    && metadata.st_nlink == 1
                {
                    Ok(true)
                } else {
                    Err(BootstrapStorageFailure::UnsafeOrCorrupt)
                }
            },
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err(BootstrapStorageFailure::Unavailable),
        }
    }

    fn directory(&self, artifact: BootstrapArtifact) -> &File {
        match artifact.root() {
            BootstrapRoot::Data => &self.data,
            BootstrapRoot::Secrets => &self.secrets,
        }
    }
}
