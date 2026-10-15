//! Bounded accepted Backup intent and terminal public evidence.
use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupSnapshotParameters {
    repository: RepositoryOperationParameters,
    retention: u64,
    registration: [u8; 32],
}
impl BackupSnapshotParameters {
    pub fn new(
        repository: RepositoryOperationParameters,
        retention_seconds: u64,
        registration: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if repository.action() != RepositoryAction::Verify
            || !(60..=315_360_000).contains(&retention_seconds)
            || registration == [0; 32]
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            repository,
            retention: retention_seconds,
            registration,
        })
    }
    pub const fn repository(self) -> RepositoryOperationParameters {
        self.repository
    }
    pub const fn retention_seconds(self) -> u64 {
        self.retention
    }
    pub const fn registration_identity(self) -> [u8; 32] {
        self.registration
    }
    pub fn intent_digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron-backup-snapshot-request-v1\0");
        hash.update(self.repository.intent_digest());
        hash.update(self.retention.to_be_bytes());
        hash.update(self.registration);
        hash.finalize().into()
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.retention.to_be_bytes());
        bytes.extend_from_slice(&self.registration);
        self.repository.encode(bytes);
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let retention = codec::take_u64(bytes, &mut offset)?;
        let registration = codec::take_array(bytes, &mut offset)?;
        let repository = RepositoryOperationParameters::decode(
            bytes
                .get(offset..)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )?;
        Self::new(repository, retention, registration)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupOperationReceipt {
    manifest: [u8; 32],
    registry: [u8; 32],
    generation: u64,
    catalog: [u8; 32],
    uploaded: u64,
    reused: u64,
    retain_until: u64,
}
impl BackupOperationReceipt {
    pub fn new(
        manifest: [u8; 32],
        registry: [u8; 32],
        generation: u64,
        catalog: [u8; 32],
        uploaded: u64,
        reused: u64,
        retain_until: u64,
    ) -> Result<Self, DurableOperationFailure> {
        if manifest == [0; 32]
            || registry == [0; 32]
            || generation == 0
            || catalog == [0; 32]
            || retain_until == 0
            || uploaded
                .checked_add(reused)
                .is_none_or(|total| total == 0 || total > 4_398_046_511_104)
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            manifest,
            registry,
            generation,
            catalog,
            uploaded,
            reused,
            retain_until,
        })
    }
    pub const fn manifest(self) -> [u8; 32] {
        self.manifest
    }
    pub const fn registry_generation(self) -> [u8; 32] {
        self.registry
    }
    pub const fn catalog_generation(self) -> u64 {
        self.generation
    }
    pub const fn catalog_identity(self) -> [u8; 32] {
        self.catalog
    }
    pub const fn uploaded_bytes(self) -> u64 {
        self.uploaded
    }
    pub const fn reused_bytes(self) -> u64 {
        self.reused
    }
    pub const fn retain_until(self) -> u64 {
        self.retain_until
    }
    pub(crate) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.manifest);
        bytes.extend_from_slice(&self.registry);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.catalog);
        bytes.extend_from_slice(&self.uploaded.to_be_bytes());
        bytes.extend_from_slice(&self.reused.to_be_bytes());
        bytes.extend_from_slice(&self.retain_until.to_be_bytes());
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let value = Self::new(
            codec::take_array(bytes, &mut offset)?,
            codec::take_array(bytes, &mut offset)?,
            codec::take_u64(bytes, &mut offset)?,
            codec::take_array(bytes, &mut offset)?,
            codec::take_u64(bytes, &mut offset)?,
            codec::take_u64(bytes, &mut offset)?,
            codec::take_u64(bytes, &mut offset)?,
        )?;
        if offset != bytes.len() {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupOperationStage {
    Capturing,
    Transferring,
    Verifying,
    Publishing,
}
impl BackupOperationStage {
    pub(super) fn phase(self) -> DurableOperationPhase {
        match self {
            Self::Capturing => DurableOperationPhase::BackupCapture,
            Self::Transferring => DurableOperationPhase::BackupTransfer,
            Self::Verifying => DurableOperationPhase::BackupVerification,
            Self::Publishing => DurableOperationPhase::BackupPublication,
        }
    }
    pub(super) fn progress(self) -> u8 {
        match self {
            Self::Capturing => 20,
            Self::Transferring => 50,
            Self::Verifying => 80,
            Self::Publishing => 95,
        }
    }
}

/// Verified signed Registry cleanup, distinct from a restorable snapshot receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupCleanupReceipt {
    snapshot: [u8; 16],
    manifest: [u8; 32],
    registry: [u8; 32],
    deleted: u32,
    absent: u32,
    shared: u32,
}
impl BackupCleanupReceipt {
    pub fn new(
        snapshot: [u8; 16],
        manifest: [u8; 32],
        registry: [u8; 32],
        deleted: u32,
        absent: u32,
        shared: u32,
    ) -> Result<Self, DurableOperationFailure> {
        if snapshot == [0; 16]
            || manifest == [0; 32]
            || registry == [0; 32]
            || deleted
                .checked_add(absent)
                .and_then(|count| count.checked_add(shared))
                .is_none()
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            snapshot,
            manifest,
            registry,
            deleted,
            absent,
            shared,
        })
    }
    pub const fn snapshot_id(self) -> [u8; 16] {
        self.snapshot
    }
    pub const fn manifest_checksum(self) -> [u8; 32] {
        self.manifest
    }
    pub const fn registry_generation(self) -> [u8; 32] {
        self.registry
    }
    pub const fn deleted_objects(self) -> u32 {
        self.deleted
    }
    pub const fn already_absent_objects(self) -> u32 {
        self.absent
    }
    pub const fn retained_shared_objects(self) -> u32 {
        self.shared
    }
    pub(crate) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.snapshot);
        bytes.extend_from_slice(&self.manifest);
        bytes.extend_from_slice(&self.registry);
        for count in [self.deleted, self.absent, self.shared] {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        if bytes.len() != 92 {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        let mut offset = 0;
        let snapshot = codec::take_array(bytes, &mut offset)?;
        let manifest = codec::take_array(bytes, &mut offset)?;
        let registry = codec::take_array(bytes, &mut offset)?;
        let deleted = u32::from_be_bytes(codec::take_array(bytes, &mut offset)?);
        let absent = u32::from_be_bytes(codec::take_array(bytes, &mut offset)?);
        let shared = u32::from_be_bytes(codec::take_array(bytes, &mut offset)?);
        Self::new(snapshot, manifest, registry, deleted, absent, shared)
    }
}

/// Exact registered snapshot selected for irreversible retention expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRetentionParameters {
    repository: RepositoryOperationParameters,
    registration: [u8; 32],
    snapshot: [u8; 16],
    manifest: [u8; 32],
}
impl BackupRetentionParameters {
    pub fn new(
        repository: RepositoryOperationParameters,
        registration: [u8; 32],
        snapshot: [u8; 16],
        manifest: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if repository.action() != RepositoryAction::Verify
            || registration == [0; 32]
            || snapshot == [0; 16]
            || manifest == [0; 32]
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            repository,
            registration,
            snapshot,
            manifest,
        })
    }
    pub const fn repository(self) -> RepositoryOperationParameters {
        self.repository
    }
    pub const fn registration_identity(self) -> [u8; 32] {
        self.registration
    }
    pub const fn snapshot_id(self) -> [u8; 16] {
        self.snapshot
    }
    pub const fn manifest_checksum(self) -> [u8; 32] {
        self.manifest
    }
    pub fn intent_digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron-backup-retention-request-v1\0");
        hash.update(self.repository.intent_digest());
        hash.update(self.registration);
        hash.update(self.snapshot);
        hash.update(self.manifest);
        hash.finalize().into()
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.registration);
        bytes.extend_from_slice(&self.snapshot);
        bytes.extend_from_slice(&self.manifest);
        self.repository.encode(bytes);
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let registration = codec::take_array(bytes, &mut offset)?;
        let snapshot = codec::take_array(bytes, &mut offset)?;
        let manifest = codec::take_array(bytes, &mut offset)?;
        let repository = RepositoryOperationParameters::decode(
            bytes
                .get(offset..)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )?;
        Self::new(repository, registration, snapshot, manifest)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
    }
}

/// Evidence that the signed Registry has irreversibly unpublished the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRetentionClaimReceipt([u8; 32]);
impl BackupRetentionClaimReceipt {
    pub fn new(registry: [u8; 32]) -> Result<Self, DurableOperationFailure> {
        if registry == [0; 32] {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self(registry))
    }
    pub const fn registry_generation(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRetentionStage {
    Scanning,
    Publishing,
}

/// One operation owns exactly one accepted Backup intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupOperationParameters {
    Snapshot(BackupSnapshotParameters),
    Retention(BackupRetentionParameters),
}
impl BackupOperationParameters {
    pub const fn repository(self) -> RepositoryOperationParameters {
        match self {
            Self::Snapshot(value) => value.repository(),
            Self::Retention(value) => value.repository(),
        }
    }
    pub const fn registration_identity(self) -> [u8; 32] {
        match self {
            Self::Snapshot(value) => value.registration_identity(),
            Self::Retention(value) => value.registration_identity(),
        }
    }
    pub fn intent_digest(self) -> [u8; 32] {
        match self {
            Self::Snapshot(value) => value.intent_digest(),
            Self::Retention(value) => value.intent_digest(),
        }
    }
}

/// Mutually exclusive evidence for the current irreversible Backup state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BackupOperationEvidence {
    Snapshot(BackupOperationReceipt),
    RetentionClaim(BackupRetentionClaimReceipt),
    Cleanup(BackupCleanupReceipt),
}
