//! Bounded release and recovery identities for one declarative Upgrade.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeReleaseIdentity {
    manifest: [u8; 32],
    artifact: [u8; 32],
    version: [u32; 3],
}
impl UpgradeReleaseIdentity {
    pub fn new(
        manifest: [u8; 32],
        artifact: [u8; 32],
        version: [u32; 3],
    ) -> Result<Self, DurableOperationFailure> {
        if manifest == [0; 32] || artifact == [0; 32] {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            manifest,
            artifact,
            version,
        })
    }
    pub const fn manifest_digest(self) -> [u8; 32] {
        self.manifest
    }
    pub const fn artifact_digest(self) -> [u8; 32] {
        self.artifact
    }
    pub const fn version(self) -> [u32; 3] {
        self.version
    }
    fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.manifest);
        bytes.extend_from_slice(&self.artifact);
        for value in self.version {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    fn decode(bytes: &[u8], offset: &mut usize) -> Result<Self, DurableOperationFailure> {
        Self::new(
            codec::take_array(bytes, offset)?,
            codec::take_array(bytes, offset)?,
            [
                u32::from_be_bytes(codec::take_array(bytes, offset)?),
                u32::from_be_bytes(codec::take_array(bytes, offset)?),
                u32::from_be_bytes(codec::take_array(bytes, offset)?),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeParameters {
    source: UpgradeReleaseIdentity,
    target: UpgradeReleaseIdentity,
    epoch: u32,
    configuration: [u8; 32],
    backup: BackupSnapshotParameters,
}
impl UpgradeParameters {
    pub fn new(
        source: UpgradeReleaseIdentity,
        target: UpgradeReleaseIdentity,
        format_epoch: u32,
        configuration: [u8; 32],
        backup: BackupSnapshotParameters,
    ) -> Result<Self, DurableOperationFailure> {
        if source == target || !matches!(format_epoch, 1 | 2) || configuration == [0; 32] {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            source,
            target,
            epoch: format_epoch,
            configuration,
            backup,
        })
    }
    pub const fn source(self) -> UpgradeReleaseIdentity {
        self.source
    }
    pub const fn target(self) -> UpgradeReleaseIdentity {
        self.target
    }
    pub const fn format_epoch(self) -> u32 {
        self.epoch
    }
    pub const fn configuration_digest(self) -> [u8; 32] {
        self.configuration
    }
    pub const fn backup(self) -> BackupSnapshotParameters {
        self.backup
    }
    pub fn intent_digest(self) -> [u8; 32] {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        let mut hash = Sha256::new();
        hash.update(b"positron.upgrade.intent.v1\0");
        hash.update(bytes);
        hash.finalize().into()
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        self.source.encode(bytes);
        self.target.encode(bytes);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.configuration);
        self.backup.encode(bytes);
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let source = UpgradeReleaseIdentity::decode(bytes, &mut offset)?;
        let target = UpgradeReleaseIdentity::decode(bytes, &mut offset)?;
        let epoch = u32::from_be_bytes(codec::take_array(bytes, &mut offset)?);
        let configuration = codec::take_array(bytes, &mut offset)?;
        let backup = BackupSnapshotParameters::decode(
            bytes
                .get(offset..)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )?;
        Self::new(source, target, epoch, configuration, backup)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeStage {
    Preflight,
    Draining,
    Snapshot,
    Publishing,
    AwaitingRestart,
    Verifying,
    Succeeded,
}
impl UpgradeStage {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Preflight => 1,
            Self::Draining => 2,
            Self::Snapshot => 3,
            Self::Publishing => 4,
            Self::AwaitingRestart => 5,
            Self::Verifying => 6,
            Self::Succeeded => 7,
        }
    }
    pub(super) fn from_code(code: u8) -> Result<Self, DurableOperationFailure> {
        match code {
            1 => Ok(Self::Preflight),
            2 => Ok(Self::Draining),
            3 => Ok(Self::Snapshot),
            4 => Ok(Self::Publishing),
            5 => Ok(Self::AwaitingRestart),
            6 => Ok(Self::Verifying),
            7 => Ok(Self::Succeeded),
            _ => Err(DurableOperationFailure::PersistenceUnavailable),
        }
    }
    pub(super) const fn phase(self) -> DurableOperationPhase {
        match self {
            Self::Preflight => DurableOperationPhase::Preflight,
            Self::Draining => DurableOperationPhase::Draining,
            Self::Snapshot => DurableOperationPhase::BackupCapture,
            Self::Publishing => DurableOperationPhase::CatalogPublication,
            Self::AwaitingRestart => DurableOperationPhase::Published,
            Self::Verifying => DurableOperationPhase::BackupVerification,
            Self::Succeeded => DurableOperationPhase::Published,
        }
    }
    pub(super) const fn progress(self) -> u8 {
        match self {
            Self::Preflight => 10,
            Self::Draining => 20,
            Self::Snapshot => 40,
            Self::Publishing => 60,
            Self::AwaitingRestart => 80,
            Self::Verifying => 90,
            Self::Succeeded => 100,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeDrainEvidence {
    pub(super) catalog: [u8; 32],
    pub(super) generation: u64,
    pub(super) marker: [u8; 32],
    pub(super) transaction: [u8; 16],
}
impl UpgradeDrainEvidence {
    /// Runtime authenticates the Graceful Shutdown Record before constructing this binding.
    pub fn new(
        catalog: [u8; 32],
        generation: u64,
        marker: [u8; 32],
        transaction: [u8; 16],
    ) -> Result<Self, DurableOperationFailure> {
        if catalog == [0; 32] || generation == 0 || marker == [0; 32] || transaction == [0; 16] {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            catalog,
            generation,
            marker,
            transaction,
        })
    }
    pub const fn catalog_identity(self) -> [u8; 32] {
        self.catalog
    }
    pub const fn catalog_generation(self) -> u64 {
        self.generation
    }
    pub const fn marker_identity(self) -> [u8; 32] {
        self.marker
    }
    pub const fn transaction(self) -> [u8; 16] {
        self.transaction
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeSnapshotEvidence {
    pub(super) operation: OperationId,
    pub(super) verification: OperationId,
    pub(super) receipt: BackupOperationReceipt,
}
impl UpgradeSnapshotEvidence {
    pub const fn operation_id(self) -> OperationId {
        self.operation
    }
    pub const fn verification_operation_id(self) -> OperationId {
        self.verification
    }
    pub const fn receipt(self) -> BackupOperationReceipt {
        self.receipt
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct UpgradeProgress {
    pub(super) report: Option<[u8; 32]>,
    pub(super) rollback: Option<AdministrativeIdempotencyKey>,
    pub(super) stage: UpgradeStage,
    pub(super) drain: Option<UpgradeDrainEvidence>,
    pub(super) snapshot: Option<UpgradeSnapshotEvidence>,
}
impl UpgradeProgress {
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.push(self.stage.code());
        bytes.push(u8::from(self.drain.is_some()));
        if let Some(drain) = self.drain {
            bytes.extend_from_slice(&drain.catalog);
            bytes.extend_from_slice(&drain.generation.to_be_bytes());
            bytes.extend_from_slice(&drain.marker);
            bytes.extend_from_slice(&drain.transaction);
        }
        bytes.push(u8::from(self.snapshot.is_some()));
        if let Some(snapshot) = self.snapshot {
            bytes.extend_from_slice(&snapshot.operation.to_bytes());
            bytes.extend_from_slice(&snapshot.verification.to_bytes());
            snapshot.receipt.encode(bytes);
        }
        bytes.push(u8::from(self.rollback.is_some()));
        if let Some(key) = self.rollback {
            bytes.extend_from_slice(&key.to_bytes());
        }
        bytes.push(u8::from(self.report.is_some()));
        if let Some(report) = self.report {
            bytes.extend_from_slice(&report);
        }
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let stage = UpgradeStage::from_code(codec::take_byte(bytes, &mut offset)?)?;
        let drain = match codec::take_byte(bytes, &mut offset)? {
            0 => None,
            1 => Some(UpgradeDrainEvidence::new(
                codec::take_array(bytes, &mut offset)?,
                codec::take_u64(bytes, &mut offset)?,
                codec::take_array(bytes, &mut offset)?,
                codec::take_array(bytes, &mut offset)?,
            )?),
            _ => return Err(DurableOperationFailure::PersistenceUnavailable),
        };
        let snapshot = match codec::take_byte(bytes, &mut offset)? {
            0 => None,
            1 => {
                let operation = OperationId::from_bytes(codec::take_array(bytes, &mut offset)?)?;
                let verification = OperationId::from_bytes(codec::take_array(bytes, &mut offset)?)?;
                let end = offset
                    .checked_add(128)
                    .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
                let receipt = BackupOperationReceipt::decode(
                    bytes
                        .get(offset..end)
                        .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
                )?;
                offset = end;
                Some(UpgradeSnapshotEvidence {
                    operation,
                    verification,
                    receipt,
                })
            },
            _ => return Err(DurableOperationFailure::PersistenceUnavailable),
        };
        let rollback = match codec::take_byte(bytes, &mut offset)? {
            0 => None,
            1 => Some(
                AdministrativeIdempotencyKey::new(codec::take_array(bytes, &mut offset)?)
                    .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?,
            ),
            _ => return Err(DurableOperationFailure::PersistenceUnavailable),
        };
        let report = match codec::take_byte(bytes, &mut offset)? {
            0 => None,
            1 => {
                let value = codec::take_array(bytes, &mut offset)?;
                if value == [0; 32] {
                    return Err(DurableOperationFailure::PersistenceUnavailable);
                }
                Some(value)
            },
            _ => return Err(DurableOperationFailure::PersistenceUnavailable),
        };
        if offset != bytes.len() {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Ok(Self {
            report,
            rollback,
            stage,
            drain,
            snapshot,
        })
    }
}
