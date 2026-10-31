//! Native artifact references extend the existing authenticated task checkpoint.
use super::*;
use crate::BackupVerificationReference;

const MAGIC: &[u8; 8] = b"BKVREF01";
const PREFIX_BYTES: usize = 80;

pub(super) fn unpack(
    bytes: &[u8],
) -> Result<(Option<BackupVerificationReference>, &[u8]), MaintenanceFailure> {
    if !bytes.starts_with(MAGIC) {
        return Ok((None, bytes));
    }
    let identity = bytes
        .get(8..40)
        .and_then(|value| value.try_into().ok())
        .ok_or(MaintenanceFailure::PreconditionFailed)?;
    let sequence = u64::from_be_bytes(
        bytes
            .get(40..48)
            .and_then(|value| value.try_into().ok())
            .ok_or(MaintenanceFailure::PreconditionFailed)?,
    );
    let predecessor = bytes
        .get(48..80)
        .and_then(|value| value.try_into().ok())
        .ok_or(MaintenanceFailure::PreconditionFailed)?;
    if identity == [0; 32] || sequence == 0 || (sequence == 1) != (predecessor == [0; 32]) {
        return Err(MaintenanceFailure::PreconditionFailed);
    }
    Ok((
        Some(BackupVerificationReference {
            identity,
            sequence,
            predecessor,
        }),
        bytes
            .get(PREFIX_BYTES..)
            .ok_or(MaintenanceFailure::PreconditionFailed)?,
    ))
}

impl RepositoryOperationBinding {
    pub(in crate::maintenance) fn reference_free_task(
        task: &MaintenanceTask,
        checkpoint: Option<&MaintenanceCheckpoint>,
    ) -> bool {
        if Self::from_task(task, checkpoint).is_err() {
            return false;
        }
        checkpoint
            .and_then(|value| value.opaque_progress().get(56..))
            .is_some_and(|bytes| matches!(unpack(bytes), Ok((None, _))))
    }

    /// Reads the native reference from the current exact persisted dispatch,
    /// never from the execution's possibly stale starting checkpoint.
    pub fn current_backup_verification_reference(
        self,
        coordinator: &MaintenanceCoordinator,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<Option<BackupVerificationReference>, MaintenanceFailure> {
        let checkpoint = self.current_backup_checkpoint(coordinator, execution)?;
        let bytes = checkpoint
            .opaque_progress()
            .get(56..)
            .ok_or(MaintenanceFailure::PreconditionFailed)?;
        unpack(bytes).map(|(reference, _)| reference)
    }

    /// Publication uses the same task/Catalog transaction and legacy handler body.
    pub fn backup_verification_checkpoint(
        self,
        sequence: u64,
        progress: &[u8],
        reference: BackupVerificationReference,
    ) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
        if progress.len() > MAX_CHECKPOINT_BYTES - 56 - PREFIX_BYTES {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(PREFIX_BYTES + progress.len())
            .map_err(|_| MaintenanceFailure::ResourceAdmissionRefused)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&reference.identity);
        bytes.extend_from_slice(&reference.sequence.to_be_bytes());
        bytes.extend_from_slice(&reference.predecessor);
        bytes.extend_from_slice(progress);
        unpack(&bytes)?;
        self.backup_checkpoint(sequence, &bytes)
    }
}
