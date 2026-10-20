//! Non-secret exact Repository binding carried by Backup operation audit records.
use super::*;
use crate::{BackupOperationReceipt, RepositoryOperationParameters, RepositoryProviderKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRepositoryAuditIdentity {
    instance: [u8; 16],
    provider: RepositoryProviderKind,
    repository: [u8; 16],
    fingerprint: [u8; 32],
    prefix: [u8; 32],
}
impl BackupRepositoryAuditIdentity {
    pub(crate) fn new(instance: [u8; 16], parameters: RepositoryOperationParameters) -> Self {
        Self {
            instance,
            provider: parameters.provider_kind(),
            repository: parameters.repository_id(),
            fingerprint: parameters.integrity_fingerprint(),
            prefix: parameters.prefix_commitment(),
        }
    }
    pub const fn instance_id(self) -> [u8; 16] {
        self.instance
    }
    pub const fn provider_kind(self) -> RepositoryProviderKind {
        self.provider
    }
    pub const fn repository_id(self) -> [u8; 16] {
        self.repository
    }
    pub const fn integrity_fingerprint(self) -> [u8; 32] {
        self.fingerprint
    }
    pub const fn prefix_commitment(self) -> [u8; 32] {
        self.prefix
    }
    pub(crate) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.instance);
        bytes.push(match self.provider {
            RepositoryProviderKind::LocalFilesystem => 1,
            RepositoryProviderKind::AwsS3 => 2,
            RepositoryProviderKind::GoogleCloudStorage => 3,
            RepositoryProviderKind::AzureBlob => 4,
        });
        bytes.extend_from_slice(&self.repository);
        bytes.extend_from_slice(&self.fingerprint);
        bytes.extend_from_slice(&self.prefix);
    }
    pub(super) fn decode(cursor: &mut Cursor<'_>) -> Result<Self, IdentityFailure> {
        let instance = cursor.take_array()?;
        let provider = match cursor.take_u8()? {
            1 => RepositoryProviderKind::LocalFilesystem,
            2 => RepositoryProviderKind::AwsS3,
            3 => RepositoryProviderKind::GoogleCloudStorage,
            4 => RepositoryProviderKind::AzureBlob,
            _ => return Err(IdentityFailure),
        };
        let repository = cursor.take_array()?;
        let fingerprint = cursor.take_array()?;
        let prefix = cursor.take_array()?;
        if instance == [0; 16]
            || repository == [0; 16]
            || fingerprint == [0; 32]
            || prefix == [0; 32]
        {
            return Err(IdentityFailure);
        }
        Ok(Self {
            instance,
            provider,
            repository,
            fingerprint,
            prefix,
        })
    }
}

type BackupAuditFields = (
    BackupRepositoryAuditIdentity,
    Option<BackupOperationReceipt>,
    Option<crate::BackupCleanupReceipt>,
    Option<crate::BackupRetentionClaimReceipt>,
    Option<[u8; 32]>,
    Option<crate::RestoredBackupPublication>,
);

pub(super) fn decode_backup_evidence(
    cursor: &mut Cursor<'_>,
    action: DurableOperationKind,
    outcome: DurableOperationStatus,
    target: Option<[u8; 16]>,
) -> Result<BackupAuditFields, IdentityFailure> {
    if !matches!(
        action,
        DurableOperationKind::BackupSnapshot
            | DurableOperationKind::BackupRetention
            | DurableOperationKind::BackupVerification
    ) {
        return Err(IdentityFailure);
    }
    let repository = BackupRepositoryAuditIdentity::decode(cursor)?;
    if target != Some(repository.instance_id()) {
        return Err(IdentityFailure);
    }
    let tag = cursor.take_u8()?;
    if action == DurableOperationKind::BackupVerification {
        let report = match tag {
            0 => None,
            4 => Some(cursor.take_array::<32>()?),
            _ => return Err(IdentityFailure),
        };
        if (outcome == DurableOperationStatus::Succeeded) != report.is_some()
            || report == Some([0; 32])
        {
            return Err(IdentityFailure);
        }
        return Ok((repository, None, None, None, report, None));
    }
    if tag == 5 {
        if action != DurableOperationKind::BackupSnapshot
            || outcome != DurableOperationStatus::Succeeded
        {
            return Err(IdentityFailure);
        }
        let publication = crate::RestoredBackupPublication::decode(cursor.take_exact(224)?)
            .map_err(|_| IdentityFailure)?;
        return Ok((repository, None, None, None, None, Some(publication)));
    }
    let (receipt, cleanup, claim) = match tag {
        0 => (None, None, None),
        1 => (
            Some(
                BackupOperationReceipt::decode(cursor.take_exact(128)?)
                    .map_err(|_| IdentityFailure)?,
            ),
            None,
            None,
        ),
        2 => (
            None,
            Some(
                crate::BackupCleanupReceipt::decode(cursor.take_exact(92)?)
                    .map_err(|_| IdentityFailure)?,
            ),
            None,
        ),
        3 => (
            None,
            None,
            Some(
                crate::BackupRetentionClaimReceipt::new(cursor.take_array()?)
                    .map_err(|_| IdentityFailure)?,
            ),
        ),
        _ => return Err(IdentityFailure),
    };
    if action == DurableOperationKind::BackupSnapshot {
        if claim.is_some() {
            return Err(IdentityFailure);
        }
        if cleanup.is_some()
            && !matches!(
                outcome,
                DurableOperationStatus::Cancelled | DurableOperationStatus::Failed
            )
        {
            return Err(IdentityFailure);
        }
        if (outcome == DurableOperationStatus::Succeeded) != receipt.is_some() {
            return Err(IdentityFailure);
        }
    } else if receipt.is_some()
        || (cleanup.is_some() != (outcome == DurableOperationStatus::Succeeded))
        || (claim.is_some() && outcome != DurableOperationStatus::Running)
    {
        return Err(IdentityFailure);
    }
    Ok((repository, receipt, cleanup, claim, None, None))
}
