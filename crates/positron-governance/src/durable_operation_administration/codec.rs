//! Durable-operation persisted-record and audit codecs.

use positron_domain::identity::{PrincipalId, TenantId};

use super::{
    DurableOperation, DurableOperationBoundary, DurableOperationCancellation,
    DurableOperationFailure, DurableOperationKind, DurableOperationPhase, DurableOperationRequest,
    DurableOperationRetry, DurableOperationStatus, DurableOperationTerminalError,
};
use crate::AdministrativeIdempotencyKey;

const OPERATION_MAGIC_V1: [u8; 8] = *b"POSOPR01";
const OPERATION_MAGIC_V2: [u8; 8] = *b"POSOPR02";
const OPERATION_MAGIC_V3: [u8; 8] = *b"POSOPR03";
const OPERATION_MAGIC: [u8; 8] = *b"POSOPR04";
const REPOSITORY_PARAMETERS_MAGIC: [u8; 8] = *b"POSREP02";
const VERIFICATION_PARAMETERS_MAGIC: [u8; 8] = *b"POSBVP01";
const VERIFICATION_REPORT_MAGIC: [u8; 8] = *b"POSBVE01";
const BACKUP_PARAMETERS_MAGIC: [u8; 8] = *b"POSBKP01";
const RETENTION_PARAMETERS_MAGIC: [u8; 8] = *b"POSBRP01";
const RETENTION_CLAIM_MAGIC: [u8; 8] = *b"POSBRC01";
const BACKUP_CLEANUP_MAGIC: [u8; 8] = *b"POSBCE01";
const BACKUP_RECEIPT_MAGIC: [u8; 8] = *b"POSBKR02";
const ROOT_PARAMETERS_MAGIC: [u8; 8] = *b"POSKPM01";
const EXPIRED_OPERATION_BINDING_MAGIC_V1: [u8; 8] = *b"POSOPX01";
const EXPIRED_OPERATION_BINDING_MAGIC_V2: [u8; 8] = *b"POSOPX02";
const EXPIRED_OPERATION_BINDING_MAGIC: [u8; 8] = *b"POSOPX03";
const OPERATION_AUDIT_MAGIC: [u8; 8] = *b"POSOPA05";

pub(super) fn encode_operation(operation: DurableOperation) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(217);
    encoded.extend_from_slice(&OPERATION_MAGIC);
    encoded.extend_from_slice(&operation.operation_id().to_bytes());
    encoded.extend_from_slice(&operation.request.principal.to_bytes());
    encoded.extend_from_slice(&operation.request.idempotency.to_bytes());
    encoded.push(operation.request.kind.code());
    encoded.extend_from_slice(&operation.request.target_identity.unwrap_or([0; 16]));
    encoded.extend_from_slice(
        &operation
            .request
            .applicable_tenant
            .map_or([0; 16], TenantId::to_bytes),
    );
    encoded.extend_from_slice(&operation.request.accepted_generation.to_be_bytes());
    encoded.extend_from_slice(&operation.request.accepted_at_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(
        &operation
            .request
            .operation_request_digest
            .unwrap_or([0; 32]),
    );
    encoded.extend_from_slice(&operation.request.digest);
    encoded.push(operation.status.code());
    encoded.push(operation.phase.code());
    encoded.push(operation.progress_percent);
    encoded.push(operation.retry.code());
    encoded.push(operation.cancellation.code());
    encoded.push(operation.boundary.code());
    let (terminal_error, terminal_detail) = operation
        .terminal_error
        .map_or((0, 0), DurableOperationTerminalError::encoded);
    encoded.push(terminal_error);
    encoded.push(terminal_detail);
    encoded.extend_from_slice(&operation.updated_at_unix_seconds.to_be_bytes());
    encoded.extend_from_slice(
        &operation
            .completed_at_unix_seconds
            .unwrap_or(0)
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&operation.revision.to_be_bytes());
    match operation.cancellation_idempotency {
        Some(idempotency) => {
            encoded.push(1);
            encoded.extend_from_slice(&idempotency.to_bytes());
        },
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0; 16]);
        },
    }
    if let Some(parameters) = operation.backup_parameters {
        match parameters {
            super::BackupOperationParameters::Verification(value) => {
                encoded.extend_from_slice(&VERIFICATION_PARAMETERS_MAGIC);
                value.encode(&mut encoded);
            },
            super::BackupOperationParameters::Snapshot(value) => {
                encoded.extend_from_slice(&BACKUP_PARAMETERS_MAGIC);
                value.encode(&mut encoded);
            },
            super::BackupOperationParameters::Retention(value) => {
                encoded.extend_from_slice(&RETENTION_PARAMETERS_MAGIC);
                value.encode(&mut encoded);
            },
        }
        match operation.backup_evidence {
            Some(super::backup_parameters::BackupOperationEvidence::VerificationReport(value)) => {
                encoded.extend_from_slice(&VERIFICATION_REPORT_MAGIC);
                encoded.extend_from_slice(&value);
            },
            Some(super::backup_parameters::BackupOperationEvidence::Snapshot(value)) => {
                encoded.extend_from_slice(&BACKUP_RECEIPT_MAGIC);
                value.encode(&mut encoded);
            },
            Some(super::backup_parameters::BackupOperationEvidence::Cleanup(value)) => {
                encoded.extend_from_slice(&BACKUP_CLEANUP_MAGIC);
                value.encode(&mut encoded);
            },
            Some(super::backup_parameters::BackupOperationEvidence::RetentionClaim(value)) => {
                encoded.extend_from_slice(&RETENTION_CLAIM_MAGIC);
                encoded.extend_from_slice(&value.registry_generation());
            },
            None => {},
        }
    }
    if let Some(parameters) = operation.key_provider_migration_parameters {
        encoded.extend_from_slice(&ROOT_PARAMETERS_MAGIC);
        parameters.encode(&mut encoded);
    }
    if let Some(parameters) = operation.repository_parameters {
        encoded.extend_from_slice(&REPOSITORY_PARAMETERS_MAGIC);
        parameters.encode(&mut encoded);
        if let Some(policy) = operation.repository_policy {
            encoded.extend(policy.encoded_bytes());
        }
    }
    encoded
}

#[cfg(test)]
pub(crate) fn pending_operation_fixture(request: DurableOperationRequest) -> Vec<u8> {
    encode_operation(DurableOperation::accepted(request))
}

pub(super) fn encode_expired_binding(request: DurableOperationRequest) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(145);
    encoded.extend_from_slice(&EXPIRED_OPERATION_BINDING_MAGIC);
    encoded.extend_from_slice(&request.principal.to_bytes());
    encoded.extend_from_slice(&request.idempotency.to_bytes());
    encoded.push(request.kind.code());
    encoded.extend_from_slice(&request.target_identity.unwrap_or([0; 16]));
    encoded.extend_from_slice(
        &request
            .applicable_tenant
            .map_or([0; 16], TenantId::to_bytes),
    );
    encoded.extend_from_slice(&request.accepted_generation.to_be_bytes());
    encoded.extend_from_slice(&request.operation_request_digest.unwrap_or([0; 32]));
    encoded.extend_from_slice(&request.digest);
    encoded
}

pub(super) fn decode_expired_binding(
    encoded: &[u8],
) -> Result<Option<ExpiredOperationBinding>, DurableOperationFailure> {
    let v3 = encoded.starts_with(&EXPIRED_OPERATION_BINDING_MAGIC);
    let v2 = encoded.starts_with(&EXPIRED_OPERATION_BINDING_MAGIC_V2);
    if !v3 && !v2 && !encoded.starts_with(&EXPIRED_OPERATION_BINDING_MAGIC_V1) {
        return Ok(None);
    }
    if encoded.len()
        != if v3 {
            145
        } else if v2 {
            129
        } else {
            97
        }
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let mut offset = 8_usize;
    let principal = PrincipalId::from_bytes(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let idempotency = AdministrativeIdempotencyKey::new(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let kind = DurableOperationKind::from_code(take_byte(encoded, &mut offset)?)?;
    let target_identity = {
        let target = take_array::<16>(encoded, &mut offset)?;
        (!target.iter().all(|byte| *byte == 0)).then_some(target)
    };
    let applicable_tenant = if v3 {
        let tenant = take_array::<16>(encoded, &mut offset)?;
        (!tenant.iter().all(|byte| *byte == 0))
            .then(|| TenantId::from_bytes(tenant))
            .transpose()
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?
    } else {
        None
    };
    let accepted_generation = take_u64(encoded, &mut offset)?;
    let operation_request_digest = if v2 || v3 {
        let digest = take_array(encoded, &mut offset)?;
        (!digest.iter().all(|byte| *byte == 0)).then_some(digest)
    } else {
        None
    };
    let digest = take_array(encoded, &mut offset)?;
    if accepted_generation == 0 || digest.iter().all(|byte| *byte == 0) || offset != encoded.len() {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let request = DurableOperationRequest {
        principal,
        idempotency,
        kind,
        target_identity,
        applicable_tenant,
        accepted_generation,
        accepted_at_unix_seconds: 1,
        operation_request_digest,
        digest,
    };
    if !request.is_valid_persisted_request() {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    Ok(Some(ExpiredOperationBinding { request }))
}

pub(super) fn decode_operation(
    encoded: &[u8],
) -> Result<Option<DurableOperation>, DurableOperationFailure> {
    let v4 = encoded.starts_with(&OPERATION_MAGIC);
    // Keeping the recognized outer magic makes old readers reject the newer
    // root-kind layout by their exact-length check, rather than ignore it.
    let root_parameters = v4 && encoded.get(56) == Some(&4);
    let repository_parameters_present = v4 && encoded.get(56) == Some(&5);
    let backup_parameters_present = v4 && matches!(encoded.get(56), Some(6..=8));
    let v3 = encoded.starts_with(&OPERATION_MAGIC_V3);
    let v2 = encoded.starts_with(&OPERATION_MAGIC_V2);
    if !v4 && !v3 && !v2 && !encoded.starts_with(&OPERATION_MAGIC_V1) {
        return Ok(None);
    }
    if (backup_parameters_present && !(351..=2688).contains(&encoded.len()))
        || (repository_parameters_present && !(310..=2428).contains(&encoded.len()))
        || (root_parameters && !(261..=2309).contains(&encoded.len()))
        || (!root_parameters
            && !repository_parameters_present
            && !backup_parameters_present
            && encoded.len()
                != if v4 {
                    218
                } else if v3 {
                    217
                } else if v2 {
                    201
                } else {
                    169
                })
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let mut offset = 8_usize;
    let operation_id = take_array::<16>(encoded, &mut offset)?;
    let principal = PrincipalId::from_bytes(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let idempotency = AdministrativeIdempotencyKey::new(take_array(encoded, &mut offset)?)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let kind = DurableOperationKind::from_code(take_byte(encoded, &mut offset)?)?;
    let target = take_array(encoded, &mut offset)?;
    let target_identity = (!target.iter().all(|byte| *byte == 0)).then_some(target);
    let applicable_tenant = if v3 || v4 {
        let tenant = take_array::<16>(encoded, &mut offset)?;
        (!tenant.iter().all(|byte| *byte == 0))
            .then(|| TenantId::from_bytes(tenant))
            .transpose()
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?
    } else {
        None
    };
    let accepted_generation = take_u64(encoded, &mut offset)?;
    let accepted_at_unix_seconds = take_u64(encoded, &mut offset)?;
    let operation_request_digest = if v2 || v3 || v4 {
        let digest = take_array(encoded, &mut offset)?;
        (!digest.iter().all(|byte| *byte == 0)).then_some(digest)
    } else {
        None
    };
    let digest = take_array(encoded, &mut offset)?;
    let request = DurableOperationRequest {
        principal,
        idempotency,
        kind,
        target_identity,
        applicable_tenant,
        accepted_generation,
        accepted_at_unix_seconds,
        operation_request_digest,
        digest,
    };
    if request.operation_id().to_bytes() != operation_id
        || accepted_generation == 0
        || accepted_at_unix_seconds == 0
    {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let status = DurableOperationStatus::from_code(take_byte(encoded, &mut offset)?)?;
    let phase = DurableOperationPhase::from_code(take_byte(encoded, &mut offset)?)?;
    let progress_percent = take_byte(encoded, &mut offset)?;
    if progress_percent > 100 {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let retry = DurableOperationRetry::from_code(take_byte(encoded, &mut offset)?)?;
    let cancellation = DurableOperationCancellation::from_code(take_byte(encoded, &mut offset)?)?;
    let boundary = DurableOperationBoundary::from_code(take_byte(encoded, &mut offset)?)?;
    let terminal_error_code = take_byte(encoded, &mut offset)?;
    let terminal_error_detail = if v4 {
        take_byte(encoded, &mut offset)?
    } else {
        0
    };
    let terminal_error = match terminal_error_code {
        0 => None,
        code => Some(DurableOperationTerminalError::from_encoded(
            code,
            terminal_error_detail,
        )?),
    };
    let updated_at_unix_seconds = take_u64(encoded, &mut offset)?;
    let completed = take_u64(encoded, &mut offset)?;
    let revision = take_u64(encoded, &mut offset)?;
    let cancellation_idempotency = match take_byte(encoded, &mut offset)? {
        0 => {
            if !take_array::<16>(encoded, &mut offset)?
                .iter()
                .all(|byte| *byte == 0)
            {
                return Err(DurableOperationFailure::PersistenceUnavailable);
            }
            None
        },
        1 => Some(
            AdministrativeIdempotencyKey::new(take_array(encoded, &mut offset)?)
                .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?,
        ),
        _ => return Err(DurableOperationFailure::PersistenceUnavailable),
    };
    let key_provider_migration_parameters = if root_parameters {
        if take_array::<8>(encoded, &mut offset)? != ROOT_PARAMETERS_MAGIC {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        let parameters = super::KeyProviderMigrationParameters::decode(
            encoded
                .get(offset..)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )?;
        offset = encoded.len();
        Some(parameters)
    } else {
        None
    };
    let repository_parameters = if repository_parameters_present {
        if take_array::<8>(encoded, &mut offset)? != REPOSITORY_PARAMETERS_MAGIC {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        let length_offset = offset
            .checked_add(82)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let length_end = length_offset
            .checked_add(2)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let length = u16::from_be_bytes(
            encoded
                .get(length_offset..length_end)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        );
        let end = length_end
            .checked_add(usize::from(length))
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let parameters = super::RepositoryOperationParameters::decode(
            encoded
                .get(offset..end)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )?;
        offset = end;
        Some(parameters)
    } else {
        None
    };
    let repository_policy = if repository_parameters.is_some() && offset < encoded.len() {
        let policy = super::repository_policy_codec::decode(
            encoded
                .get(offset..)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )?;
        offset = encoded.len();
        Some(policy)
    } else {
        None
    };
    let (backup_parameters, backup_evidence) = if backup_parameters_present {
        let magic = take_array::<8>(encoded, &mut offset)?;
        let verification = request.kind() == DurableOperationKind::BackupVerification;
        let retention = request.kind() == DurableOperationKind::BackupRetention;
        if magic
            != if verification {
                VERIFICATION_PARAMETERS_MAGIC
            } else if retention {
                RETENTION_PARAMETERS_MAGIC
            } else {
                BACKUP_PARAMETERS_MAGIC
            }
        {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        let length_offset = offset
            .checked_add(if retention || verification { 162 } else { 122 })
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let length_end = length_offset
            .checked_add(2)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let locator = usize::from(u16::from_be_bytes(
            encoded
                .get(length_offset..length_end)
                .and_then(|value| value.try_into().ok())
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        ));
        let end = length_end
            .checked_add(locator)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let bytes = encoded
            .get(offset..end)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let parameters = if verification {
            super::BackupOperationParameters::Verification(
                super::BackupVerificationParameters::decode(bytes)?,
            )
        } else if retention {
            super::BackupOperationParameters::Retention(super::BackupRetentionParameters::decode(
                bytes,
            )?)
        } else {
            super::BackupOperationParameters::Snapshot(super::BackupSnapshotParameters::decode(
                bytes,
            )?)
        };
        offset = end;
        let evidence = if offset < encoded.len() {
            let magic = take_array::<8>(encoded, &mut offset)?;
            let bytes = encoded
                .get(offset..)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
            let value = if magic == VERIFICATION_REPORT_MAGIC {
                super::backup_parameters::BackupOperationEvidence::VerificationReport(
                    bytes
                        .try_into()
                        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?,
                )
            } else if magic == BACKUP_RECEIPT_MAGIC {
                super::backup_parameters::BackupOperationEvidence::Snapshot(
                    super::BackupOperationReceipt::decode(bytes)?,
                )
            } else if magic == BACKUP_CLEANUP_MAGIC {
                super::backup_parameters::BackupOperationEvidence::Cleanup(
                    super::BackupCleanupReceipt::decode(bytes)?,
                )
            } else if magic == RETENTION_CLAIM_MAGIC {
                super::backup_parameters::BackupOperationEvidence::RetentionClaim(
                    super::BackupRetentionClaimReceipt::new(
                        bytes
                            .try_into()
                            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?,
                    )
                    .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?,
                )
            } else {
                return Err(DurableOperationFailure::PersistenceUnavailable);
            };
            offset = encoded.len();
            Some(value)
        } else {
            None
        };
        (Some(parameters), evidence)
    } else {
        (None, None)
    };
    if offset != encoded.len() {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    let completed_at_unix_seconds = if completed == 0 {
        None
    } else {
        Some(completed)
    };
    let operation = DurableOperation {
        request,
        backup_parameters,
        backup_evidence,
        key_provider_migration_parameters,
        repository_parameters,
        repository_policy,
        status,
        phase,
        progress_percent,
        retry,
        cancellation,
        boundary,
        terminal_error,
        cancellation_idempotency,
        updated_at_unix_seconds,
        completed_at_unix_seconds,
        revision,
    };
    if !operation.is_legal_persisted_state() {
        return Err(DurableOperationFailure::PersistenceUnavailable);
    }
    Ok(Some(operation))
}

pub(super) fn take_array<const N: usize>(
    encoded: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], DurableOperationFailure> {
    let end = offset
        .checked_add(N)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    let bytes = encoded
        .get(*offset..end)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    *offset = end;
    bytes
        .try_into()
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
}

pub(super) fn take_byte(encoded: &[u8], offset: &mut usize) -> Result<u8, DurableOperationFailure> {
    take_array::<1>(encoded, offset).map(|[value]| value)
}
pub(super) fn take_u64(encoded: &[u8], offset: &mut usize) -> Result<u64, DurableOperationFailure> {
    Ok(u64::from_be_bytes(take_array(encoded, offset)?))
}

pub(super) fn encode_audit(
    operation: DurableOperation,
) -> Result<Vec<u8>, DurableOperationFailure> {
    let mut encoded = Vec::with_capacity(142);
    encoded.extend_from_slice(
        if matches!(
            operation.kind(),
            DurableOperationKind::BackupSnapshot
                | DurableOperationKind::BackupRetention
                | DurableOperationKind::BackupVerification
        ) {
            b"POSOPA06"
        } else {
            &OPERATION_AUDIT_MAGIC
        },
    );
    encoded.extend_from_slice(&operation.operation_id().to_bytes());
    encoded.extend_from_slice(&operation.request.principal.to_bytes());
    encoded.extend_from_slice(&operation.request.target_identity.unwrap_or([0; 16]));
    match operation.request.applicable_tenant {
        Some(tenant) => {
            encoded.push(1);
            encoded.extend_from_slice(&tenant.to_bytes());
        },
        None => encoded.push(0),
    }
    encoded.push(operation.request.kind.code());
    encoded.push(operation.status.code());
    encoded.push(operation.phase.code());
    encoded.extend_from_slice(&operation.request.idempotency.to_bytes());
    encoded.extend_from_slice(&operation.request.accepted_generation.to_be_bytes());
    encoded.extend_from_slice(
        &operation
            .request
            .operation_request_digest
            .unwrap_or([0; 32]),
    );
    encoded.push(operation.progress_percent);
    encoded.extend_from_slice(&operation.revision.to_be_bytes());
    match operation.cancellation_idempotency {
        Some(idempotency) => {
            encoded.push(1);
            encoded.extend_from_slice(&idempotency.to_bytes());
        },
        None => {
            encoded.push(0);
            encoded.extend_from_slice(&[0; 16]);
        },
    }
    if matches!(
        operation.kind(),
        DurableOperationKind::BackupSnapshot
            | DurableOperationKind::BackupRetention
            | DurableOperationKind::BackupVerification
    ) {
        let parameters = operation
            .backup_binding()
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let instance = operation
            .request
            .target_identity
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        crate::BackupRepositoryAuditIdentity::new(instance, parameters.repository())
            .encode(&mut encoded);
        if let Some(report) = operation.backup_verification_report() {
            encoded.push(4);
            encoded.extend_from_slice(&report);
            return Ok(encoded);
        }
        match operation.backup_receipt() {
            Some(receipt) => {
                encoded.push(1);
                receipt.encode(&mut encoded);
            },
            None => match operation.backup_cleanup_receipt() {
                Some(receipt) => {
                    encoded.push(2);
                    receipt.encode(&mut encoded);
                },
                None => match operation.backup_retention_claim() {
                    Some(receipt) => {
                        encoded.push(3);
                        encoded.extend_from_slice(&receipt.registry_generation());
                    },
                    None => encoded.push(0),
                },
            },
        }
    }
    Ok(encoded)
}

/// Exercises the bounded persisted-record decoder with hostile bytes.
#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_durable_operation_record(data: &[u8]) {
    let _ = decode_operation(data);
    let _ = decode_expired_binding(data);
    let parameters = if data.first().copied().unwrap_or_default() & 1 == 0 {
        crate::RepositoryOperationParameters::local(
            crate::RepositoryAction::Doctor,
            "/fuzz/repository",
            [0x44; 16],
            [0x55; 32],
            [0x66; 32],
        )
    } else {
        crate::RepositoryOperationParameters::aws_s3(
            crate::RepositoryAction::Doctor,
            "positron-example\0us-east-1\0https://s3.us-east-1.amazonaws.com\x00123456789012\0owned/",
            [0x44; 16],
            [0x55; 32],
            [0x66; 32],
        )
    }
    .expect("bounded fixture");
    let request = DurableOperationRequest::repository(
        PrincipalId::from_bytes([0x11; 16]).expect("actor"),
        AdministrativeIdempotencyKey::new([0x22; 16]).expect("key"),
        [0x33; 16],
        1,
        17,
        parameters.intent_digest(),
    )
    .expect("request");
    let mut operation = DurableOperation::accepted(request);
    operation.repository_parameters = Some(parameters);
    if data.get(1).copied().unwrap_or_default() & 1 != 0 {
        operation = operation
            .begin(18)
            .expect("begin fixture")
            .succeeded(19)
            .expect("success fixture");
        operation.repository_policy = Some(
            super::repository_policy_codec::RepositoryPolicyReceipt::new({
                use positron_domain::repository::*;
                let mut policy = RepositoryPolicy::local();
                if data.get(2).copied().unwrap_or_default() & 1 != 0 {
                    policy.doctor_probe = Some(ObjectProtection {
                        retention: PolicyObservation::Observed(ObjectRetention {
                            mode: RetentionMode::Compliance,
                            retain_until_unix_seconds: 1_900_000_000,
                        }),
                        legal_hold: PolicyObservation::Unavailable(
                            RepositoryFailure::PermissionDenied,
                        ),
                        event_hold: PolicyObservation::Observed(Some(RetentionPeriod::Days(7))),
                    });
                }
                policy
            })
            .expect("policy fixture"),
        );
    }
    if data.get(3).copied().unwrap_or_default() & 1 != 0 {
        let repository = crate::RepositoryOperationParameters::local(
            crate::RepositoryAction::Verify,
            "/fuzz/repository",
            [0x44; 16],
            [0x55; 32],
            [0x66; 32],
        )
        .expect("verification repository");
        let parameters = super::BackupVerificationParameters::new(
            repository, [0x77; 32], [0x88; 16], [0x99; 32],
        )
        .expect("verification parameters");
        let request = DurableOperationRequest::backup_verification(
            PrincipalId::from_bytes([0x11; 16]).expect("actor"),
            AdministrativeIdempotencyKey::new([0x22; 16]).expect("key"),
            [0x33; 16],
            1,
            17,
            parameters.intent_digest(),
        )
        .expect("verification request");
        operation = DurableOperation::accepted(request);
        operation.backup_parameters =
            Some(super::BackupOperationParameters::Verification(parameters));
        if data.get(4).copied().unwrap_or_default() & 1 != 0 {
            operation = operation
                .begin(18)
                .expect("begin")
                .succeeded(19)
                .expect("success");
            operation.backup_evidence = Some(
                super::backup_parameters::BackupOperationEvidence::VerificationReport([0xaa; 32]),
            );
        }
    }
    let mut record = encode_operation(operation);
    for mutation in data.chunks(4).take(128) {
        let Some(kind) = mutation.first() else {
            continue;
        };
        let position = usize::from(u16::from_be_bytes([
            mutation.get(1).copied().unwrap_or_default(),
            mutation.get(2).copied().unwrap_or_default(),
        ]));
        let value = mutation.get(3).copied().unwrap_or_default();
        match kind % 3 {
            0 => {
                if let Some(byte) = record.get_mut(position) {
                    *byte ^= value;
                }
            },
            1 => record.truncate(position.min(record.len())),
            _ => {
                if record.len() < 2400 {
                    record.push(value);
                }
            },
        }
        if let Ok(Some(decoded)) = decode_operation(&record) {
            assert_eq!(
                decode_operation(&encode_operation(decoded)).expect("accepted record round trip"),
                Some(decoded)
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExpiredOperationBinding {
    pub(super) request: DurableOperationRequest,
}

impl ExpiredOperationBinding {
    pub(super) fn exact_replay(
        self,
        request: DurableOperationRequest,
    ) -> Result<(), DurableOperationFailure> {
        self.request
            .has_same_semantics(request)
            .then_some(())
            .ok_or(DurableOperationFailure::IdempotencyConflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DurableQueryBudgetDimension, DurableQueryExportFailure, DurableQueryExportFailureCode,
    };

    const TARGET_OFFSET: usize = 57;
    const STATUS_OFFSET: usize = 169;
    const PHASE_OFFSET: usize = 170;
    const PROGRESS_OFFSET: usize = 171;
    const RETRY_OFFSET: usize = 172;
    const CANCELLATION_OFFSET: usize = 173;
    const BOUNDARY_OFFSET: usize = 174;
    const TERMINAL_ERROR_OFFSET: usize = 175;
    const TERMINAL_DETAIL_OFFSET: usize = 176;
    const UPDATED_AT_OFFSET: usize = 177;
    const COMPLETED_AT_OFFSET: usize = 185;

    fn accepted_record() -> Vec<u8> {
        pending_operation_fixture(
            DurableOperationRequest::catalog_format_migration(
                PrincipalId::from_bytes([0x11; 16]).expect("principal"),
                AdministrativeIdempotencyKey::new([0x22; 16]).expect("idempotency key"),
                [0x33; 16],
                1,
                17,
            )
            .expect("migration request"),
        )
    }

    #[test]
    fn root_migration_records_preserve_legacy_v4_bytes_and_fail_closed_in_old_reader() {
        let legacy = include_bytes!("../../tests/fixtures/durable-operation-v4-pending.bin");
        let decoded = decode_operation(legacy)
            .expect("baseline v4 decode")
            .expect("operation");
        assert_eq!(encode_operation(decoded), legacy);
        assert_eq!(decoded.status(), DurableOperationStatus::Pending);
        let parameters = crate::KeyProviderMigrationParameters::new(
            crate::KeyProviderMigrationAction::Prepare,
            Some("/protected/target.toml"),
            Some([0x44; 32]),
        )
        .expect("parameters");
        let request = DurableOperationRequest::key_provider_migration(
            PrincipalId::from_bytes([0x11; 16]).expect("principal"),
            AdministrativeIdempotencyKey::new([0x22; 16]).expect("key"),
            [0x33; 16],
            1,
            17,
            parameters.intent_digest(),
        )
        .expect("request");
        let mut operation = DurableOperation::accepted(request);
        operation.key_provider_migration_parameters = Some(parameters);
        let encoded = encode_operation(operation);
        assert_eq!(
            decode_operation(&encoded).expect("new record"),
            Some(operation)
        );
        // Independent first admission gate from b53689a5's v4 reader:
        // recognized POSOPR04 records must have exactly 218 bytes. An unknown
        // outer magic would instead be omitted, which is forbidden here.
        fn baseline_v4_admission(bytes: &[u8]) -> Option<Result<(), ()>> {
            bytes
                .starts_with(b"POSOPR04")
                .then_some(if bytes.len() == 218 { Ok(()) } else { Err(()) })
        }
        assert_eq!(baseline_v4_admission(legacy), Some(Ok(())));
        assert_eq!(baseline_v4_admission(&encoded), Some(Err(())));
    }

    #[test]
    fn repository_record_extension_preserves_baseline_and_rejects_unknown_native_tail() {
        let legacy = include_bytes!("../../tests/fixtures/durable-operation-v4-pending.bin");
        let old = decode_operation(legacy)
            .expect("baseline decode")
            .expect("baseline operation");
        assert_eq!(encode_operation(old), legacy);
        let parameters = crate::RepositoryOperationParameters::local(
            crate::RepositoryAction::Doctor,
            "/protected/repository",
            [0x44; 16],
            [0x55; 32],
            [0x66; 32],
        )
        .expect("native parameters");
        let request = DurableOperationRequest::repository(
            PrincipalId::from_bytes([0x11; 16]).expect("actor"),
            AdministrativeIdempotencyKey::new([0x22; 16]).expect("key"),
            [0x33; 16],
            1,
            17,
            parameters.intent_digest(),
        )
        .expect("request");
        let mut operation = DurableOperation::accepted(request);
        operation.repository_parameters = Some(parameters);
        let encoded = encode_operation(operation);
        assert_eq!(
            decode_operation(&encoded).expect("repository decode"),
            Some(operation)
        );
        // abc6388's reader recognizes POSOPR04 and rejects lengths other
        // than218 unless kind4 has the known root-parameter tail.
        assert!(encoded.starts_with(b"POSOPR04"));
        assert_ne!(encoded.len(), 218);
        assert_ne!(encoded.get(56), Some(&4));
        for index in [218, 226, encoded.len() - 1] {
            let mut changed = encoded.clone();
            if let Some(byte) = changed.get_mut(index) {
                *byte ^= 0xff;
            }
            assert!(decode_operation(&changed).is_err());
        }
        let mut extra = encoded;
        extra.push(0);
        assert!(decode_operation(&extra).is_err());
    }

    #[test]
    fn repository_policy_tail_preserves_old_frames_and_old_reader_refuses_extensions() {
        let legacy = include_bytes!("../../tests/fixtures/durable-operation-v4-pending.bin");
        assert_eq!(
            encode_operation(
                decode_operation(legacy)
                    .expect("legacy")
                    .expect("operation")
            ),
            legacy
        );
        let parameters = crate::RepositoryOperationParameters::local(
            crate::RepositoryAction::Doctor,
            "/protected/repository",
            [0x44; 16],
            [0x55; 32],
            [0x66; 32],
        )
        .expect("parameters");
        let request = DurableOperationRequest::repository(
            PrincipalId::from_bytes([0x11; 16]).expect("actor"),
            AdministrativeIdempotencyKey::new([0x22; 16]).expect("key"),
            [0x33; 16],
            1,
            17,
            parameters.intent_digest(),
        )
        .expect("request");
        let mut operation = DurableOperation::accepted(request);
        operation.repository_parameters = Some(parameters);
        let pending = encode_operation(operation);
        // Independent admission boundary from a5dfbfb6's Local decoder:
        // provider byte1 and exact 84+locator-length native parameter frame.
        fn old_local_payload_accepts(bytes: &[u8]) -> bool {
            bytes.first() == Some(&1)
                && bytes
                    .get(82..84)
                    .and_then(|length| <[u8; 2]>::try_from(length).ok())
                    .is_some_and(|length| {
                        bytes.len() == 84 + usize::from(u16::from_be_bytes(length))
                    })
        }
        assert!(old_local_payload_accepts(
            pending.get(226..).expect("native tail")
        ));
        operation = operation
            .begin(18)
            .expect("begin")
            .succeeded(19)
            .expect("success");
        operation.repository_policy = Some(
            super::super::repository_policy_codec::RepositoryPolicyReceipt::new(
                positron_domain::repository::RepositoryPolicy::local(),
            )
            .expect("checked policy"),
        );
        let encoded = encode_operation(operation);
        assert!(encoded.ends_with(b"POSRPL01\x01\x01\x01"));
        assert!(!old_local_payload_accepts(
            encoded.get(226..).expect("extended tail")
        ));
        assert_eq!(
            decode_operation(&encoded).expect("new decode"),
            Some(operation)
        );
        let native = crate::RepositoryOperationParameters::aws_s3(
            crate::RepositoryAction::Doctor,
            "positron-example\0us-east-1\0https://s3.us-east-1.amazonaws.com\x00123456789012\0owned/",
            [0x44; 16],
            [0x55; 32],
            [0x66; 32],
        )
        .expect("native");
        let mut payload = Vec::new();
        native.encode(&mut payload);
        assert!(!old_local_payload_accepts(&payload));
        // A fully absent result remains valid for legacy Local receipts.
        let mut old_terminal = operation;
        old_terminal.repository_policy = None;
        assert_eq!(
            decode_operation(&encode_operation(old_terminal)).expect("legacy terminal"),
            Some(old_terminal)
        );
        for length in 0..10 {
            let end = encoded.len().checked_sub(length + 1).expect("end");
            assert!(decode_operation(encoded.get(..end).expect("truncation")).is_err());
        }
    }

    #[test]
    fn durable_operation_decoder_rejects_impossible_semantic_state_combinations() {
        let mut missing_migration_target = accepted_record();
        missing_migration_target[TARGET_OFFSET..TARGET_OFFSET + 16].fill(0);

        let mut pending_published = accepted_record();
        pending_published[PHASE_OFFSET] = DurableOperationPhase::Published.code();
        pending_published[PROGRESS_OFFSET] = 100;
        pending_published[RETRY_OFFSET] = DurableOperationRetry::Never.code();
        pending_published[CANCELLATION_OFFSET] =
            DurableOperationCancellation::NotAllowedAfterDrain.code();
        pending_published[BOUNDARY_OFFSET] =
            DurableOperationBoundary::CatalogGenerationPublished.code();

        let mut completed_before_acceptance = accepted_record();
        completed_before_acceptance[STATUS_OFFSET] = DurableOperationStatus::Succeeded.code();
        completed_before_acceptance[PHASE_OFFSET] = DurableOperationPhase::Published.code();
        completed_before_acceptance[PROGRESS_OFFSET] = 100;
        completed_before_acceptance[RETRY_OFFSET] = DurableOperationRetry::Never.code();
        completed_before_acceptance[CANCELLATION_OFFSET] =
            DurableOperationCancellation::NotAllowedAfterDrain.code();
        completed_before_acceptance[BOUNDARY_OFFSET] =
            DurableOperationBoundary::CatalogGenerationPublished.code();
        completed_before_acceptance[UPDATED_AT_OFFSET..UPDATED_AT_OFFSET + 8]
            .copy_from_slice(&17_u64.to_be_bytes());
        completed_before_acceptance[COMPLETED_AT_OFFSET..COMPLETED_AT_OFFSET + 8]
            .copy_from_slice(&1_u64.to_be_bytes());

        for record in [
            missing_migration_target,
            pending_published,
            completed_before_acceptance,
        ] {
            assert!(
                decode_operation(&record).is_err(),
                "persisted durable state must match a legal handler checkpoint"
            );
        }
    }

    #[test]
    fn query_export_manifest_failure_round_trips_only_with_its_crossed_boundary() {
        let request = DurableOperationRequest::query_export(
            PrincipalId::from_bytes([0x51; 16]).expect("principal"),
            TenantId::from_bytes([0x52; 16]).expect("tenant"),
            AdministrativeIdempotencyKey::new([0x53; 16]).expect("idempotency key"),
            [0x54; 16],
            1,
            17,
            [0x55; 32],
        )
        .expect("query export request");
        let failed = DurableOperation::accepted(request)
            .begin(18)
            .expect("operation begins")
            .failed_after_manifest_publication(19, DurableOperationTerminalError::HandlerRejected)
            .expect("published manifest failure");
        let encoded = encode_operation(failed);

        assert_eq!(
            decode_operation(&encoded)
                .expect("decode")
                .expect("operation"),
            failed
        );

        let mut missing_boundary = encoded;
        missing_boundary[BOUNDARY_OFFSET] = DurableOperationBoundary::NotCrossed.code();
        assert!(
            decode_operation(&missing_boundary).is_err(),
            "a terminal incomplete export cannot deny its durable manifest boundary"
        );
    }

    #[test]
    fn query_export_pre_output_failure_round_trips_and_keeps_legacy_reader_support() {
        let request = DurableOperationRequest::query_export(
            PrincipalId::from_bytes([0x61; 16]).expect("principal"),
            TenantId::from_bytes([0x62; 16]).expect("tenant"),
            AdministrativeIdempotencyKey::new([0x63; 16]).expect("idempotency key"),
            [0x64; 16],
            1,
            17,
            [0x65; 32],
        )
        .expect("query export request");
        let failed = DurableOperation::accepted(request)
            .begin(18)
            .expect("operation begins")
            .failed(
                19,
                DurableOperationTerminalError::QueryFailure(DurableQueryExportFailure::new(
                    DurableQueryExportFailureCode::BudgetExhausted,
                    Some(DurableQueryBudgetDimension::MemoryBytes),
                )),
            )
            .expect("pre-output failure");
        let encoded = encode_operation(failed);
        assert_eq!(
            decode_operation(&encoded)
                .expect("decode")
                .expect("operation"),
            failed
        );

        let mut malformed_budget = encoded.clone();
        malformed_budget[TERMINAL_ERROR_OFFSET] = 13;
        malformed_budget[TERMINAL_DETAIL_OFFSET] = 5;
        assert!(
            decode_operation(&malformed_budget).is_err(),
            "only budget failures may retain a limiting dimension"
        );

        let migration = DurableOperation::accepted(
            DurableOperationRequest::catalog_format_migration(
                PrincipalId::from_bytes([0x71; 16]).expect("principal"),
                AdministrativeIdempotencyKey::new([0x72; 16]).expect("idempotency key"),
                [0x73; 16],
                1,
                17,
            )
            .expect("migration request"),
        )
        .begin(18)
        .expect("operation begins")
        .failed(19, DurableOperationTerminalError::HandlerRejected)
        .expect("transition construction");
        let mut wrong_kind = encode_operation(migration);
        wrong_kind[TERMINAL_ERROR_OFFSET] = 13;
        assert!(
            decode_operation(&wrong_kind).is_err(),
            "a Query-export terminal outcome cannot inhabit another handler's operation"
        );

        let legacy = DurableOperation::accepted(request)
            .begin(18)
            .expect("operation begins")
            .failed(19, DurableOperationTerminalError::HandlerRejected)
            .expect("legacy failure");
        let mut v3 = encode_operation(legacy);
        v3[..8].copy_from_slice(&OPERATION_MAGIC_V3);
        v3.remove(TERMINAL_DETAIL_OFFSET);
        assert_eq!(
            decode_operation(&v3)
                .expect("legacy decode")
                .expect("legacy operation"),
            legacy
        );
    }
}
