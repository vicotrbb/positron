//! Exact offline target and independent recovery are part of accepted restore intent.
use super::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRestoreParameters {
    source: BackupVerificationParameters,
    target: [u8; 32],
    configuration: [u8; 32],
    recovery: [u8; 32],
}
impl BackupRestoreParameters {
    pub fn new(
        source: BackupVerificationParameters,
        target: [u8; 32],
        configuration: [u8; 32],
        recovery: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if target == [0; 32] || configuration == [0; 32] || recovery == [0; 32] {
            return Err(DurableOperationFailure::InvalidInput);
        }
        Ok(Self {
            source,
            target,
            configuration,
            recovery,
        })
    }
    pub const fn source(self) -> BackupVerificationParameters {
        self.source
    }
    pub const fn target_identity(self) -> [u8; 32] {
        self.target
    }
    pub const fn configuration_digest(self) -> [u8; 32] {
        self.configuration
    }
    pub const fn recovery_digest(self) -> [u8; 32] {
        self.recovery
    }
    pub fn intent_digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron-backup-restore-request-v1\0");
        hash.update(self.source.intent_digest());
        hash.update(self.target);
        hash.update(self.configuration);
        hash.update(self.recovery);
        hash.finalize().into()
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.target);
        bytes.extend_from_slice(&self.configuration);
        bytes.extend_from_slice(&self.recovery);
        self.source.encode(bytes);
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let target = codec::take_array(bytes, &mut offset)?;
        let configuration = codec::take_array(bytes, &mut offset)?;
        let recovery = codec::take_array(bytes, &mut offset)?;
        let source = BackupVerificationParameters::decode(
            bytes
                .get(offset..)
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )?;
        Self::new(source, target, configuration, recovery)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)
    }
}
impl DurableOperationRequest {
    pub fn backup_restore(
        principal: positron_domain::identity::PrincipalId,
        idempotency: AdministrativeIdempotencyKey,
        instance: [u8; 16],
        accepted_generation: u64,
        accepted_at_unix_seconds: u64,
        intent: [u8; 32],
    ) -> Result<Self, DurableOperationFailure> {
        if accepted_generation == 0
            || accepted_at_unix_seconds == 0
            || instance == [0; 16]
            || intent == [0; 32]
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let kind = DurableOperationKind::BackupRestore;
        let mut hash = Sha256::new();
        hash.update(types::REQUEST_DOMAIN);
        hash.update(principal.to_bytes());
        hash.update(idempotency.to_bytes());
        hash.update([kind.code()]);
        hash.update(instance);
        hash.update(accepted_generation.to_be_bytes());
        hash.update(intent);
        Ok(Self {
            principal,
            idempotency,
            kind,
            target_identity: Some(instance),
            applicable_tenant: None,
            accepted_generation,
            accepted_at_unix_seconds,
            operation_request_digest: Some(intent),
            digest: hash.finalize().into(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRestoreStage {
    Transferring,
    Verifying,
    Publishing,
}
