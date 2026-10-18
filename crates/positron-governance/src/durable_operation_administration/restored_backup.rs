//! Restore-only historical completion of the verified snapshot's own capture.
use super::*;

/// Authenticated publication facts recovered during a fresh offline restore.
/// Transfer counters and the original publication generation are unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoredBackupPublication {
    manifest: [u8; 32],
    current_registry: [u8; 32],
    source_catalog: [u8; 32],
    source_generation: u64,
    retain_until: u64,
    origin: [u8; 16],
    restore_intent: [u8; 32],
    restore_key: [u8; 16],
    capture: [u8; 16],
    capture_request: [u8; 32],
}
impl RestoredBackupPublication {
    /// The Runtime supplies the independently verified signed registry head and
    /// manifest retention after full remote verification. Kernel origin custody
    /// proves the captured Catalog and its original operation binding.
    pub fn new(
        origin: &positron_kernel::BackupRestoreOrigin,
        source: BackupVerificationParameters,
        restore_key: AdministrativeIdempotencyKey,
        current_registry: [u8; 32],
        retain_until: u64,
    ) -> Result<Self, DurableOperationFailure> {
        let (capture, capture_request) = origin.capture_binding();
        if source.snapshot_id() != capture
            || source.manifest_checksum() != origin.manifest_checksum()
            || current_registry == [0; 32]
            || retain_until == 0
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let operation = find_by_id(origin.snapshot(), OperationId::from_bytes(capture)?)?
            .ok_or(DurableOperationFailure::UnknownOperation)?;
        let value = Self {
            manifest: origin.manifest_checksum(),
            current_registry,
            source_catalog: origin.snapshot().identity().to_bytes(),
            source_generation: origin.snapshot().number(),
            retain_until,
            origin: origin.transaction_id().map_err(map_catalog)?.to_bytes(),
            restore_intent: origin.restore_intent(),
            restore_key: restore_key.to_bytes(),
            capture,
            capture_request,
        };
        if operation.target_identity() != Some(origin.instance().to_bytes())
            || !operation.backup_parameters().is_some_and(|parameters| {
                parameters.repository() == source.repository()
                    && parameters.registration_identity() == source.registration_identity()
            })
            || !value.matches_capture(operation)
            || operation.status() != DurableOperationStatus::Running
            || operation.phase() != DurableOperationPhase::BackupCapture
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        Ok(value)
    }
    fn matches_capture(self, operation: DurableOperation) -> bool {
        operation.operation_id().to_bytes() == self.capture
            && operation.kind() == DurableOperationKind::BackupSnapshot
            && operation
                .backup_parameters()
                .is_some_and(|parameters| parameters.intent_digest() == self.capture_request)
            && operation.request.operation_request_digest == Some(self.capture_request)
    }
    /// A later authenticated registry append does not rewrite the first receipt.
    pub fn same_restore_binding(self, other: Self) -> bool {
        Self {
            current_registry: other.current_registry,
            ..self
        } == other
    }
    pub const fn manifest(self) -> [u8; 32] {
        self.manifest
    }
    pub const fn current_registry_generation(self) -> [u8; 32] {
        self.current_registry
    }
    pub const fn source_catalog_identity(self) -> [u8; 32] {
        self.source_catalog
    }
    pub const fn source_catalog_generation(self) -> u64 {
        self.source_generation
    }
    pub const fn retain_until(self) -> u64 {
        self.retain_until
    }
    pub const fn origin_transaction(self) -> [u8; 16] {
        self.origin
    }
    pub const fn restore_intent(self) -> [u8; 32] {
        self.restore_intent
    }
    pub const fn restore_idempotency_key(self) -> [u8; 16] {
        self.restore_key
    }
    pub const fn capture_operation(self) -> [u8; 16] {
        self.capture
    }
    pub const fn capture_request(self) -> [u8; 32] {
        self.capture_request
    }
    pub(super) fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.manifest);
        bytes.extend_from_slice(&self.current_registry);
        bytes.extend_from_slice(&self.source_catalog);
        bytes.extend_from_slice(&self.source_generation.to_be_bytes());
        bytes.extend_from_slice(&self.retain_until.to_be_bytes());
        bytes.extend_from_slice(&self.origin);
        bytes.extend_from_slice(&self.restore_intent);
        bytes.extend_from_slice(&self.capture);
        bytes.extend_from_slice(&self.capture_request);
        bytes.extend_from_slice(&self.restore_key);
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DurableOperationFailure> {
        let mut offset = 0;
        let value = Self {
            manifest: codec::take_array(bytes, &mut offset)?,
            current_registry: codec::take_array(bytes, &mut offset)?,
            source_catalog: codec::take_array(bytes, &mut offset)?,
            source_generation: codec::take_u64(bytes, &mut offset)?,
            retain_until: codec::take_u64(bytes, &mut offset)?,
            origin: codec::take_array(bytes, &mut offset)?,
            restore_intent: codec::take_array(bytes, &mut offset)?,
            capture: codec::take_array(bytes, &mut offset)?,
            capture_request: codec::take_array(bytes, &mut offset)?,
            restore_key: codec::take_array(bytes, &mut offset)?,
        };
        if offset != bytes.len()
            || value.manifest == [0; 32]
            || value.current_registry == [0; 32]
            || value.source_catalog == [0; 32]
            || value.source_generation == 0
            || value.retain_until == 0
            || value.restore_key == [0; 16]
            || value.restore_intent == [0; 32]
            || value.capture_request == [0; 32]
            || value.capture == [0; 16]
            || value.origin
                != value
                    .manifest
                    .get(..16)
                    .ok_or(DurableOperationFailure::InvalidInput)?
        {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Ok(value)
    }
    pub(crate) fn transaction(
        self,
        revision: u64,
    ) -> Result<TransactionId, DurableOperationFailure> {
        let mut hash = Sha256::new();
        hash.update(b"positron.restore.self-capture-completion.v1\0");
        hash.update(self.origin);
        hash.update(self.capture);
        hash.update(self.manifest);
        hash.update(self.restore_intent);
        hash.update(self.capture_request);
        hash.update(self.restore_key);
        hash.update(revision.to_be_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        TransactionId::new(
            *digest
                .first_chunk::<16>()
                .ok_or(DurableOperationFailure::InvalidInput)?,
        )
        .map_err(map_catalog)
    }
}
impl DurableOperation {
    pub const fn restored_backup_publication(self) -> Option<RestoredBackupPublication> {
        match self.backup_evidence {
            Some(backup_parameters::BackupOperationEvidence::RestoredPublication(value)) => {
                Some(value)
            },
            _ => None,
        }
    }
}
impl DurableOperationAdministration {
    /// Only an authenticated, already installed fresh restore origin may finish
    /// its own historical self-capture. No provider work or cancellation runs.
    pub fn reconcile_restored_backup(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        evidence: RestoredBackupPublication,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        if !catalog
            .matches_restore_origin(
                evidence.manifest,
                evidence.restore_intent,
                evidence.source_catalog,
            )
            .map_err(map_catalog)?
        {
            return Err(DurableOperationFailure::InvalidInput);
        }
        let (snapshot, operation) = backup_administration::authorized(
            catalog,
            actor,
            OperationId::from_bytes(evidence.capture)?,
        )?;
        validate_system_actor(actor, operation.request.principal)?;
        if operation.status().is_terminal() {
            return if operation.status() == DurableOperationStatus::Succeeded
                && operation.restored_backup_publication() == Some(evidence)
            {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if !evidence.matches_capture(operation)
            || operation.status() != DurableOperationStatus::Running
            || operation.phase() != DurableOperationPhase::BackupCapture
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let binding = positron_kernel::RepositoryOperationBinding::new(
            evidence.capture,
            evidence.capture_request,
        )
        .map_err(|_| DurableOperationFailure::InvalidInput)?;
        let (previous, task) = binding
            .restored_snapshot_completion(&snapshot)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        let mut completed = operation.succeeded(now)?;
        completed.backup_evidence =
            Some(backup_parameters::BackupOperationEvidence::RestoredPublication(evidence));
        publish_with_objects(catalog, &snapshot, completed, vec![task], Some(previous))
    }
}

#[cfg(any(test, fuzzing))]
pub(super) fn historical_record_fixture() -> DurableOperation {
    let repository = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/fuzz/repository",
        [0x44; 16],
        [0x55; 32],
        [0x66; 32],
    )
    .expect("bounded repository fixture");
    let parameters =
        BackupSnapshotParameters::new(repository, 3600, [0x77; 32]).expect("snapshot fixture");
    let request = DurableOperationRequest::backup_snapshot(
        PrincipalId::from_bytes([0x11; 16]).expect("actor"),
        AdministrativeIdempotencyKey::new([0x22; 16]).expect("key"),
        [0x33; 16],
        1,
        17,
        parameters.intent_digest(),
    )
    .expect("capture request");
    let mut operation = DurableOperation::accepted(request)
        .begin(18)
        .expect("begin")
        .succeeded(19)
        .expect("complete");
    operation.backup_parameters = Some(BackupOperationParameters::Snapshot(parameters));
    operation.backup_evidence = Some(
        backup_parameters::BackupOperationEvidence::RestoredPublication(
            RestoredBackupPublication {
                manifest: [0x99; 32],
                current_registry: [0xaa; 32],
                source_catalog: [0xbb; 32],
                source_generation: 7,
                retain_until: 1000,
                origin: [0x99; 16],
                restore_intent: [0xcc; 32],
                restore_key: [0xdd; 16],
                capture: operation.operation_id().to_bytes(),
                capture_request: parameters.intent_digest(),
            },
        ),
    );
    operation
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_record_and_audit_preserve_binding_and_distinct_transaction() {
        let operation = historical_record_fixture();
        let record = encode_operation(operation);
        assert_eq!(decode_operation(&record).expect("record"), Some(operation));
        let evidence = operation.restored_backup_publication().expect("receipt");
        let transaction = transition_transaction(operation).expect("successor");
        assert_ne!(transaction.to_bytes(), evidence.origin_transaction());
        let audit = encode_audit(operation).expect("audit");
        let entry = crate::GovernanceAuditEntry::decode_fields(1, transaction.to_bytes(), &audit)
            .expect("bound audit");
        let crate::GovernanceAuditEntry::DurableOperation(entry) = entry else {
            panic!("historical operation audit");
        };
        assert_eq!(entry.restored_backup_publication(), Some(evidence));
        assert_eq!(entry.backup_receipt(), None);
        assert!(
            crate::GovernanceAuditEntry::decode_fields(1, evidence.origin_transaction(), &audit)
                .is_err()
        );
        let start = record
            .windows(8)
            .position(|magic| magic == b"POSBKH01")
            .expect("historical codec")
            + 8;
        let mut different_capture = record.clone();
        different_capture[start + 160] ^= 1;
        assert!(decode_operation(&different_capture).is_err());
        for end in start..record.len() {
            assert!(decode_operation(&record[..end]).is_err());
        }
        let mut extended = record;
        extended.push(0);
        assert!(decode_operation(&extended).is_err());
    }
    #[test]
    fn historical_publication_rejects_missing_or_inconsistent_proof_fields() {
        let evidence = historical_record_fixture()
            .restored_backup_publication()
            .expect("receipt");
        let mut original = Vec::new();
        evidence.encode(&mut original);
        for range in [
            0..32,
            32..64,
            64..96,
            96..104,
            104..112,
            112..128,
            128..160,
            160..176,
            176..208,
            208..224,
        ] {
            let mut bytes = original.clone();
            bytes[range].fill(0);
            assert!(RestoredBackupPublication::decode(&bytes).is_err());
        }
        let mut different_origin = original;
        different_origin[112] ^= 1;
        assert!(RestoredBackupPublication::decode(&different_origin).is_err());
    }
}
