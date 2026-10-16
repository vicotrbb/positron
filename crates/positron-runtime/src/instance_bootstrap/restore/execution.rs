use super::*;
use positron_governance::{BackupRestoreStage, DurableOperationPhase, DurableOperationStatus};
use positron_kernel::{
    ActiveSegmentLedger, CatalogGovernanceObject, CatalogObject, IntegrityScrubBudget,
    IntegrityVerificationOutcome, IntegrityVerificationRequest, TransactionId,
};

pub(super) fn record(
    pin: RecoveryIdentity,
    custody: &BootstrapKeyCustody,
    governance: CatalogGovernanceObject,
) -> Result<super::super::codec::BootstrapRecord, BootstrapFailure> {
    let (salt, hash) = governance.principal_secret();
    Ok(super::super::codec::BootstrapRecord {
        instance: pin.instance(),
        key: custody.bootstrap_identity(),
        tenant: governance.tenant(),
        administrator: governance.principal(),
        transaction: TransactionId::new(governance.principal().to_bytes())
            .map_err(|_| failure())?,
        api_key_salt: salt,
        api_key_hash: hash,
        integrity_fingerprint: pin.integrity().fingerprint(),
        ingest: governance
            .ingest_credential()
            .map(|(principal, api_key_salt, api_key_hash)| {
                super::super::codec::BootstrapIngestIdentity {
                    principal,
                    api_key_salt,
                    api_key_hash,
                    api_key_secret: None,
                }
            }),
        query: governance
            .query_credential()
            .map(|(principal, api_key_salt, api_key_hash)| {
                super::super::codec::BootstrapQueryIdentity {
                    principal,
                    api_key_salt,
                    api_key_hash,
                    api_key_secret: None,
                }
            }),
        api_key_secret: None,
        integrity_key_secret: None,
    })
}
impl BackupRestoreSession {
    pub fn status(&self) -> DurableOperation {
        self.operation
    }
    /// Cancels only at the persisted operation revision and before publication.
    pub fn cancel(
        &mut self,
        key: AdministrativeIdempotencyKey,
        revision: u64,
    ) -> Result<DurableOperation, BootstrapFailure> {
        let catalog = Catalog::open(
            &self.authority,
            self.pin.instance(),
            self.custody
                .catalog_secret(self.pin.instance())
                .map_err(|_| failure())?,
        )
        .map_err(|_| failure())?;
        let basis = catalog.pin().map_err(|_| failure())?;
        let actor = Identity::authorize_backup_restore(&basis, &self.custody, self.pin, now()?)
            .map_err(|_| failure())?;
        self.operation = DurableOperationAdministration::cancel_backup_restore(
            &catalog,
            actor,
            self.operation.operation_id(),
            key,
            revision,
            now()?,
        )
        .map_err(|_| failure())?;
        Ok(self.operation)
    }

    pub fn step(&mut self) -> Result<DurableOperation, BootstrapFailure> {
        let catalog = Catalog::open(
            &self.authority,
            self.pin.instance(),
            self.custody
                .catalog_secret(self.pin.instance())
                .map_err(|_| failure())?,
        )
        .map_err(|_| failure())?;
        let basis = catalog.pin().map_err(|_| failure())?;
        let actor = Identity::authorize_backup_restore(&basis, &self.custody, self.pin, now()?)
            .map_err(|_| failure())?;
        if self.operation.status() == DurableOperationStatus::Succeeded {
            self.publish_initialized(&basis)?;
            return Ok(self.operation);
        }
        if self.operation.status().is_terminal() {
            return Ok(self.operation);
        }
        if self.operation.status() == DurableOperationStatus::Pending {
            self.operation = DurableOperationAdministration::begin(
                &catalog,
                actor,
                self.operation.operation_id(),
                now()?,
            )
            .map_err(|_| failure())?;
            return Ok(self.operation);
        }
        let publisher =
            BackupPublisher::new(self.repository.as_ref(), &self.identity, &self.signer)
                .with_control_resources(&self.resources, 0)
                .map_err(|_| failure())?
                .with_registry_verification(&self.registry)
                .map_err(|_| failure())?;
        match self.operation.phase() {
            DurableOperationPhase::Preflight => {
                self.operation = DurableOperationAdministration::advance_backup_restore(
                    &catalog,
                    actor,
                    self.operation.operation_id(),
                    BackupRestoreStage::Transferring,
                    now()?,
                )
                .map_err(|_| failure())?;
            },
            DurableOperationPhase::BackupTransfer => {
                while let Some(file) = self.files.get(self.next_file).copied() {
                    if !matches!(
                        file.kind(),
                        BackupCaptureFileKind::Segment | BackupCaptureFileKind::SegmentFrontier
                    ) {
                        self.next_file += 1;
                        continue;
                    }
                    let object = self
                        .manifest
                        .objects()
                        .iter()
                        .find(|object| {
                            object.file() == file.identity()
                                && object.offset() <= self.offset
                                && object.offset() + object.length() > self.offset
                        })
                        .ok_or_else(failure)?;
                    let object_offset = self.offset - object.offset();
                    let length =
                        (object.length() - object_offset).min(positron_backup::MAX_RANGE_BYTES);
                    let bytes = self
                        .runtime
                        .block_on(
                            self.repository.read_range(
                                positron_backup::ObjectRange::new(
                                    object.object(),
                                    object_offset,
                                    length,
                                )
                                .map_err(|_| failure())?
                                .with_expected_size(object.length())
                                .map_err(|_| failure())?,
                            ),
                        )
                        .map_err(|_| failure())?;
                    if bytes.bytes().len() as u64 != length {
                        return Err(failure());
                    }
                    catalog
                        .restore_segment_range(file, self.offset, bytes.bytes())
                        .map_err(|_| failure())?;
                    self.offset += length;
                    if self.offset == file.size() {
                        self.next_file += 1;
                        self.offset = 0;
                    }
                    return Ok(self.operation);
                }
                self.operation = DurableOperationAdministration::advance_backup_restore(
                    &catalog,
                    actor,
                    self.operation.operation_id(),
                    BackupRestoreStage::Verifying,
                    now()?,
                )
                .map_err(|_| failure())?;
            },
            DurableOperationPhase::BackupVerification
            | DurableOperationPhase::CatalogPublication => {
                if !self.remote.complete() {
                    self.runtime
                        .block_on(publisher.snapshot_verification_step(&mut self.remote))
                        .map_err(|_| failure())?;
                    return Ok(self.operation);
                }
                if let Some(scope) = self.native_scopes.get(self.native_index).copied() {
                    let identity = Identity::open(&basis).map_err(|_| failure())?;
                    let protection = positron_kernel::RootRewrapSession::derive_tenant_segment_key(
                        &self.authority,
                        &self.custody,
                        self.pin.instance(),
                        scope,
                        identity
                            .tenant_key_envelope(scope.tenant_id())
                            .map_err(|_| failure())?,
                    )
                    .map_err(|_| failure())?;
                    let result = ActiveSegmentLedger::verify_snapshot_integrity(
                        &self.authority,
                        &basis,
                        self.pin.instance(),
                        IntegrityVerificationRequest::new(
                            scope,
                            protection,
                            IntegrityScrubBudget::new(IntegrityScrubBudget::MAX_SEGMENTS)
                                .map_err(|_| failure())?,
                            &positron_kernel::IntegrityCancellation::new(),
                            TransactionId::new(self.operation.operation_id().to_bytes())
                                .map_err(|_| failure())?,
                            self.native_cursor,
                        ),
                    );
                    let result = match result {
                        Ok(result) => result,
                        Err(error) => {
                            if matches!(
                                error.code(),
                                positron_kernel::IntegrityFailureCode::AmbiguousIntegrity
                                    | positron_kernel::IntegrityFailureCode::DurabilityFrontierAmbiguity
                            ) {
                                self.operation = DurableOperationAdministration::fail_backup_restore(
                                    &catalog,
                                    actor,
                                    self.operation.operation_id(),
                                    now()?,
                                )
                                .map_err(|_| failure())?;
                            }
                            return Err(failure());
                        },
                    };
                    self.native_cursor = result.continuation();
                    match result.outcome() {
                        IntegrityVerificationOutcome::Verified if self.native_cursor.is_none() => {
                            self.native_index += 1;
                        },
                        IntegrityVerificationOutcome::Incomplete
                            if self.native_cursor.is_some() => {},
                        IntegrityVerificationOutcome::Quarantined
                        | IntegrityVerificationOutcome::Fenced => {
                            self.operation = DurableOperationAdministration::fail_backup_restore(
                                &catalog,
                                actor,
                                self.operation.operation_id(),
                                now()?,
                            )
                            .map_err(|_| failure())?;
                            return Err(failure());
                        },
                        _ => return Err(failure()),
                    }
                    return Ok(self.operation);
                }
                if self.operation.phase() == DurableOperationPhase::BackupVerification {
                    self.operation = DurableOperationAdministration::advance_backup_restore(
                        &catalog,
                        actor,
                        self.operation.operation_id(),
                        BackupRestoreStage::Publishing,
                        now()?,
                    )
                    .map_err(|_| failure())?;
                    return Ok(self.operation);
                }
                let report = self
                    .runtime
                    .block_on(publisher.snapshot_restore_report(
                        &self.remote,
                        &self.source_catalog,
                        &basis,
                        self.recovered_keys,
                    ))
                    .map_err(|_| failure())?;
                self.operation = DurableOperationAdministration::succeed_backup_restore(
                    &catalog,
                    actor,
                    self.operation.operation_id(),
                    CatalogObject::new(report.bytes().to_vec()).map_err(|_| failure())?,
                    now()?,
                )
                .map_err(|_| failure())?;
                self.publish_initialized(&basis)?;
            },
            _ => return Err(failure()),
        }
        Ok(self.operation)
    }
    fn publish_initialized(
        &self,
        basis: &positron_kernel::CatalogSnapshot,
    ) -> Result<(), BootstrapFailure> {
        let layout = self.access.layout().map_err(storage::storage_failure)?;
        if layout.contains(positron_kernel::BootstrapEntry::LocalKey)
            || layout.contains(positron_kernel::BootstrapEntry::LocalKeyEpoch)
        {
            let existing = self.access.open_key().map_err(|_| failure())?;
            let (_, governance) = basis.governance_object().map_err(|_| failure())?;
            if existing.active_root_identity().map_err(|_| failure())? != self.pin.root()
                || existing.bootstrap_identity() != self.custody.bootstrap_identity()
                || existing
                    .backup_control_signer(
                        self.pin.instance(),
                        governance.protected_integrity_key(),
                    )
                    .map_err(|_| failure())?
                    .identity()
                    != self.pin.integrity()
            {
                return Err(failure());
            }
        } else {
            self.access
                .publish_recovered_key(&self.custody)
                .map_err(|_| failure())?;
        }
        let encoded = self
            .custody
            .protect(
                self.pin.instance(),
                BootstrapObjectPurpose::Initialized,
                &self.record.encode(),
            )
            .map_err(|_| failure())?;
        if self
            .access
            .exists(BootstrapArtifact::Initialized)
            .map_err(storage::storage_failure)?
        {
            let existing = self
                .access
                .read(BootstrapArtifact::Initialized)
                .map_err(storage::storage_failure)?;
            let opened = self
                .custody
                .open_object(
                    self.pin.instance(),
                    BootstrapObjectPurpose::Initialized,
                    &existing,
                )
                .map_err(|_| failure())?;
            if opened.as_slice() != self.record.encode().as_slice() {
                return Err(failure());
            }
        } else {
            if !self
                .access
                .exists(BootstrapArtifact::InitializedStaging)
                .map_err(storage::storage_failure)?
            {
                storage::write_new(
                    &self.access,
                    BootstrapArtifact::InitializedStaging,
                    &encoded,
                )?;
            } else if self
                .access
                .read(BootstrapArtifact::InitializedStaging)
                .map_err(storage::storage_failure)?
                != encoded.as_slice()
            {
                // AEAD is randomized: authenticate the existing canonical record.
                let existing = self
                    .access
                    .read(BootstrapArtifact::InitializedStaging)
                    .map_err(storage::storage_failure)?;
                let opened = self
                    .custody
                    .open_object(
                        self.pin.instance(),
                        BootstrapObjectPurpose::Initialized,
                        &existing,
                    )
                    .map_err(|_| failure())?;
                if opened.as_slice() != self.record.encode().as_slice() {
                    return Err(failure());
                }
            }
            storage::publish_initialized(&self.access)?;
        }
        Ok(())
    }
}
