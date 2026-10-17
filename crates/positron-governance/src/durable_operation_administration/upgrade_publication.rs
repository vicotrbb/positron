//! One Catalog-owned active release/readiness pointer outlives lookup history.
use super::upgrade_parameters::UpgradeProgress;
use super::*;
const MAGIC: &[u8; 8] = b"POSUPUB1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradePublicationOutcome {
    AwaitingVerification,
    Verified { report: [u8; 32] },
    Failed,
    SourceRollback,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradePublication {
    operation: OperationId,
    parameters: UpgradeParameters,
    drain: UpgradeDrainEvidence,
    snapshot: UpgradeSnapshotEvidence,
    rollback: Option<AdministrativeIdempotencyKey>,
    outcome: UpgradePublicationOutcome,
}
impl UpgradePublication {
    pub const fn operation_id(self) -> OperationId {
        self.operation
    }
    pub const fn parameters(self) -> UpgradeParameters {
        self.parameters
    }
    pub const fn drain(self) -> UpgradeDrainEvidence {
        self.drain
    }
    pub const fn snapshot(self) -> UpgradeSnapshotEvidence {
        self.snapshot
    }
    pub const fn release(self) -> UpgradeReleaseIdentity {
        if self.is_rollback() {
            self.parameters.source()
        } else {
            self.parameters.target()
        }
    }
    fn verification_publication_identity(mut self) -> Result<[u8; 32], DurableOperationFailure> {
        self.outcome = UpgradePublicationOutcome::AwaitingVerification;
        self.object_identity()
    }
    pub const fn is_rollback(self) -> bool {
        matches!(self.outcome, UpgradePublicationOutcome::SourceRollback)
    }
    pub const fn outcome(self) -> UpgradePublicationOutcome {
        self.outcome
    }
    pub const fn failed(self) -> bool {
        matches!(self.outcome, UpgradePublicationOutcome::Failed)
    }
    pub const fn verification_report(self) -> Option<[u8; 32]> {
        match self.outcome {
            UpgradePublicationOutcome::Verified { report } => Some(report),
            _ => None,
        }
    }
    pub fn object_identity(self) -> Result<[u8; 32], DurableOperationFailure> {
        Ok(CatalogObject::new(self.encode())
            .map_err(map_catalog)?
            .identity()
            .to_bytes())
    }
    fn from_operation(operation: DurableOperation) -> Result<Self, DurableOperationFailure> {
        if operation.kind() != DurableOperationKind::Upgrade
            || operation.irreversible_boundary()
                != DurableOperationBoundary::CatalogGenerationPublished
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        let outcome = match (
            operation.status(),
            operation.upgrade_stage(),
            operation.upgrade_rollback_key(),
        ) {
            (DurableOperationStatus::Running, Some(UpgradeStage::AwaitingRestart), None) => {
                UpgradePublicationOutcome::AwaitingVerification
            },
            (DurableOperationStatus::Succeeded, Some(UpgradeStage::Succeeded), None) => {
                UpgradePublicationOutcome::Verified {
                    report: operation
                        .upgrade_verification_report()
                        .ok_or(DurableOperationFailure::InvalidState)?,
                }
            },
            (
                DurableOperationStatus::Failed,
                Some(UpgradeStage::AwaitingRestart | UpgradeStage::Verifying),
                None,
            ) => UpgradePublicationOutcome::Failed,
            (
                DurableOperationStatus::Failed,
                Some(UpgradeStage::AwaitingRestart | UpgradeStage::Verifying),
                Some(_),
            ) => UpgradePublicationOutcome::SourceRollback,
            _ => return Err(DurableOperationFailure::InvalidState),
        };
        Ok(Self {
            outcome,
            rollback: operation.upgrade_rollback_key(),
            operation: operation.operation_id(),
            parameters: operation
                .upgrade_parameters()
                .ok_or(DurableOperationFailure::InvalidState)?,
            drain: operation
                .upgrade_drain_evidence()
                .ok_or(DurableOperationFailure::InvalidState)?,
            snapshot: operation
                .upgrade_snapshot_evidence()
                .ok_or(DurableOperationFailure::InvalidState)?,
        })
    }
    fn encode(self) -> Vec<u8> {
        let mut encoded = MAGIC.to_vec();
        encoded.extend_from_slice(&self.operation.to_bytes());
        let mut parameters = Vec::new();
        self.parameters.encode(&mut parameters);
        encoded.extend_from_slice(&(parameters.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&parameters);
        let mut progress = Vec::new();
        UpgradeProgress {
            report: None,
            rollback: self.rollback,
            stage: UpgradeStage::AwaitingRestart,
            drain: Some(self.drain),
            snapshot: Some(self.snapshot),
        }
        .encode(&mut progress);
        encoded.extend_from_slice(&(progress.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&progress);
        match self.outcome {
            UpgradePublicationOutcome::AwaitingVerification => encoded.push(1),
            UpgradePublicationOutcome::Verified { report } => {
                encoded.push(2);
                encoded.extend_from_slice(&report);
            },
            UpgradePublicationOutcome::Failed => encoded.push(3),
            UpgradePublicationOutcome::SourceRollback => encoded.push(4),
        }
        encoded
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Option<Self>, DurableOperationFailure> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if !(300..=3200).contains(&bytes.len()) {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        let mut offset = 8;
        let operation = OperationId::from_bytes(codec::take_array(bytes, &mut offset)?)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        let parameters = UpgradeParameters::decode(take_payload(bytes, &mut offset)?)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        let progress = UpgradeProgress::decode(take_payload(bytes, &mut offset)?)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        let outcome = match codec::take_byte(bytes, &mut offset)? {
            1 => UpgradePublicationOutcome::AwaitingVerification,
            2 => {
                let report = codec::take_array(bytes, &mut offset)?;
                if report == [0; 32] {
                    return Err(DurableOperationFailure::PersistenceUnavailable);
                }
                UpgradePublicationOutcome::Verified { report }
            },
            3 => UpgradePublicationOutcome::Failed,
            4 => UpgradePublicationOutcome::SourceRollback,
            _ => return Err(DurableOperationFailure::PersistenceUnavailable),
        };
        let drain = progress
            .drain
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let snapshot = progress
            .snapshot
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        if offset != bytes.len()
            || progress.stage != UpgradeStage::AwaitingRestart
            || progress.report.is_some()
            || progress.rollback.is_some()
                != matches!(outcome, UpgradePublicationOutcome::SourceRollback)
            || snapshot.receipt().catalog_generation() < drain.catalog_generation()
            || snapshot.operation_id() == operation
            || snapshot.verification_operation_id() == operation
            || snapshot.operation_id() == snapshot.verification_operation_id()
        {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        Ok(Some(Self {
            outcome,
            rollback: progress.rollback,
            operation,
            parameters,
            drain,
            snapshot,
        }))
    }
}
fn take_payload<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
) -> Result<&'a [u8], DurableOperationFailure> {
    let length = usize::try_from(u32::from_be_bytes(codec::take_array(bytes, offset)?))
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let end = offset
        .checked_add(length)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    let payload = bytes
        .get(*offset..end)
        .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
    *offset = end;
    Ok(payload)
}
impl DurableOperationAdministration {
    pub fn current_upgrade_publication(
        catalog: &Catalog<'_>,
    ) -> Result<Option<UpgradePublication>, DurableOperationFailure> {
        Self::current_upgrade_publication_snapshot(&catalog.pin().map_err(map_catalog)?)
    }
    pub fn current_upgrade_publication_snapshot(
        snapshot: &CatalogSnapshot,
    ) -> Result<Option<UpgradePublication>, DurableOperationFailure> {
        Ok(current(snapshot)?.map(|(_, publication)| publication))
    }
}
fn current(
    snapshot: &CatalogSnapshot,
) -> Result<Option<(CatalogObjectId, UpgradePublication)>, DurableOperationFailure> {
    let mut current = None;
    for id in snapshot.object_identities() {
        if let Some(publication) = UpgradePublication::decode(
            snapshot
                .object(id)
                .map_err(map_catalog)?
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )? && current.replace((id, publication)).is_some()
        {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
    }
    if let Some((_, publication)) = current
        && let Some(report_id) = publication.verification_report()
    {
        let object = snapshot
            .object_identities()
            .find(|id| id.to_bytes() == report_id)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let report = positron_kernel::upgrade_verification::UpgradeVerificationReport::from_bytes(
            snapshot
                .object(object)
                .map_err(map_catalog)?
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let integrity = positron_kernel::BootstrapIntegrityIdentity::from_pinned(
            governance.integrity_public_key(),
            governance.integrity_key_fingerprint(),
        )
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        report
            .verify(integrity)
            .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        let input = report.input();
        if input.instance() != governance.instance()
            || input.operation() != publication.operation_id().to_bytes()
            || input.publication() != publication.verification_publication_identity()?
            || input.catalog_generation() > snapshot.number()
        {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
    }
    Ok(current)
}
pub(super) fn publish_current(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    operation: DurableOperation,
) -> Result<DurableOperation, DurableOperationFailure> {
    publish_current_with_additions(catalog, snapshot, operation, Vec::new())
}
pub(super) fn publish_current_with_additions(
    catalog: &Catalog<'_>,
    snapshot: &CatalogSnapshot,
    operation: DurableOperation,
    mut additional: Vec<CatalogObject>,
) -> Result<DurableOperation, DurableOperationFailure> {
    let publication = UpgradePublication::from_operation(operation)?;
    let previous = current(snapshot)?.map(|(id, _)| id);
    additional.push(CatalogObject::new(publication.encode()).map_err(map_catalog)?);
    publish_with_objects(catalog, snapshot, operation, additional, previous)
}
