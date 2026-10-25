//! Mutually exclusive child-operation frames remain scoped to their owning phase.
use super::*;
impl OfflineUpgradeSession {
    pub(super) fn snapshot_operation(
        &self,
        operation: &DurableOperation,
        deadline: Instant,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let parameters = operation
            .upgrade_parameters()
            .ok_or(UpgradeFailure::UnsafeState)?;
        let snapshot_key = Administration::upgrade_snapshot_key(self.id).map_err(persistence)?;
        let snapshot = match self.child(snapshot_key)? {
            Some(operation) => operation,
            None => {
                let catalog = open(&self.instance)?;
                let actor = actor(&catalog, &self.instance, self.id)?;
                let generation = catalog
                    .pin()
                    .map_err(|_| UpgradeFailure::PersistenceUnavailable)?
                    .number();
                drop(catalog);
                self.services.accept_upgrade_snapshot(
                    actor,
                    parameters.backup(),
                    snapshot_key,
                    generation,
                )?
            },
        };
        validate_snapshot_child(operation, &snapshot)?;
        self.services
            .drive_upgrade_backup_operation(snapshot.operation_id(), deadline)
    }
    pub(super) fn verification_operation(
        &self,
        operation: &DurableOperation,
        snapshot: &DurableOperation,
        deadline: Instant,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let verification_key =
            Administration::upgrade_snapshot_verification_key(self.id).map_err(persistence)?;
        let verification = match self.child(verification_key)? {
            Some(operation) => operation,
            None => {
                let catalog = open(&self.instance)?;
                let actor = actor(&catalog, &self.instance, self.id)?;
                let generation = catalog
                    .pin()
                    .map_err(|_| UpgradeFailure::PersistenceUnavailable)?
                    .number();
                drop(catalog);
                self.services.accept_upgrade_verification(
                    actor,
                    *snapshot,
                    verification_key,
                    generation,
                )?
            },
        };
        validate_verification_child(operation, snapshot, &verification)?;
        self.services
            .drive_upgrade_backup_operation(verification.operation_id(), deadline)
    }
    pub(super) fn record_snapshot(
        &self,
        snapshot: OperationId,
        verification: OperationId,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let catalog = open(&self.instance)?;
        let actor = actor(&catalog, &self.instance, self.id)?;
        Administration::record_upgrade_snapshot(
            &catalog,
            actor,
            self.id,
            snapshot,
            verification,
            now(&self.instance)?,
        )
        .map_err(persistence)?;
        drop(catalog);
        self.advance_stage(UpgradeStage::Publishing)
    }
}

pub(super) fn validate_snapshot_child(
    parent: &DurableOperation,
    child: &DurableOperation,
) -> Result<(), UpgradeFailure> {
    let parameters = parent
        .upgrade_parameters()
        .ok_or(UpgradeFailure::UnsafeState)?;
    if child.kind() != DurableOperationKind::BackupSnapshot
        || child.backup_parameters() != Some(parameters.backup())
        || child.target_identity() != parent.target_identity()
        || child.request().principal() != parent.request().principal()
    {
        return Err(UpgradeFailure::InvalidRequest);
    }
    Ok(())
}
pub(super) fn validate_verification_child(
    parent: &DurableOperation,
    snapshot: &DurableOperation,
    child: &DurableOperation,
) -> Result<(), UpgradeFailure> {
    let parameters = parent
        .upgrade_parameters()
        .ok_or(UpgradeFailure::UnsafeState)?;
    let verified = child
        .backup_verification_parameters()
        .ok_or(UpgradeFailure::InvalidRequest)?;
    let receipt = snapshot
        .backup_receipt()
        .ok_or(UpgradeFailure::SnapshotUnavailable)?;
    if child.kind() != DurableOperationKind::BackupVerification
        || child.target_identity() != parent.target_identity()
        || child.request().principal() != parent.request().principal()
        || verified.snapshot_id() != snapshot.operation_id().to_bytes()
        || verified.manifest_checksum() != receipt.manifest()
        || verified.repository() != parameters.backup().repository()
        || verified.registration_identity() != parameters.backup().registration_identity()
    {
        return Err(UpgradeFailure::InvalidRequest);
    }
    Ok(())
}
