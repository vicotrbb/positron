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
        let snapshot_key = child_key(self.id, b"snapshot")?;
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
        if snapshot.kind() != DurableOperationKind::BackupSnapshot
            || snapshot.backup_parameters() != Some(parameters.backup())
            || snapshot.target_identity() != operation.target_identity()
            || snapshot.request().principal() != operation.request().principal()
        {
            return Err(UpgradeFailure::InvalidRequest);
        }
        self.services
            .drive_upgrade_backup_operation(snapshot.operation_id(), deadline)
    }
    pub(super) fn verification_operation(
        &self,
        operation: &DurableOperation,
        snapshot: &DurableOperation,
        deadline: Instant,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let parameters = operation
            .upgrade_parameters()
            .ok_or(UpgradeFailure::UnsafeState)?;
        let verification_key = child_key(self.id, b"verification")?;
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
        let verified = verification
            .backup_verification_parameters()
            .ok_or(UpgradeFailure::InvalidRequest)?;
        let receipt = snapshot
            .backup_receipt()
            .ok_or(UpgradeFailure::SnapshotUnavailable)?;
        if verification.kind() != DurableOperationKind::BackupVerification
            || verification.target_identity() != operation.target_identity()
            || verification.request().principal() != operation.request().principal()
            || verified.snapshot_id() != snapshot.operation_id().to_bytes()
            || verified.manifest_checksum() != receipt.manifest()
            || verified.repository() != parameters.backup().repository()
        {
            return Err(UpgradeFailure::InvalidRequest);
        }
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
