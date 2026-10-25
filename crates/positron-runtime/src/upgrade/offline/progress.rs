//! Secret-safe progress for the two children of an authenticated offline upgrade.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeCheckpointProgress {
    pub sequence: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeChildProgress {
    pub kind: DurableOperationKind,
    pub phase: positron_governance::DurableOperationPhase,
    pub status: DurableOperationStatus,
    pub revision: u64,
    pub progress_percent: u8,
    pub checkpoint: Option<UpgradeCheckpointProgress>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineUpgradeProgress {
    pub operation: DurableOperation,
    pub snapshot: Option<UpgradeChildProgress>,
    pub verification: Option<UpgradeChildProgress>,
}
impl OfflineUpgradeSession {
    /// Reads bounded child summaries without starting mutable services.
    pub fn inspect_progress(
        paths: &BootstrapPaths,
        configuration: &EffectiveConfiguration,
        id: OperationId,
    ) -> Result<OfflineUpgradeProgress, UpgradeFailure> {
        let instance = InstanceBootstrap::reopen_configured_read_only(paths, configuration)
            .map_err(|_| UpgradeFailure::UnsafeState)?;
        read_progress(&instance, configuration, id)
    }
    /// Reads the current child checkpoints while retaining exclusive offline ownership.
    pub fn progress(
        &self,
        configuration: &EffectiveConfiguration,
    ) -> Result<OfflineUpgradeProgress, UpgradeFailure> {
        read_progress(&self.instance, configuration, self.id)
    }
}
fn read_progress(
    instance: &InitializedInstance,
    configuration: &EffectiveConfiguration,
    id: OperationId,
) -> Result<OfflineUpgradeProgress, UpgradeFailure> {
    let view = Catalog::read_current_view(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| UpgradeFailure::AuthenticationFailed)?,
    )
    .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
    let basis = view.snapshot();
    let operation = reference::inspect_operation(basis, instance.instance, configuration, id)?;
    let snapshot = Administration::inspect_snapshot_by_idempotency(
        basis,
        Administration::upgrade_snapshot_key(id).map_err(persistence)?,
    )
    .map_err(persistence)?;
    if let Some(child) = &snapshot {
        snapshot::validate_snapshot_child(&operation, child)?;
    }
    let verification = Administration::inspect_snapshot_by_idempotency(
        basis,
        Administration::upgrade_snapshot_verification_key(id).map_err(persistence)?,
    )
    .map_err(persistence)?;
    if let Some(child) = &verification {
        snapshot::validate_verification_child(
            &operation,
            snapshot.as_ref().ok_or(UpgradeFailure::InvalidRequest)?,
            child,
        )?;
    }
    Ok(OfflineUpgradeProgress {
        operation,
        snapshot: snapshot.map(|child| summarize(basis, child)).transpose()?,
        verification: verification
            .map(|child| summarize(basis, child))
            .transpose()?,
    })
}
fn summarize(
    basis: &positron_kernel::CatalogSnapshot,
    operation: DurableOperation,
) -> Result<UpgradeChildProgress, UpgradeFailure> {
    use sha2::Digest;
    let identity = positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
        .map_err(|_| UpgradeFailure::InvalidRequest)?;
    let checkpoint =
        positron_kernel::MaintenanceCoordinator::inspect_checkpoint_snapshot(basis, identity)
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?
            .map(|checkpoint| UpgradeCheckpointProgress {
                sequence: checkpoint.sequence(),
                sha256: sha2::Sha256::digest(checkpoint.opaque_progress()).into(),
            });
    Ok(UpgradeChildProgress {
        kind: operation.kind(),
        phase: operation.phase(),
        status: operation.status(),
        revision: operation.revision(),
        progress_percent: operation.progress_percent(),
        checkpoint,
    })
}
