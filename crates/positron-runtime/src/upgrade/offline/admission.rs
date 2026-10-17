//! Authenticate exact final Drain before creating any offline services.
use super::*;

impl OfflineUpgradeSession {
    /// Cancels accepted pre-Drain intent or replays an authenticated cancellation.
    /// This owner never constructs ordinary services or admits mutable work.
    pub fn cancel_intent(
        paths: &BootstrapPaths,
        configuration: &EffectiveConfiguration,
        id: OperationId,
        key: AdministrativeIdempotencyKey,
        revision: u64,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let instance = InstanceBootstrap::reopen_configured(paths, configuration)
            .map_err(|_| UpgradeFailure::UnsafeState)?;
        let catalog = open(&instance)?;
        let operation = Administration::inspect(&catalog, id)
            .map_err(persistence)?
            .ok_or(UpgradeFailure::InvalidRequest)?;
        if operation.kind() != DurableOperationKind::Upgrade
            || operation.target_identity() != Some(instance.instance.to_bytes())
            || operation.upgrade_parameters().is_none_or(|parameters| {
                parameters.configuration_digest() != configuration.audit_binding_digest()
            })
        {
            return Err(UpgradeFailure::UnsafeState);
        }
        let actor = actor(&catalog, &instance, id)?;
        if operation.status() == DurableOperationStatus::Cancelled
            && operation.cancellation_idempotency_key() == Some(key)
        {
            return Administration::cancel_upgrade(
                &catalog,
                actor,
                id,
                key,
                revision,
                now(&instance)?,
            )
            .map_err(persistence);
        }
        if operation.upgrade_drain_evidence().is_some()
            || !matches!(
                operation.upgrade_stage(),
                Some(UpgradeStage::Preflight | UpgradeStage::Draining)
            )
        {
            return Err(UpgradeFailure::UnsafeState);
        }
        let time = now(&instance)?;
        if time < operation.updated_at_unix_seconds() {
            return Err(UpgradeFailure::SnapshotUnavailable);
        }
        Administration::cancel_upgrade(&catalog, actor, id, key, revision, time)
            .map_err(persistence)
    }

    pub fn begin(
        paths: &BootstrapPaths,
        configuration: &EffectiveConfiguration,
        id: OperationId,
    ) -> Result<Self, UpgradeFailure> {
        let instance = Arc::new(
            InstanceBootstrap::reopen_configured(paths, configuration)
                .map_err(|_| UpgradeFailure::UnsafeState)?,
        );
        let operation = {
            let catalog = open(&instance)?;
            Administration::inspect(&catalog, id)
                .map_err(persistence)?
                .ok_or(UpgradeFailure::InvalidRequest)?
        };
        if operation.kind() != DurableOperationKind::Upgrade
            || operation.target_identity() != Some(instance.instance.to_bytes())
            || !matches!(
                operation.status(),
                DurableOperationStatus::Running | DurableOperationStatus::Failed
            )
        {
            return Err(UpgradeFailure::UnsafeState);
        }
        let parameters = operation
            .upgrade_parameters()
            .ok_or(UpgradeFailure::InvalidRequest)?;
        if parameters.configuration_digest() != configuration.audit_binding_digest() {
            return Err(UpgradeFailure::InvalidRequest);
        }
        let record = instance
            .graceful_shutdown_record()
            .map_err(|_| UpgradeFailure::DrainIncomplete)?
            .ok_or(UpgradeFailure::DrainIncomplete)?;
        instance
            .verify_graceful_shutdown_frontiers(&record)
            .map_err(|_| UpgradeFailure::DrainIncomplete)?;
        {
            let catalog = open(&instance)?;
            let basis = catalog
                .pin()
                .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
            if basis
                .format_epoch()
                .map(positron_kernel::FormatEpoch::value)
                != Some(parameters.format_epoch())
            {
                return Err(UpgradeFailure::UnsupportedTransition);
            }
            let committed = catalog
                .confirm_committed_transaction(
                    TransactionId::new(record.transaction())
                        .map_err(|_| UpgradeFailure::DrainIncomplete)?,
                )
                .map_err(|_| UpgradeFailure::DrainIncomplete)?
                .ok_or(UpgradeFailure::DrainIncomplete)?;
            let final_snapshot = committed.snapshot();
            let final_operation = Administration::inspect_snapshot_by_idempotency(
                final_snapshot,
                operation.request().idempotency_key(),
            )
            .map_err(persistence)?
            .ok_or(UpgradeFailure::DrainIncomplete)?;
            if committed.number() != record.catalog_generation()
                || committed.predecessor().to_bytes() != record.predecessor()
                || final_operation.operation_id() != id
                || final_operation.upgrade_stage() != Some(UpgradeStage::Draining)
                || final_operation.status() != DurableOperationStatus::Running
            {
                return Err(UpgradeFailure::DrainIncomplete);
            }
            let evidence = UpgradeDrainEvidence::new(
                final_snapshot.identity().to_bytes(),
                committed.number(),
                record.marker_identity(),
                record.transaction(),
            )
            .map_err(persistence)?;
            match operation.upgrade_drain_evidence() {
                None => {
                    if operation.upgrade_stage() != Some(UpgradeStage::Draining)
                        || basis.identity() != final_snapshot.identity()
                    {
                        return Err(UpgradeFailure::DrainIncomplete);
                    }
                    if now(&instance)? < operation.updated_at_unix_seconds() {
                        return Err(UpgradeFailure::SnapshotUnavailable);
                    }
                    let actor = actor(&catalog, &instance, id)?;
                    Administration::record_upgrade_drain(
                        &catalog,
                        actor,
                        id,
                        evidence,
                        now(&instance)?,
                    )
                    .map_err(persistence)?;
                },
                Some(existing) if existing == evidence => {},
                Some(_) => return Err(UpgradeFailure::DrainIncomplete),
            }
        }
        let services =
            ServiceHandle::new(Arc::clone(&instance)).map_err(|_| UpgradeFailure::UnsafeState)?;
        Ok(Self {
            instance,
            services,
            id,
        })
    }
}
