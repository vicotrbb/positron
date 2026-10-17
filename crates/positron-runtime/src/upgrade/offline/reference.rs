//! Historical recovery instructions need authenticated Catalog, not mutable data.
use super::*;

impl OfflineUpgradeSession {
    /// Inspects an authenticated operation without starting mutable services.
    pub fn inspect(
        paths: &BootstrapPaths,
        configuration: &EffectiveConfiguration,
        id: OperationId,
    ) -> Result<DurableOperation, UpgradeFailure> {
        let instance = InstanceBootstrap::reopen_configured_read_only(paths, configuration)
            .map_err(|_| UpgradeFailure::UnsafeState)?;
        let view = Catalog::read_current_view(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| UpgradeFailure::AuthenticationFailed)?,
        )
        .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        let operation = Administration::inspect_snapshot(view.snapshot(), id)
            .map_err(persistence)?
            .ok_or(UpgradeFailure::InvalidRequest)?;
        if operation.kind() != DurableOperationKind::Upgrade
            || operation.target_identity() != Some(instance.instance.to_bytes())
            || operation.upgrade_parameters().is_none_or(|parameters| {
                parameters.configuration_digest() != configuration.audit_binding_digest()
            })
        {
            return Err(UpgradeFailure::InvalidRequest);
        }
        Ok(operation)
    }
    /// Reads the exact retained verified snapshot for the existing fresh-target
    /// Restore owner. This does not qualify current repository objects or keys.
    pub fn restore_reference(
        paths: &BootstrapPaths,
        configuration: &EffectiveConfiguration,
        id: OperationId,
    ) -> Result<BackupVerificationParameters, UpgradeFailure> {
        let instance = InstanceBootstrap::reopen_configured_read_only(paths, configuration)
            .map_err(|_| UpgradeFailure::UnsafeState)?;
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
        let (parameters, snapshot) =
            match Administration::inspect_snapshot(basis, id).map_err(persistence)? {
                Some(operation)
                    if operation.kind() == DurableOperationKind::Upgrade
                        && operation.target_identity() == Some(instance.instance.to_bytes()) =>
                {
                    (
                        operation
                            .upgrade_parameters()
                            .ok_or(UpgradeFailure::InvalidRequest)?,
                        operation
                            .upgrade_snapshot_evidence()
                            .ok_or(UpgradeFailure::SnapshotUnavailable)?,
                    )
                },
                Some(_) => return Err(UpgradeFailure::InvalidRequest),
                None => {
                    let publication = Administration::current_upgrade_publication_snapshot(basis)
                        .map_err(persistence)?
                        .filter(|publication| publication.operation_id() == id)
                        .ok_or(UpgradeFailure::InvalidRequest)?;
                    (publication.parameters(), publication.snapshot())
                },
            };
        if parameters.configuration_digest() != configuration.audit_binding_digest() {
            return Err(UpgradeFailure::InvalidRequest);
        }
        BackupVerificationParameters::new(
            parameters.backup().repository(),
            parameters.backup().registration_identity(),
            snapshot.operation_id().to_bytes(),
            snapshot.receipt().manifest(),
        )
        .map_err(persistence)
    }
}
