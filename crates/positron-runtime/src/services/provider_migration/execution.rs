use super::*;

/// Reconciles one acceptance/task-publication crash gap before dispatch. Each
/// worker turn remains bounded; existing tasks retain their exact association.
pub(in crate::services) fn recover_accepted_task(
    services: &ServiceHandle,
) -> Result<(), crate::ServiceFailure> {
    use crate::ServiceFailure;
    let Some(_gate) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogBusy);
    };
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let coordinator = services.instance.maintenance_coordinator();
    let mut after = None;
    while let Some(operation) =
        DurableOperationAdministration::next_key_provider_migration_operation(&catalog, after)
            .map_err(|_| ServiceFailure::CorruptState)?
    {
        require_root_operation(operation, services.instance.instance.to_bytes())
            .map_err(|_| ServiceFailure::CorruptState)?;
        after = Some(operation.operation_id());
        let task = positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
            .map_err(|_| ServiceFailure::CorruptState)?;
        match coordinator.status(task) {
            Ok(_) => continue,
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(failure) => return Err(crate::services::maintenance::map_failure(failure)),
        }
        let parameters = operation
            .key_provider_migration_parameters()
            .ok_or(ServiceFailure::CorruptState)?;
        let binding = RootProviderMigrationBinding::new(
            operation.operation_id().to_bytes(),
            parameters.intent_digest(),
        )
        .map_err(|_| ServiceFailure::CorruptState)?;
        let generation = operation
            .request()
            .accepted_generation()
            .checked_add(1)
            .ok_or(ServiceFailure::CorruptState)?;
        coordinator
            .submit_root_provider_migration_and_persist(
                &catalog,
                binding,
                MaintenancePreconditions::new(generation, 1)
                    .map_err(crate::services::maintenance::map_failure)?,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )
            .map_err(crate::services::maintenance::map_failure)?;
        break;
    }
    Ok(())
}
/// The coordinator reservation owns this attempt. Native custody keeps the
/// existing instance lease; no serving Catalog gate is held during provider I/O.
pub(in crate::services) fn complete(
    services: &ServiceHandle,
    execution: &positron_kernel::MaintenanceExecution<'_>,
) -> Result<bool, crate::ServiceFailure> {
    use crate::ServiceFailure;
    use positron_governance::{DurableOperationPhase, DurableOperationStatus};
    let binding = RootProviderMigrationBinding::from_execution(execution)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let id = OperationId::from_bytes(binding.operation_id())
        .map_err(|_| ServiceFailure::CorruptState)?;
    let (operation, actor, parameters) = {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let operation = DurableOperationAdministration::inspect(&catalog, id)
            .map_err(|_| ServiceFailure::CorruptState)?
            .ok_or(ServiceFailure::CorruptState)?;
        require_root_operation(operation, services.instance.instance.to_bytes())
            .map_err(|_| ServiceFailure::CorruptState)?;
        let parameters = operation
            .key_provider_migration_parameters()
            .ok_or(ServiceFailure::CorruptState)?;
        if parameters.intent_digest() != binding.intent_digest() {
            return Err(ServiceFailure::CorruptState);
        }
        if operation.status().is_terminal() {
            execution
                .complete_and_persist(
                    services.instance.maintenance_coordinator(),
                    &catalog,
                    operation.status() == DurableOperationStatus::Succeeded,
                )
                .map_err(crate::services::maintenance::map_failure)?;
            return Ok(true);
        }
        let now = services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let actor = match DurableOperationAdministration::resume_key_provider_migration_actor(
            &catalog, id, now,
        ) {
            Ok(actor) => actor,
            Err(positron_governance::DurableOperationFailure::Unauthorized) => {
                DurableOperationAdministration::reject_key_provider_migration_authorization(
                    &catalog, id, now,
                )
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                execution
                    .complete_and_persist(
                        services.instance.maintenance_coordinator(),
                        &catalog,
                        false,
                    )
                    .map_err(crate::services::maintenance::map_failure)?;
                return Ok(true);
            },
            Err(_) => return Err(ServiceFailure::CatalogUnavailable),
        };
        let operation = if operation.status() == DurableOperationStatus::Pending {
            DurableOperationAdministration::begin(&catalog, actor, id, now)
                .map_err(|_| ServiceFailure::CatalogUnavailable)?
        } else {
            operation
        };
        (operation, actor, parameters)
    };
    let configuration = parameters
        .configuration_reference()
        .map(load_configuration)
        .transpose()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    if configuration
        .as_ref()
        .map(positron_config::EffectiveConfiguration::audit_binding_digest)
        != parameters.configuration_digest()
    {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        DurableOperationAdministration::fail_key_provider_migration(
            &catalog,
            actor,
            id,
            services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?,
        )
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        execution
            .complete_and_persist(services.instance.maintenance_coordinator(), &catalog, false)
            .map_err(crate::services::maintenance::map_failure)?;
        return Ok(true);
    }
    {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        if operation.phase() == DurableOperationPhase::Preflight {
            DurableOperationAdministration::mark_draining(
                &catalog,
                actor,
                id,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        }
    }
    let context = crate::instance_bootstrap::RootMigrationContext {
        principal: actor.principal_id(),
        operation: id,
        catalog_gate: &services.catalog_operation,
    };
    let instance = &services.instance;
    let mut retirement_refused = false;
    let phase_result = (|| -> Result<(), ServiceFailure> {
        match parameters.action() {
            KeyProviderMigrationAction::Prepare => {
                let configuration = configuration.as_ref().ok_or(ServiceFailure::CorruptState)?;
                if let Some(access) = configuration.provider_access() {
                    let target = crate::native_root_configuration(access)
                        .map_err(|_| ServiceFailure::KeyUnavailable)?;
                    instance
                        .begin_key_provider_migration_for_operation(target, Some(context))
                        .map_err(crate::services::tenant_rotation::rotation_failure)?;
                } else {
                    instance
                        .begin_local_key_rotation_for_operation(Some(context))
                        .map_err(crate::services::tenant_rotation::rotation_failure)?;
                }
            },
            KeyProviderMigrationAction::Activate => {
                let configuration = configuration.as_ref().ok_or(ServiceFailure::CorruptState)?;
                if let Some(access) = configuration.provider_access() {
                    let target = crate::native_root_configuration(access)
                        .map_err(|_| ServiceFailure::KeyUnavailable)?;
                    instance
                        .activate_key_provider_migration_for_operation(target, Some(context))
                        .map_err(crate::services::tenant_rotation::rotation_failure)?;
                } else {
                    instance
                        .activate_local_key_rotation_for_operation(Some(context))
                        .map_err(crate::services::tenant_rotation::rotation_failure)?;
                }
            },
            KeyProviderMigrationAction::Cancel | KeyProviderMigrationAction::Resume => {
                instance
                    .set_key_provider_migration_cancelled_for_operation(
                        parameters.action() == KeyProviderMigrationAction::Cancel,
                        context,
                    )
                    .map_err(crate::services::tenant_rotation::rotation_failure)?;
            },
            KeyProviderMigrationAction::Verify | KeyProviderMigrationAction::Retire => {
                let configuration = configuration.as_ref().ok_or(ServiceFailure::CorruptState)?;
                let native = configuration
                    .provider_access()
                    .map(crate::native_root_configuration)
                    .transpose()
                    .map_err(|_| ServiceFailure::KeyUnavailable)?;
                let result = instance.verify_or_retire_key_provider_for_operation(
                    native,
                    context,
                    execution,
                    parameters.action() == KeyProviderMigrationAction::Retire,
                );
                retirement_refused = matches!(
                    result,
                    Err(crate::LocalKeyRotationFailure::RetirementRefused)
                );
                result.map_err(crate::services::tenant_rotation::rotation_failure)?;
            },
        }
        Ok(())
    })();
    if let Err(failure) = phase_result {
        if retirement_refused {
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            DurableOperationAdministration::fail_key_provider_migration(
                &catalog,
                actor,
                id,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            execution
                .complete_and_persist(instance.maintenance_coordinator(), &catalog, false)
                .map_err(crate::services::maintenance::map_failure)?;
            return Ok(true);
        }
        return Err(failure);
    }
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    DurableOperationAdministration::succeed_key_provider_migration(
        &catalog,
        actor,
        id,
        services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    execution
        .complete_and_persist(instance.maintenance_coordinator(), &catalog, true)
        .map_err(crate::services::maintenance::map_failure)?;
    Ok(true)
}
