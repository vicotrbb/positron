use super::*;
use crate::ServiceFailure;
use positron_backup::{LocalRepository, Repository, RepositoryFailure, RepositoryIdentity};
use positron_governance::{DurableOperationPhase, DurableOperationStatus};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
/// Repairs one acceptance/task-publication gap per bounded worker turn.
pub(in crate::services) fn recover_accepted_task(
    services: &ServiceHandle,
) -> Result<(), ServiceFailure> {
    let Some(_gate) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogBusy);
    };
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let coordinator = services.instance.maintenance_coordinator();
    let mut after = None;
    while let Some(operation) =
        DurableOperationAdministration::next_repository_operation(&catalog, after)
            .map_err(|_| ServiceFailure::CorruptState)?
    {
        require_operation(operation, services.instance.instance.to_bytes())?;
        after = Some(operation.operation_id());
        let task = positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
            .map_err(|_| ServiceFailure::CorruptState)?;
        match coordinator.status(task) {
            Ok(_) => continue,
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(failure) => return Err(super::super::maintenance::map_failure(failure)),
        }
        let parameters = operation
            .repository_parameters()
            .ok_or(ServiceFailure::CorruptState)?;
        let binding = RepositoryOperationBinding::new(
            operation.operation_id().to_bytes(),
            parameters.intent_digest(),
        )
        .map_err(|_| ServiceFailure::CorruptState)?;
        coordinator
            .submit_repository_operation_and_persist(
                &catalog,
                binding,
                MaintenancePreconditions::new(
                    operation
                        .request()
                        .accepted_generation()
                        .checked_add(1)
                        .ok_or(ServiceFailure::CorruptState)?,
                    1,
                )
                .map_err(super::super::maintenance::map_failure)?,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )
            .map_err(super::super::maintenance::map_failure)?;
        break;
    }
    Ok(())
}
pub(in crate::services) fn complete(
    services: &ServiceHandle,
    execution: &positron_kernel::MaintenanceExecution<'_>,
) -> Result<bool, ServiceFailure> {
    let binding = RepositoryOperationBinding::from_execution(execution)
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
        require_operation(operation, services.instance.instance.to_bytes())?;
        let parameters = operation
            .repository_parameters()
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
                .map_err(super::super::maintenance::map_failure)?;
            return Ok(true);
        }
        let now = services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let actor = match DurableOperationAdministration::resume_repository_actor(&catalog, id, now)
        {
            Ok(actor) => actor,
            Err(positron_governance::DurableOperationFailure::Unauthorized) => {
                DurableOperationAdministration::reject_repository_authorization(&catalog, id, now)
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                execution
                    .complete_and_persist(
                        services.instance.maintenance_coordinator(),
                        &catalog,
                        false,
                    )
                    .map_err(super::super::maintenance::map_failure)?;
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
        if operation.phase() == DurableOperationPhase::Preflight {
            DurableOperationAdministration::mark_draining(&catalog, actor, id, now)
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        }
        (operation, actor, parameters)
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let result = runtime.block_on(async {
        let path = Path::new(
            parameters
                .locator()
                .map_err(|_| RepositoryFailure::CorruptState)?,
        );
        let identity = RepositoryIdentity::local(
            parameters.repository_id(),
            services.instance.instance.to_bytes(),
            parameters.integrity_fingerprint(),
            path,
        )?;
        if identity.prefix_commitment() != parameters.prefix_commitment() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let repository = match parameters.action() {
            RepositoryAction::Initialize => match LocalRepository::attach(path, &identity).await {
                Ok(repository) => repository,
                Err(RepositoryFailure::NotFound) => {
                    LocalRepository::initialize(path, identity.clone()).await?
                },
                Err(failure) => return Err(failure),
            },
            RepositoryAction::Verify | RepositoryAction::Doctor => {
                LocalRepository::attach(path, &identity).await?
            },
        };
        if repository.identify().await? != identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if parameters.action() == RepositoryAction::Doctor {
            let mut probe = [0; 32];
            let operation_id = operation.operation_id().to_bytes();
            probe
                .get_mut(..16)
                .ok_or(RepositoryFailure::CorruptState)?
                .copy_from_slice(&operation_id);
            probe
                .get_mut(16..)
                .ok_or(RepositoryFailure::CorruptState)?
                .copy_from_slice(&operation_id);
            positron_backup::doctor(
                &repository,
                positron_backup::DoctorPlan::new(
                    probe,
                    identity,
                    Duration::from_secs(30),
                    Arc::new(AtomicBool::new(false)),
                )?,
            )
            .await?;
        }
        Ok(())
    });
    let success = match result {
        Ok(()) => true,
        Err(RepositoryFailure::Busy | RepositoryFailure::Throttled { .. }) => {
            return Err(ServiceFailure::CapacityUnavailable);
        },
        Err(
            RepositoryFailure::StorageUnavailable
            | RepositoryFailure::OutcomeUnknown
            | RepositoryFailure::Interrupted,
        ) => return Err(ServiceFailure::StorageUnavailable),
        Err(_) => false,
    };
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let now = services
        .maintenance_status_now()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    if success {
        DurableOperationAdministration::succeed_repository(&catalog, actor, id, now)
    } else {
        DurableOperationAdministration::fail_repository(&catalog, actor, id, now)
    }
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    execution
        .complete_and_persist(
            services.instance.maintenance_coordinator(),
            &catalog,
            success,
        )
        .map_err(super::super::maintenance::map_failure)?;
    Ok(true)
}
