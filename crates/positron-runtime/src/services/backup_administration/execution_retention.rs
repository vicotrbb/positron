//! Signed retention claims retain one Maintenance owner through delete and acknowledgement.
use super::*;
use positron_backup::{BackupCleanupPlan, BackupCleanupProgress, BackupCleanupReason};
use positron_governance::{
    BackupCleanupReceipt, BackupRetentionClaimReceipt, BackupRetentionStage,
};

pub(in crate::services) struct RetentionWork {
    pub(super) owner: owner::BackupOwner,
    state: State,
}
enum State {
    Recover,
    Prepare,
    Scan(BackupCleanupPlan),
    Claim(BackupCleanupPlan),
    Delete(BackupCleanupProgress),
    Complete(BackupCleanupProgress),
}
fn validate(
    progress: BackupCleanupProgress,
    operation: DurableOperation,
) -> Result<(), ServiceFailure> {
    let parameters = operation
        .backup_retention_parameters()
        .ok_or(ServiceFailure::CorruptState)?;
    if progress.owner() != operation.operation_id().to_bytes()
        || progress.reason() != BackupCleanupReason::Retention
        || progress.snapshot_id() != parameters.snapshot_id()
        || progress.manifest().checksum() != parameters.manifest_checksum()
    {
        return Err(ServiceFailure::CorruptState);
    }
    Ok(())
}
pub(super) fn complete(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut Option<BackupWork>,
    operation: DurableOperation,
    actor: positron_governance::AuthorizedContext,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(super::super::super::maintenance::map_failure)?;
    if operation.status() == DurableOperationStatus::Failed {
        *work = None;
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        execution
            .complete_and_persist(services.instance.maintenance_coordinator(), &catalog, false)
            .map_err(super::super::super::maintenance::map_failure)?;
        return Ok(true);
    }
    if operation.phase() == DurableOperationPhase::BackupCancellation
        || operation.status() == DurableOperationStatus::Cancelled
    {
        // Cancellation is admitted only before the publication cutoff; no
        // retention claim or provider deletion can exist for this operation.
        *work = None;
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let now = services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        DurableOperationAdministration::complete_backup_cancellation(
            &catalog,
            actor,
            operation.operation_id(),
            now,
        )
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let coordinator = services.instance.maintenance_coordinator();
        coordinator
            .cancel_and_persist(&catalog, execution.task().identity())
            .map_err(super::super::super::maintenance::map_failure)?;
        execution
            .complete_and_persist(coordinator, &catalog, false)
            .map_err(super::super::super::maintenance::map_failure)?;
        return Ok(true);
    }
    if !matches!(work, Some(BackupWork::Retention(_))) {
        *work = None;
        let mut owner = owner::BackupOwner::open(services, execution, operation)?;
        if !owner.registry_ready(services, execution, 0)? {
            return Ok(false);
        }
        let (_, owner_checkpoint) = checkpoint::current(services, execution, binding)?;
        let (_, checkpoint) = checkpoint::unpack(&owner_checkpoint)?;
        let state = if let Some(proof) = checkpoint.strip_prefix(b"POSBKE02") {
            let progress = owner
                .runtime
                .block_on(
                    owner
                        .publisher(0)
                        .map_err(provider_failure)?
                        .verify_cleanup_checkpoint(proof),
                )
                .map_err(provider_failure)?;
            validate(progress, operation)?;
            State::Complete(progress)
        } else {
            State::Recover
        };
        *work = Some(BackupWork::Retention(Box::new(RetentionWork {
            owner,
            state,
        })));
    }
    let Some(BackupWork::Retention(work)) = work.as_mut() else {
        return Err(ServiceFailure::CorruptState);
    };
    let retained = match &work.state {
        State::Scan(plan) | State::Claim(plan) => {
            plan.retained_memory_bytes().map_err(provider_failure)?
        },
        _ => 0,
    };
    if !work.owner.registry_ready(services, execution, retained)? {
        return Ok(false);
    }
    let publisher = work.owner.publisher(0).map_err(provider_failure)?;
    let parameters = operation
        .backup_retention_parameters()
        .ok_or(ServiceFailure::CorruptState)?;
    match &mut work.state {
        State::Recover => {
            work.state = match work
                .owner
                .runtime
                .block_on(publisher.cleanup_for_owner(binding.operation_id()))
                .map_err(provider_failure)?
            {
                Some(progress) => {
                    validate(progress, operation)?;
                    record_claim(services, actor, operation, &work.owner.identity, progress)?;
                    work.owner.set_trusted(progress.registry_generation());
                    State::Delete(progress)
                },
                None if operation.status() == DurableOperationStatus::Succeeded => {
                    return Err(ServiceFailure::StorageUnavailable);
                },
                None => State::Prepare,
            };
        },
        State::Prepare => {
            work.state = State::Scan(
                work.owner
                    .runtime
                    .block_on(publisher.prepare_expiry(
                        binding.operation_id(),
                        parameters.snapshot_id(),
                        parameters.manifest_checksum(),
                    ))
                    .map_err(retention_failure)?,
            );
        },
        State::Scan(plan) => {
            if work
                .owner
                .runtime
                .block_on(publisher.scan_expiry_step(plan))
                .map_err(retention_failure)?
            {
                // Preparation authenticated the exact signed target and its
                // deadline. Known early commands fail rather than inventing a
                // schedule; uncertainty remains pending. The engine checks
                // trusted time again immediately before its irreversible CAS.
                let now = services
                    .instance
                    .retention_time
                    .destructive_governance_now_seconds()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?;
                if now < plan.retain_until() {
                    let _gate = services.catalog_operation()?;
                    let catalog = services
                        .open_maintenance_catalog()
                        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    DurableOperationAdministration::reject_backup_retention_not_due(
                        &catalog,
                        actor,
                        operation.operation_id(),
                        services
                            .maintenance_status_now()
                            .map_err(|_| ServiceFailure::StorageUnavailable)?,
                    )
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    execution
                        .complete_and_persist(
                            services.instance.maintenance_coordinator(),
                            &catalog,
                            false,
                        )
                        .map_err(super::super::super::maintenance::map_failure)?;
                    return Ok(true);
                }
                if operation.phase() != DurableOperationPhase::BackupRetentionPublication {
                    let _gate = services.catalog_operation()?;
                    let catalog = services
                        .open_maintenance_catalog()
                        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    DurableOperationAdministration::advance_backup_retention(
                        &catalog,
                        actor,
                        operation.operation_id(),
                        BackupRetentionStage::Publishing,
                        services
                            .maintenance_status_now()
                            .map_err(|_| ServiceFailure::StorageUnavailable)?,
                    )
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                }
                // Keep the scanned candidate in memory only. A cold restart
                // rechecks the signed head and exact target before any CAS.
                let state = std::mem::replace(&mut work.state, State::Recover);
                let State::Scan(plan) = state else {
                    return Err(ServiceFailure::CorruptState);
                };
                work.state = State::Claim(plan);
            }
        },
        State::Claim(plan) => {
            if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
                return Err(ServiceFailure::Cancelled);
            }
            match work
                .owner
                .runtime
                .block_on(publisher.claim_expiry(plan, &services.instance.retention_time))
            {
                Ok(progress) => {
                    validate(progress, operation)?;
                    record_claim(services, actor, operation, &work.owner.identity, progress)?;
                    work.owner.set_trusted(progress.registry_generation());
                    work.state = State::Delete(progress);
                },
                Err(RepositoryFailure::PreconditionFailed) => {
                    work.state = State::Recover;
                    return Err(ServiceFailure::StorageUnavailable);
                },
                Err(failure) => {
                    work.state = State::Recover;
                    return Err(retention_failure(failure));
                },
            }
        },
        State::Delete(progress) => {
            validate(*progress, operation)?;
            if progress.complete() {
                let mut checkpoint = b"POSBKE02".to_vec();
                checkpoint.extend_from_slice(
                    &publisher
                        .cleanup_checkpoint(*progress)
                        .map_err(provider_failure)?,
                );
                cancellation::checkpoint(services, execution, binding, &checkpoint)?;
                work.state = State::Complete(*progress);
            } else {
                *progress = work
                    .owner
                    .runtime
                    .block_on(publisher.delete_expired_step(
                        binding.operation_id(),
                        parameters.manifest_checksum(),
                    ))
                    .map_err(retention_failure)?;
            }
        },
        State::Complete(progress) => {
            if operation.status() == DurableOperationStatus::Succeeded {
                work.owner
                    .runtime
                    .block_on(
                        publisher.acknowledge_expiry(
                            binding.operation_id(),
                            parameters.manifest_checksum(),
                        ),
                    )
                    .map_err(retention_failure)?;
                let _gate = services.catalog_operation()?;
                let catalog = services
                    .open_maintenance_catalog()
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                execution
                    .complete_and_persist(
                        services.instance.maintenance_coordinator(),
                        &catalog,
                        true,
                    )
                    .map_err(super::super::super::maintenance::map_failure)?;
                return Ok(true);
            }
            let receipt = BackupCleanupReceipt::new(
                progress.snapshot_id(),
                progress.manifest().checksum(),
                progress.registry_generation(),
                progress.deleted_objects(),
                progress.already_absent_objects(),
                progress.retained_shared_objects(),
            )
            .map_err(|_| ServiceFailure::CorruptState)?;
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            let (previous, registration) =
                registration(&catalog, services, &work.owner.identity, operation)?;
            let successor = registration
                .with_registry_generation(progress.registry_generation())
                .and_then(|row| row.catalog_object())
                .map_err(provider_failure)?;
            DurableOperationAdministration::succeed_backup_retention_with_registration(
                &catalog,
                actor,
                operation.operation_id(),
                receipt,
                previous,
                successor,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            work.owner.set_trusted(progress.registry_generation());
        },
    }
    Ok(false)
}
fn registration(
    catalog: &positron_kernel::Catalog<'_>,
    services: &ServiceHandle,
    identity: &RepositoryIdentity,
    operation: DurableOperation,
) -> Result<
    (
        positron_kernel::CatalogObjectId,
        positron_backup::BackupRepositoryRegistration,
    ),
    ServiceFailure,
> {
    let basis = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let (address, registration) = positron_backup::BackupRepositoryRegistration::find(
        &basis,
        services.instance.instance.to_bytes(),
        identity.repository_id(),
    )
    .map_err(provider_failure)?
    .ok_or(ServiceFailure::CorruptState)?;
    if registration.identity() != identity
        || registration.binding_identity().map_err(provider_failure)?
            != operation
                .backup_binding()
                .ok_or(ServiceFailure::CorruptState)?
                .registration_identity()
    {
        return Err(ServiceFailure::CorruptState);
    }
    Ok((address, registration))
}
fn record_claim(
    services: &ServiceHandle,
    actor: positron_governance::AuthorizedContext,
    operation: DurableOperation,
    identity: &RepositoryIdentity,
    progress: BackupCleanupProgress,
) -> Result<(), ServiceFailure> {
    if operation.irreversible_boundary()
        == positron_governance::DurableOperationBoundary::BackupRegistryExpired
    {
        return Ok(());
    }
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let (previous, registration) = registration(&catalog, services, identity, operation)?;
    let successor = registration
        .with_registry_generation(progress.registry_generation())
        .and_then(|row| row.catalog_object())
        .map_err(provider_failure)?;
    DurableOperationAdministration::publish_backup_retention_claim_with_registration(
        &catalog,
        actor,
        operation.operation_id(),
        BackupRetentionClaimReceipt::new(progress.registry_generation())
            .map_err(|_| ServiceFailure::CorruptState)?,
        previous,
        successor,
        services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    Ok(())
}
fn retention_failure(failure: RepositoryFailure) -> ServiceFailure {
    match failure {
        RepositoryFailure::PreconditionFailed | RepositoryFailure::NotFound => {
            ServiceFailure::StorageUnavailable
        },
        _ => provider_failure(failure),
    }
}
