//! A new Repository cannot enter managed scope before permanent exclusions apply.
use super::*;
use positron_backup::{BackupPublisher, BackupPurgeTombstone, BackupRepositoryRegistration};
use positron_kernel::{
    Catalog, CatalogObject, NativeAwsResources, ResourceAmounts, ResourceDimension, WorkClaim,
};
pub(super) fn prepare(
    services: &ServiceHandle,
    catalog: &Catalog<'_>,
    parameters: BackupSnapshotParameters,
    original: CatalogObject,
) -> Result<CatalogObject, MaintenanceServiceFailure> {
    let snapshot = catalog
        .pin()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let native = super::super::repository_administration::repository_resources(
        parameters.repository().provider_kind(),
    );
    let memory = native
        .get(ResourceDimension::MemoryBytes)
        .checked_add(BackupPublisher::registry_read_memory_bytes())
        .ok_or(MaintenanceServiceFailure::CapacityUnavailable)?;
    let resources = ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| {
        if dimension == ResourceDimension::MemoryBytes {
            memory
        } else {
            native.get(dimension)
        }
    }));
    let claim = WorkClaim::backup_repository_read(resources)
        .map_err(|_| MaintenanceServiceFailure::CapacityUnavailable)?;
    let grant = NativeAwsResources::new(
        services
            .instance
            .resource_governor()
            .reserve(claim)
            .map_err(|_| MaintenanceServiceFailure::CapacityUnavailable)?
            .transfer(),
    );
    let exclusions = positron_governance::TenantAdministration::restore_purge_exclusions(&snapshot)
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    if exclusions.is_empty() {
        return Ok(original);
    }
    let mut tombstones = Vec::new();
    for exclusion in exclusions {
        tombstones.push(
            BackupPurgeTombstone::new(
                exclusion.tenant_id().to_bytes(),
                exclusion.slug(),
                exclusion
                    .operation_id()
                    .ok_or(MaintenanceServiceFailure::PreconditionFailed)?,
                exclusion
                    .accepted_at_unix_seconds()
                    .ok_or(MaintenanceServiceFailure::PreconditionFailed)?,
            )
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        );
    }
    let (_, governance) = snapshot
        .governance_object()
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let signer = services
        .instance
        .key
        .backup_control_signer(
            services.instance.instance,
            governance.protected_integrity_key(),
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
    let registration = std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("positron-backup-purge-barrier".into())
            .spawn_scoped(scope, || {
                // The outer admitted grant outlives this scoped thread and
                // dedicated runtime, including cancellation of SDK async tasks.
                // A remote accepted CAS remains ambiguous and is reconciled by
                // the deterministic initial barrier on the next attempt.
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .max_blocking_threads(1)
                    .build()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
                let (identity, provider) = runtime.block_on(async {
                    tokio::time::timeout(
                        deadline.saturating_duration_since(std::time::Instant::now()),
                        super::super::repository_administration::open_repository(
                            services,
                            parameters.repository(),
                            Some(grant.clone()),
                        ),
                    )
                    .await
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                    .map_err(failure)
                })?;
                let publisher = BackupPublisher::new(provider.as_ref(), &identity, &signer)
                    .with_control_resources(&grant, 0)
                    .map_err(failure)?;
                let head = runtime.block_on(async {
                    tokio::time::timeout(
                        deadline.saturating_duration_since(std::time::Instant::now()),
                        publisher.prepare_purge_barrier(&tombstones),
                    )
                    .await
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                    .map_err(failure)
                })?;
                let mut registration = BackupRepositoryRegistration::new(
                    identity,
                    parameters
                        .repository()
                        .locator()
                        .map_err(super::super::provider_migration::operation_failure)?,
                )
                .map_err(failure)?;
                if registration.binding_identity().map_err(failure)?
                    != parameters.registration_identity()
                {
                    return Err(MaintenanceServiceFailure::IdempotencyConflict);
                }
                if let Some(head) = head {
                    registration = registration
                        .with_registry_generation(head)
                        .map_err(failure)?;
                }
                registration.catalog_object().map_err(failure)
            })
            .map_err(|_| MaintenanceServiceFailure::CapacityUnavailable)?;
        worker
            .join()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
    })?;
    // The caller holds the shared Catalog gate across this proof and its atomic
    // registration/acceptance publication, so no exclusion can race admission.
    Ok(registration)
}
fn failure(failure: positron_backup::RepositoryFailure) -> MaintenanceServiceFailure {
    match failure {
        positron_backup::RepositoryFailure::PreconditionFailed
        | positron_backup::RepositoryFailure::ForeignPrefix
        | positron_backup::RepositoryFailure::IdentityMismatch => {
            MaintenanceServiceFailure::PreconditionFailed
        },
        positron_backup::RepositoryFailure::ControlMemoryRequired { .. }
        | positron_backup::RepositoryFailure::LimitExceeded => {
            MaintenanceServiceFailure::CapacityUnavailable
        },
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}
