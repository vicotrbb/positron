//! A transient admitted scan publishes one complete descriptor before deletion.
use super::execution::catalog_failure;
use super::*;
use positron_kernel::MaintenanceExecution;
#[derive(Default)]
pub(in crate::services) struct PurgeWork {
    inventory: Option<Box<positron_kernel::TenantKeyInventory>>,
}
pub(super) fn prepare(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    work: &mut PurgeWork,
    operation: DurableOperation,
    actor: positron_governance::AuthorizedContext,
    tenant: TenantId,
) -> Result<bool, ServiceFailure> {
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let id = operation.operation_id();
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let mut progress = super::checkpoint::current(services, execution, binding)?;
    if !progress.descriptor {
        let digest = live_proof(
            &catalog
                .pin()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?,
            tenant,
            operation.request().canonical_digest(),
        )?;
        if catalog
            .tenant_key_reclamation_prepared(tenant, digest)
            .map_err(catalog_failure)?
        {
            progress.descriptor = true;
        } else {
            if work.inventory.is_none() {
                work.inventory = Some(Box::new(
                    TenantAdministration::begin_live_purge_inventory(&catalog, tenant, digest)
                        .map_err(|_| ServiceFailure::StorageUnavailable)?,
                ));
            }
            let step = work
                .inventory
                .as_mut()
                .ok_or(ServiceFailure::CorruptState)?
                .step(&catalog, |bytes| {
                    TenantAdministration::is_tenant_key_object(bytes, tenant)
                })
                .map_err(catalog_failure)?;
            match step {
                positron_kernel::TenantKeyInventoryStep::Pending { .. } => return Ok(false),
                positron_kernel::TenantKeyInventoryStep::Complete {
                    objects: descriptors,
                } => {
                    let snapshot = catalog
                        .pin()
                        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    let mut objects = Vec::new();
                    for id in snapshot.object_identities() {
                        objects.push(
                            positron_kernel::CatalogObject::new(
                                snapshot
                                    .object(id)
                                    .map_err(|_| ServiceFailure::CorruptState)?
                                    .ok_or(ServiceFailure::CorruptState)?
                                    .to_vec(),
                            )
                            .map_err(catalog_failure)?,
                        );
                    }
                    for descriptor in descriptors {
                        if !objects
                            .iter()
                            .any(|object| object.identity() == descriptor.identity())
                        {
                            objects.push(descriptor);
                        }
                    }
                    DurableOperationAdministration::publish_tenant_purge_objects(
                        &catalog,
                        actor,
                        id,
                        objects,
                        false,
                        services
                            .maintenance_status_now()
                            .map_err(|_| ServiceFailure::StorageUnavailable)?,
                    )
                    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
                    progress.descriptor = true;
                },
            }
        }
        work.inventory = None;
        super::checkpoint::persist(services, &catalog, execution, binding, &progress)?;
        return Ok(false);
    }
    Ok(true)
}
