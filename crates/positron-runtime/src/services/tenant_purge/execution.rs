use super::inventory::PurgeWork;
use super::*;
use positron_domain::{lifecycle::TenantLifecycleState, routing::SignalKind};
use positron_governance::{DurableOperationPhase, DurableOperationStatus, Identity};
use positron_kernel::{ActiveSegmentLedger, MaintenanceExecution};

pub(in crate::services) fn recover_accepted_task(
    services: &ServiceHandle,
) -> Result<(), ServiceFailure> {
    let Some(_gate) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogBusy);
    };
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    if let Some(operation) = DurableOperationAdministration::next_tenant_purge(&catalog)
        .map_err(|_| ServiceFailure::CorruptState)?
    {
        let task = positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
            .map_err(|_| ServiceFailure::CorruptState)?;
        match services.instance.maintenance_coordinator().status(task) {
            Ok(_) => {},
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => submit(
                services,
                &catalog,
                operation,
                services
                    .maintenance_status_now()
                    .map_err(|_| ServiceFailure::StorageUnavailable)?,
            )?,
            Err(failure) => return Err(super::super::maintenance::map_failure(failure)),
        }
    }
    Ok(())
}

pub(in crate::services) fn complete(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut PurgeWork,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    match complete_inner(services, execution, work, cancellation) {
        Err(
            ServiceFailure::CapacityUnavailable
            | ServiceFailure::StorageUnavailable
            | ServiceFailure::CatalogBusy,
        ) => Ok(false),
        outcome => outcome,
    }
}
fn complete_inner(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut PurgeWork,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let id = OperationId::from_bytes(binding.operation_id())
        .map_err(|_| ServiceFailure::CorruptState)?;
    let (mut operation, actor, tenant, slug) = {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let now = services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        let operation = DurableOperationAdministration::inspect(&catalog, id)
            .map_err(|_| ServiceFailure::CorruptState)?
            .ok_or(ServiceFailure::CorruptState)?;
        if operation.kind() != DurableOperationKind::TenantPurge
            || operation.request().canonical_digest() != binding.intent_digest()
        {
            return Err(ServiceFailure::CorruptState);
        }
        if operation.status().is_terminal() {
            execution
                .complete_and_persist(services.instance.maintenance_coordinator(), &catalog, false)
                .map_err(super::super::maintenance::map_failure)?;
            return Ok(true);
        }
        let actor = DurableOperationAdministration::resume_tenant_purge_actor(&catalog, id, now)
            .map_err(|_| ServiceFailure::Unauthorized)?;
        let operation = if operation.status() == DurableOperationStatus::Pending {
            DurableOperationAdministration::begin(&catalog, actor, id, now)
                .map_err(|_| ServiceFailure::CatalogUnavailable)?
        } else {
            operation
        };
        let tenant = operation
            .request()
            .applicable_tenant()
            .ok_or(ServiceFailure::CorruptState)?;
        let tenants = TenantAdministration::list(
            &catalog
                .pin()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?,
        )
        .map_err(|_| ServiceFailure::CorruptState)?;
        let slug = tenants
            .iter()
            .find(|value| value.tenant_id() == tenant)
            .ok_or(ServiceFailure::CorruptState)?
            .slug()
            .to_owned();
        (operation, actor, tenant, slug)
    };
    if operation.phase() == DurableOperationPhase::Preflight {
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let (_, generation) = TenantAdministration::lifecycle_state(&snapshot, tenant)
            .map_err(|_| ServiceFailure::CorruptState)?;
        let request = operation.request();
        let current_request = DurableOperationRequest::tenant_purge(
            request.principal(),
            tenant,
            request.idempotency_key(),
            request.accepted_generation(),
            request.accepted_at_unix_seconds(),
            confirmation(tenant, &slug, generation.get()),
        )
        .map_err(|_| ServiceFailure::CorruptState)?;
        if current_request.canonical_digest() != request.canonical_digest() {
            DurableOperationAdministration::reject_tenant_purge(
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
                .map_err(super::super::maintenance::map_failure)?;
            return Ok(true);
        }
        // A capture may still own tenant key bytes. Its ordinary owner must finish before purge starts.
        if catalog
            .has_backup_capture_references()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?
        {
            return Ok(false);
        }
        operation = DurableOperationAdministration::mark_draining(
            &catalog,
            actor,
            id,
            services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?,
        )
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    }
    if operation.phase() == DurableOperationPhase::Draining {
        let _gate = services.catalog_operation()?;
        let generation = {
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            let snapshot = catalog
                .pin()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
            let (state, generation) = TenantAdministration::lifecycle_state(&snapshot, tenant)
                .map_err(|_| ServiceFailure::CorruptState)?;
            if state == TenantLifecycleState::Purging {
                None
            } else {
                Some(generation)
            }
        };
        if let Some(generation) = generation {
            let key = phase_key(id, b"lifecycle")?;
            services
                .instance
                .transition_tenant_lifecycle(
                    actor,
                    tenant,
                    TenantLifecycleState::Purging,
                    generation,
                    key,
                )
                .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        }
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let identity = Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
        // No admitted tenant work survives Purging. Seal active ledgers before removing live manifests.
        for signal in [SignalKind::Logs, SignalKind::Traces] {
            for scope in snapshot
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|_| ServiceFailure::LedgerUnavailable)?
            {
                if snapshot
                    .has_active_ledger_scope(scope)
                    .map_err(|_| ServiceFailure::LedgerUnavailable)?
                {
                    let key =
                        super::super::tenant_segment_key(&services.instance, &identity, scope)?;
                    ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                        &services.instance._authority,
                        &services.instance.retention_time,
                        &catalog,
                        scope,
                        key,
                    )
                    .map_err(|_| ServiceFailure::LedgerUnavailable)?
                    .seal()
                    .map_err(|_| ServiceFailure::LedgerUnavailable)?;
                    return Ok(false);
                }
            }
        }
        services
            .schema_sessions
            .evict(tenant)
            .map_err(|_| ServiceFailure::Internal)?;
        let now = services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?;
        DurableOperationAdministration::publish_tenant_purge_boundary(&catalog, actor, id, now)
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let proof = live_proof(&snapshot, tenant, operation.request().canonical_digest())?;
        let objects = TenantAdministration::live_purge_objects(
            &snapshot,
            tenant,
            proof,
            operation.operation_id().to_bytes(),
            operation.request().accepted_at_unix_seconds(),
        )
        .map_err(|_| ServiceFailure::CorruptState)?;
        let mut retained = Vec::new();
        for object in objects {
            if positron_signals::SchemaCatalog::catalog_tenant(object.canonical_bytes())
                .map_err(|_| ServiceFailure::CorruptState)?
                != Some(tenant)
            {
                retained.push(object);
            }
        }
        let objects = retained;
        operation = DurableOperationAdministration::publish_tenant_purge_progress(
            &catalog, actor, id, objects, now,
        )
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    }
    if !super::inventory::prepare(services, execution, work, operation, actor, tenant)? {
        return Ok(false);
    }
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let repositories =
        match super::repositories::purge(services, operation, tenant, &slug, execution) {
            Ok(Some(proof)) => proof,
            Ok(None) => return Ok(false),
            Err(
                failure @ (ServiceFailure::BackupRepositoryRejected
                | ServiceFailure::StorageUnavailable
                | ServiceFailure::CapacityUnavailable
                | ServiceFailure::CatalogBusy),
            ) => {
                let _ = failure;
                return Ok(false);
            },
            Err(failure) => return Err(failure),
        };
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    if !repositories.still_current(&catalog)? {
        return Ok(false);
    }
    let mut progress = super::checkpoint::current(services, execution, binding)?;
    let proof = match TenantAdministration::reclaim_live_purge_step(
        &catalog,
        tenant,
        live_proof(
            &catalog
                .pin()
                .map_err(|_| ServiceFailure::CatalogUnavailable)?,
            tenant,
            operation.request().canonical_digest(),
        )?,
        (!progress.reclamation.is_empty()).then_some(progress.reclamation.as_slice()),
    ) {
        Ok(positron_kernel::TenantKeyReclamationStep::Pending { cursor }) => {
            progress.reclamation = cursor;
            super::checkpoint::persist(services, &catalog, execution, binding, &progress)?;
            return Ok(false);
        },
        Ok(positron_kernel::TenantKeyReclamationStep::Complete(proof)) => proof,
        Err(positron_governance::TenantAdministrationFailure::PersistenceUnavailable) => {
            return Ok(false);
        },
        Err(_) => return Err(ServiceFailure::CatalogUnavailable),
    };
    DurableOperationAdministration::complete_tenant_purge(
        &catalog,
        actor,
        id,
        &proof,
        services
            .maintenance_status_now()
            .map_err(|_| ServiceFailure::StorageUnavailable)?,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    execution
        .complete_and_persist(services.instance.maintenance_coordinator(), &catalog, false)
        .map_err(super::super::maintenance::map_failure)?;
    Ok(true)
}
fn phase_key(
    id: OperationId,
    phase: &[u8],
) -> Result<AdministrativeIdempotencyKey, ServiceFailure> {
    let mut hash = Sha256::new();
    hash.update(id.to_bytes());
    hash.update(phase);
    let digest = hash.finalize();
    AdministrativeIdempotencyKey::new(
        digest
            .get(..16)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ServiceFailure::CorruptState)?,
    )
    .map_err(|_| ServiceFailure::CorruptState)
}

pub(super) fn catalog_failure(failure: positron_kernel::CatalogFailure) -> ServiceFailure {
    match failure.code() {
        positron_kernel::CatalogFailureCode::LimitExceeded
        | positron_kernel::CatalogFailureCode::ResourceAdmissionRefused => {
            ServiceFailure::CapacityUnavailable
        },
        positron_kernel::CatalogFailureCode::StorageUnavailable => {
            ServiceFailure::StorageUnavailable
        },
        positron_kernel::CatalogFailureCode::ConcurrentWriter => ServiceFailure::CatalogBusy,
        _ => ServiceFailure::CorruptState,
    }
}
