//! The online barrier rolls active files and retains owned immutable sources.
use super::*;
use positron_backup::{BackupCaptureContext, BackupKeyEnvelope, BackupRetention};
use positron_kernel::{
    BackupCapture, BackupCaptureCustody, BackupCapturePreparation, MaintenanceExecution,
};
pub(super) fn prepare(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    operation: DurableOperation,
    repository: &positron_backup::RepositoryIdentity,
) -> Result<
    (
        BackupCaptureContext,
        Option<BackupCapture>,
        Option<BackupCapturePreparation>,
    ),
    ServiceFailure,
> {
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let parameters = operation
        .backup_parameters()
        .ok_or(ServiceFailure::CorruptState)?;
    if let Some(capture) = catalog
        .resume_backup_capture(
            operation.operation_id().to_bytes(),
            parameters.intent_digest(),
        )
        .map_err(|_| ServiceFailure::CorruptState)?
    {
        let bytes = catalog
            .backup_capture_registry_checkpoint(&capture)
            .map_err(|_| ServiceFailure::CorruptState)?;
        let context = BackupCaptureContext::decode(&bytes, repository)
            .map_err(|_| ServiceFailure::CorruptState)?;
        return Ok((context, Some(capture), None));
    }
    let instance = &services.instance;
    let basis = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let identity =
        positron_governance::Identity::open(&basis).map_err(|_| ServiceFailure::CorruptState)?;
    let tenants = positron_governance::TenantAdministration::restore_key_tenant_ids(&basis)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let mut keys = Vec::new();
    let mut stable = Vec::new();
    let mut scopes = Vec::new();
    keys.try_reserve_exact(tenants.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    stable
        .try_reserve_exact(tenants.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for tenant in tenants {
        let envelope = identity
            .tenant_key_envelope(tenant)
            .map_err(|_| ServiceFailure::KeyUnavailable)?;
        let (epoch, fingerprint) = instance
            .key
            .backup_tenant_key_identity(instance.instance, tenant, envelope)
            .map_err(|_| ServiceFailure::KeyEnvelopeMismatch)?;
        keys.push(
            BackupKeyEnvelope::new(tenant.to_bytes(), epoch, fingerprint, envelope.to_vec())
                .map_err(|_| ServiceFailure::CorruptState)?,
        );
        stable.push((tenant, epoch, fingerprint));
        for signal in [
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::SignalKind::Traces,
        ] {
            let found = basis
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|_| ServiceFailure::CorruptState)?;
            if scopes
                .len()
                .checked_add(found.len())
                .is_none_or(|count| count > 4096)
            {
                return Err(ServiceFailure::CapacityUnavailable);
            }
            scopes.extend(found);
        }
    }
    drop(basis);
    let mut segment_keys = Vec::new();
    segment_keys
        .try_reserve_exact(scopes.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for scope in scopes {
        // Maintenance reopening preserves the existing writer/frontier authority.
        // Sealing changes only physical immutability and its Catalog publication.
        if catalog
            .pin()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?
            .has_active_ledger_scope(scope)
            .map_err(|_| ServiceFailure::CorruptState)?
        {
            positron_kernel::ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                &instance._authority,
                &instance.retention_time,
                &catalog,
                scope,
                super::super::super::tenant_segment_key(instance, &identity, scope)?,
            )
            .map_err(|_| ServiceFailure::CorruptState)?
            .seal()
            .map_err(|_| ServiceFailure::CorruptState)?;
        }
        segment_keys.push((
            scope,
            super::super::super::tenant_segment_key(instance, &identity, scope)?,
        ));
    }
    let basis = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let now = services
        .maintenance_status_now()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let context = BackupCaptureContext::new(
        repository.clone(),
        BackupRetention::new(
            now,
            now.checked_add(parameters.retention_seconds())
                .ok_or(ServiceFailure::CorruptState)?,
        )
        .map_err(|_| ServiceFailure::CorruptState)?,
        keys,
    )
    .map_err(|_| ServiceFailure::CorruptState)?;
    let sanitized =
        positron_governance::TenantAdministration::backup_catalog_objects(&basis, &stable)
            .map_err(|_| ServiceFailure::CorruptState)?;
    let checkpoint = context
        .encode()
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let custody = BackupCaptureCustody::new(
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
        segment_keys,
    )
    .and_then(|custody| custody.with_registry_checkpoint(checkpoint))
    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let preparation = catalog
        .prepare_backup_capture(
            execution,
            operation.operation_id().to_bytes(),
            parameters.intent_digest(),
            &basis,
            &sanitized,
            custody,
        )
        .map_err(|failure| super::super::super::classify_catalog_failure_code(failure.code()))?;
    Ok((context, None, Some(preparation)))
}
