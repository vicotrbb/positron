//! Native dispatch shares the foreground verifier's admitted traversal owner.
use super::{ServiceFailure, ServiceHandle};
use crate::LocalKeyRotationFailure;
use positron_kernel::{
    Catalog, MaintenanceExecution, MaintenanceTerminalFailure, RootRewrapSession,
};

pub(super) fn complete(
    services: &ServiceHandle,
    catalog: &Catalog<'_>,
    execution: &MaintenanceExecution<'_>,
) -> Result<bool, ServiceFailure> {
    let instance = &services.instance;
    let session = RootRewrapSession::admit(&instance._authority)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let tenant = execution
        .task()
        .scope()
        .tenant_id()
        .ok_or(ServiceFailure::CorruptState)?;
    let basis = catalog
        .pin()
        .map_err(|failure| super::classify_catalog_failure_code(failure.code()))?;
    let identity =
        positron_governance::Identity::open(&basis).map_err(|_| ServiceFailure::CorruptState)?;
    let envelope = identity
        .tenant_key_envelope(tenant)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let epoch = instance
        .key
        .tenant_key_epoch(instance.instance, tenant, envelope)
        .map_err(|_| ServiceFailure::KeyEnvelopeMismatch)?;
    drop(session);
    if epoch < 2 {
        return Err(ServiceFailure::CorruptState);
    }
    match instance.complete_tenant_key_verification_execution(catalog, execution, epoch) {
        Ok(_) => Ok(true),
        Err(LocalKeyRotationFailure::Busy) => {
            // A legitimate source mutation invalidates this proof. Record a
            // typed failure; the existing authenticated reset can requeue it.
            execution
                .fail_and_persist(
                    instance.maintenance_coordinator(),
                    catalog,
                    MaintenanceTerminalFailure::StaleGeneration,
                )
                .map_err(super::maintenance::map_failure)?;
            Ok(true)
        },
        Err(failure) => Err(super::tenant_rotation::rotation_failure(failure)),
    }
}
