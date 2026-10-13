//! Authenticated admission; Administration owns parameters and lifecycle.
mod execution;
mod wire;
use super::{ServiceHandle, maintenance_api::MaintenanceServiceFailure};
pub(super) use execution::{complete, recover_accepted_task};
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperation, DurableOperationAdministration,
    DurableOperationKind, DurableOperationRequest, OperationId, RepositoryAction,
    RepositoryOperationParameters,
};
use positron_kernel::{MaintenancePreconditions, RepositoryOperationBinding};
use std::path::Path;
#[derive(Clone, Copy)]
pub(crate) struct RepositoryAdmission<'a> {
    pub action: RepositoryAction,
    pub locator: &'a Path,
    pub repository: [u8; 16],
    pub expected_generation: u64,
    pub idempotency: AdministrativeIdempotencyKey,
}
impl ServiceHandle {
    pub(crate) fn accept_repository_operation(
        &self,
        bearer: &str,
        input: RepositoryAdmission<'_>,
    ) -> Result<DurableOperation, MaintenanceServiceFailure> {
        let actor = self.authorize_system_administration(bearer)?;
        let fingerprint = {
            let _gate = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = self.open_maintenance_catalog()?;
            catalog
                .pin()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                .governance_object()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                .1
                .integrity_key_fingerprint()
        };
        // Native path resolution follows authorization and precedes admission.
        // Provider work never runs while owning the primary Catalog writer gate.
        let identity = positron_backup::RepositoryIdentity::local(
            input.repository,
            self.instance.instance.to_bytes(),
            fingerprint,
            input.locator,
        )
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let locator = input
            .locator
            .to_str()
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let parameters = RepositoryOperationParameters::local(
            input.action,
            locator,
            input.repository,
            fingerprint,
            identity.prefix_commitment(),
        )
        .map_err(super::provider_migration::operation_failure)?;
        let operation = {
            let _gate = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = self.open_maintenance_catalog()?;
            let now = self.maintenance_status_now()?;
            let request = DurableOperationRequest::repository(
                actor.principal_id(),
                input.idempotency,
                self.instance.instance.to_bytes(),
                input.expected_generation,
                now,
                parameters.intent_digest(),
            )
            .map_err(super::provider_migration::operation_failure)?;
            let operation = DurableOperationAdministration::accept_repository(
                &catalog, actor, request, parameters,
            )
            .map_err(super::provider_migration::operation_failure)?;
            if !operation.status().is_terminal() {
                let binding = RepositoryOperationBinding::new(
                    operation.operation_id().to_bytes(),
                    parameters.intent_digest(),
                )
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                self.instance
                    .maintenance_coordinator()
                    .submit_repository_operation_and_persist(
                        &catalog,
                        binding,
                        MaintenancePreconditions::new(
                            operation
                                .request()
                                .accepted_generation()
                                .checked_add(1)
                                .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?,
                            1,
                        )
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
                        now,
                    )
                    .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
            }
            operation
        };
        self.notify_maintenance_worker();
        Ok(operation)
    }
    pub(crate) fn repository_operation_by_idempotency(
        &self,
        bearer: &str,
        key: AdministrativeIdempotencyKey,
    ) -> Result<DurableOperation, MaintenanceServiceFailure> {
        let actor = self.authorize_system_administration(bearer)?;
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let operation = DurableOperationAdministration::inspect_by_idempotency(&catalog, key)
            .map_err(super::provider_migration::operation_failure)?
            .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
        require_operation(operation, self.instance.instance.to_bytes())
            .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?;
        DurableOperationAdministration::inspect_authorized(
            &catalog,
            actor,
            operation.operation_id(),
        )
        .map_err(super::provider_migration::operation_failure)?
        .ok_or(MaintenanceServiceFailure::SourceUnavailable)
    }
    pub(crate) fn repository_operation_status(
        &self,
        bearer: &str,
        id: OperationId,
    ) -> Result<DurableOperation, MaintenanceServiceFailure> {
        let actor = self.authorize_system_administration(bearer)?;
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let operation = DurableOperationAdministration::inspect_authorized(&catalog, actor, id)
            .map_err(super::provider_migration::operation_failure)?
            .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
        require_operation(operation, self.instance.instance.to_bytes())
            .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?;
        Ok(operation)
    }
}
fn require_operation(
    operation: DurableOperation,
    instance: [u8; 16],
) -> Result<(), crate::ServiceFailure> {
    if operation.kind() != DurableOperationKind::RepositoryInspection
        || operation.target_identity() != Some(instance)
    {
        return Err(crate::ServiceFailure::CorruptState);
    }
    Ok(())
}
