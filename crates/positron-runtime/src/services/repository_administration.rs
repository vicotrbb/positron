//! Authenticated admission; Administration owns parameters and lifecycle.
mod execution;
mod policy_projection;
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
pub(crate) enum RepositoryLocation<'a> {
    Local(&'a Path),
    AwsS3(&'a positron_backup::AwsS3Target),
    GoogleCloudStorage(&'a positron_backup::GoogleCloudStorageTarget),
    AzureBlob(&'a positron_backup::AzureBlobTarget),
}
#[derive(Clone, Copy)]
pub(crate) struct RepositoryAdmission<'a> {
    pub action: RepositoryAction,
    pub locator: RepositoryLocation<'a>,
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
        // Resolve only the selected native locator after authorization.
        let parameters = match input.locator {
            RepositoryLocation::Local(path) => {
                let identity = positron_backup::RepositoryIdentity::local(
                    input.repository,
                    self.instance.instance.to_bytes(),
                    fingerprint,
                    path,
                )
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                RepositoryOperationParameters::local(
                    input.action,
                    path.to_str()
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    input.repository,
                    fingerprint,
                    identity.prefix_commitment(),
                )
            },
            RepositoryLocation::AwsS3(target) => {
                let identity = positron_backup::RepositoryIdentity::aws_s3(
                    input.repository,
                    self.instance.instance.to_bytes(),
                    fingerprint,
                    target,
                )
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                RepositoryOperationParameters::aws_s3(
                    input.action,
                    &target.encode_locator(),
                    input.repository,
                    fingerprint,
                    identity.prefix_commitment(),
                )
            },
            RepositoryLocation::GoogleCloudStorage(target) => {
                let identity = positron_backup::RepositoryIdentity::google_cloud_storage(
                    input.repository,
                    self.instance.instance.to_bytes(),
                    fingerprint,
                    target,
                )
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                RepositoryOperationParameters::google_cloud_storage(
                    input.action,
                    &target.encode_locator(),
                    input.repository,
                    fingerprint,
                    identity.prefix_commitment(),
                )
            },
            RepositoryLocation::AzureBlob(target) => {
                let identity = positron_backup::RepositoryIdentity::azure_blob(
                    input.repository,
                    self.instance.instance.to_bytes(),
                    fingerprint,
                    target,
                )
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                RepositoryOperationParameters::azure_blob(
                    input.action,
                    &target.encode_locator(),
                    input.repository,
                    fingerprint,
                    identity.prefix_commitment(),
                )
            },
        }
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
                    .submit_repository_operation_with_resources_and_persist(
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
                        repository_resources(parameters.provider_kind()),
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

fn repository_resources(
    kind: positron_governance::RepositoryProviderKind,
) -> positron_kernel::ResourceAmounts {
    let mut amounts = [131_072, 1, 1, 0, 1, 0, 1, 1, 1, 4, 16_384];
    if kind != positron_governance::RepositoryProviderKind::LocalFilesystem {
        let native = match kind {
            positron_governance::RepositoryProviderKind::GoogleCloudStorage => {
                positron_backup::GoogleCloudStorageRepository::required_resources()
            },
            positron_governance::RepositoryProviderKind::AzureBlob => {
                positron_backup::AzureBlobRepository::required_resources()
            },
            _ => positron_backup::AwsS3Repository::required_resources(),
        };
        for (amount, dimension) in amounts
            .iter_mut()
            .zip(positron_kernel::ResourceDimension::ALL)
        {
            *amount = (*amount).max(native.get(dimension));
        }
    }
    positron_kernel::ResourceAmounts::new(amounts)
}
