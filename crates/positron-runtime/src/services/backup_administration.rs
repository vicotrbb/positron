//! Runtime composes authenticated Backup commands with existing durable owners.
mod execution;
mod purge_barrier;
pub(in crate::services) mod registered;
mod verification;
#[cfg(feature = "test-support")]
pub(super) use verification::{
    report_readmission as report_verification_readmission, report_turn as report_verification_turn,
};
mod wire;
use super::{ServiceFailure, ServiceHandle, maintenance_api::MaintenanceServiceFailure};
pub(super) use execution::{BackupWork, complete, recover_accepted_task, reject_repository};
use positron_governance::{
    AdministrativeIdempotencyKey, BackupRetentionParameters, BackupSnapshotParameters,
    BackupVerificationParameters, DurableOperation, DurableOperationAdministration,
    DurableOperationKind, DurableOperationRequest, OperationId, RepositoryAction,
    RepositoryOperationParameters, RepositoryProviderKind,
};
use positron_kernel::{MaintenancePreconditions, RepositoryOperationBinding};
fn require_operation(
    operation: DurableOperation,
    instance: [u8; 16],
) -> Result<(), ServiceFailure> {
    if !matches!(
        operation.kind(),
        DurableOperationKind::BackupSnapshot
            | DurableOperationKind::BackupRetention
            | DurableOperationKind::BackupVerification
    ) || operation.target_identity() != Some(instance)
    {
        return Err(ServiceFailure::CorruptState);
    }
    Ok(())
}
fn identity(
    parameters: RepositoryOperationParameters,
    instance: [u8; 16],
) -> Result<positron_backup::RepositoryIdentity, positron_backup::RepositoryFailure> {
    use positron_backup::*;
    let locator = parameters
        .locator()
        .map_err(|_| RepositoryFailure::CorruptState)?;
    let identity = match parameters.provider_kind() {
        RepositoryProviderKind::LocalFilesystem => RepositoryIdentity::local(
            parameters.repository_id(),
            instance,
            parameters.integrity_fingerprint(),
            std::path::Path::new(locator),
        )?,
        RepositoryProviderKind::AwsS3 => RepositoryIdentity::aws_s3(
            parameters.repository_id(),
            instance,
            parameters.integrity_fingerprint(),
            &AwsS3Target::decode_locator(locator)?,
        )?,
        RepositoryProviderKind::GoogleCloudStorage => RepositoryIdentity::google_cloud_storage(
            parameters.repository_id(),
            instance,
            parameters.integrity_fingerprint(),
            &GoogleCloudStorageTarget::decode_locator(locator)?,
        )?,
        RepositoryProviderKind::AzureBlob => RepositoryIdentity::azure_blob(
            parameters.repository_id(),
            instance,
            parameters.integrity_fingerprint(),
            &AzureBlobTarget::decode_locator(locator)?,
        )?,
    };
    if identity.prefix_commitment() != parameters.prefix_commitment() {
        return Err(RepositoryFailure::IdentityMismatch);
    }
    Ok(identity)
}
impl ServiceHandle {
    pub(in crate::services) fn accept_backup(
        &self,
        actor: positron_governance::AuthorizedContext,
        parameters: RepositoryOperationParameters,
        retention: u64,
        expected: u64,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<DurableOperation, MaintenanceServiceFailure> {
        let repository_identity = identity(parameters, self.instance.instance.to_bytes())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let registration = positron_backup::BackupRepositoryRegistration::new(
            repository_identity,
            parameters
                .locator()
                .map_err(super::provider_migration::operation_failure)?,
        )
        .and_then(|registration| registration.catalog_object())
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let parameters = BackupSnapshotParameters::new(
            parameters,
            retention,
            registration.identity().to_bytes(),
        )
        .map_err(super::provider_migration::operation_failure)?;
        let new_operation = {
            let _gate = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = self.open_maintenance_catalog()?;
            DurableOperationAdministration::inspect_by_idempotency(&catalog, idempotency)
                .map_err(super::provider_migration::operation_failure)?
                .is_none()
        };
        if new_operation
            && readiness(self).map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                != crate::RecoveryReadiness::Verified
        {
            return Err(MaintenanceServiceFailure::PreconditionFailed);
        }
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let now = self.maintenance_status_now()?;
        let request = DurableOperationRequest::backup_snapshot(
            actor.principal_id(),
            idempotency,
            self.instance.instance.to_bytes(),
            expected,
            now,
            parameters.intent_digest(),
        )
        .map_err(super::provider_migration::operation_failure)?;
        let snapshot = catalog
            .pin()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let registered = positron_backup::BackupRepositoryRegistration::find(
            &snapshot,
            self.instance.instance.to_bytes(),
            parameters.repository().repository_id(),
        )
        .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?;
        let operation = match registered {
            Some((address, registered)) => {
                if registered
                    .binding_identity()
                    .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?
                    != parameters.registration_identity()
                    || registered.identity()
                        != &identity(parameters.repository(), self.instance.instance.to_bytes())
                            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
                {
                    return Err(MaintenanceServiceFailure::IdempotencyConflict);
                }
                DurableOperationAdministration::accept_backup_registered(
                    &catalog, actor, request, parameters, address,
                )
            },
            None => {
                let registration =
                    purge_barrier::prepare(self, &catalog, parameters, registration)?;
                DurableOperationAdministration::accept_backup(
                    &catalog,
                    actor,
                    request,
                    parameters,
                    parameters.registration_identity(),
                    registration,
                )
            },
        }
        .map_err(super::provider_migration::operation_failure)?;
        if !operation.status().is_terminal() {
            submit(&self.instance, &catalog, operation, now)
                .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
        }
        Ok(operation)
    }
}
impl ServiceHandle {
    pub(in crate::services) fn accept_backup_snapshot_action(
        &self,
        verification: bool,
        actor: positron_governance::AuthorizedContext,
        repository: [u8; 16],
        (snapshot, manifest): ([u8; 16], [u8; 32]),
        expected: u64,
        key: AdministrativeIdempotencyKey,
    ) -> Result<DurableOperation, MaintenanceServiceFailure> {
        let (address, registration, parameters, _) = registered::registered(self, repository)?;
        if verification {
            let parameters = BackupVerificationParameters::new(
                parameters,
                registration
                    .binding_identity()
                    .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?,
                snapshot,
                manifest,
            )
            .map_err(super::provider_migration::operation_failure)?;
            let _gate = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = self.open_maintenance_catalog()?;
            let now = self.maintenance_status_now()?;
            let request = DurableOperationRequest::backup_verification(
                actor.principal_id(),
                key,
                self.instance.instance.to_bytes(),
                expected,
                now,
                parameters.intent_digest(),
            )
            .map_err(super::provider_migration::operation_failure)?;
            let operation = DurableOperationAdministration::accept_backup_verification_registered(
                &catalog, actor, request, parameters, address,
            )
            .map_err(super::provider_migration::operation_failure)?;
            if !operation.status().is_terminal() {
                submit(&self.instance, &catalog, operation, now)
                    .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
            }
            return Ok(operation);
        }
        let parameters = BackupRetentionParameters::new(
            parameters,
            registration
                .binding_identity()
                .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?,
            snapshot,
            manifest,
        )
        .map_err(super::provider_migration::operation_failure)?;
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let now = self.maintenance_status_now()?;
        let request = DurableOperationRequest::backup_retention(
            actor.principal_id(),
            key,
            self.instance.instance.to_bytes(),
            expected,
            now,
            parameters.intent_digest(),
        )
        .map_err(super::provider_migration::operation_failure)?;
        let operation = DurableOperationAdministration::accept_backup_retention_registered(
            &catalog, actor, request, parameters, address,
        )
        .map_err(super::provider_migration::operation_failure)?;
        if !operation.status().is_terminal() {
            submit(&self.instance, &catalog, operation, now)
                .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
        }
        Ok(operation)
    }
}
fn submit(
    instance: &crate::InitializedInstance,
    catalog: &positron_kernel::Catalog<'_>,
    operation: DurableOperation,
    now: u64,
) -> Result<(), ServiceFailure> {
    let parameters = operation
        .backup_binding()
        .ok_or(ServiceFailure::CorruptState)?;
    let binding = RepositoryOperationBinding::new(
        operation.operation_id().to_bytes(),
        parameters.intent_digest(),
    )
    .map_err(|_| ServiceFailure::CorruptState)?;
    if matches!(
        operation.kind(),
        DurableOperationKind::BackupRetention | DurableOperationKind::BackupVerification
    ) {
        let native = super::repository_administration::repository_resources(
            parameters.repository().provider_kind(),
        );
        let memory = native
            .get(positron_kernel::ResourceDimension::MemoryBytes)
            .checked_add(positron_backup::BackupPublisher::control_read_memory_bytes())
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        let resources = positron_kernel::ResourceAmounts::new(
            positron_kernel::ResourceDimension::ALL.map(|dimension| match dimension {
                positron_kernel::ResourceDimension::MemoryBytes => memory,
                positron_kernel::ResourceDimension::FileDescriptors => native.get(dimension).max(8),
                _ => native.get(dimension),
            }),
        );
        let submit = if operation.kind() == DurableOperationKind::BackupVerification {
            positron_kernel::MaintenanceCoordinator::submit_backup_operation_with_resources_and_persist
        } else {
            positron_kernel::MaintenanceCoordinator::submit_backup_retention_operation_with_resources_and_persist
        };
        submit(
            instance.maintenance_coordinator(),
            catalog,
            binding,
            MaintenancePreconditions::new(
                operation
                    .request()
                    .accepted_generation()
                    .checked_add(1)
                    .ok_or(ServiceFailure::CorruptState)?,
                1,
            )
            .map_err(|_| ServiceFailure::CorruptState)?,
            resources,
            now,
        )
        .map_err(super::maintenance::map_failure)?;
        return Ok(());
    }
    let snapshot = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let tenants = positron_governance::TenantAdministration::restore_key_tenant_ids(&snapshot)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let context_bytes = tenants.iter().try_fold(136usize, |sum, tenant| {
        sum.checked_add(
            identity
                .tenant_key_envelope(*tenant)
                .map_err(|_| ServiceFailure::CorruptState)?
                .len()
                + 72,
        )
        .ok_or(ServiceFailure::CapacityUnavailable)
    })?;
    let estimate = catalog
        .backup_capture_resource_estimate(context_bytes)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let native = super::repository_administration::repository_resources(
        parameters.repository().provider_kind(),
    );
    // Capture copying and Repository control do not overlap. Both retain the
    // bounded capture metadata/context; provider ownership overlaps either phase.
    let control = estimate
        .retained_memory_bytes()
        .checked_add(positron_backup::BackupPublisher::control_read_memory_bytes())
        .and_then(|bytes| bytes.checked_add(execution::checkpoint::MAX_OWNER_FIELD as u64))
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    let estimate_resources = estimate.resources();
    let memory = native
        .get(positron_kernel::ResourceDimension::MemoryBytes)
        .checked_add(
            estimate_resources
                .get(positron_kernel::ResourceDimension::MemoryBytes)
                .max(control),
        )
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    let resources = positron_kernel::ResourceAmounts::new(
        positron_kernel::ResourceDimension::ALL.map(|dimension| match dimension {
            positron_kernel::ResourceDimension::MemoryBytes => memory,
            _ => estimate_resources.get(dimension).max(native.get(dimension)),
        }),
    );
    instance
        .maintenance_coordinator()
        .submit_backup_operation_with_resources_and_persist(
            catalog,
            binding,
            MaintenancePreconditions::new(
                operation
                    .request()
                    .accepted_generation()
                    .checked_add(1)
                    .ok_or(ServiceFailure::CorruptState)?,
                1,
            )
            .map_err(|_| ServiceFailure::CorruptState)?,
            resources,
            now,
        )
        .map_err(super::maintenance::map_failure)?;
    Ok(())
}

pub(crate) fn readiness(
    services: &ServiceHandle,
) -> Result<crate::RecoveryReadiness, ServiceFailure> {
    // Recovery opens its own Catalog. Hold only the existing Runtime gate,
    // never a second Catalog Writer, across strict owner revalidation.
    let _gate = services.catalog_operation()?;
    readiness_under_gate(services, &_gate)
}

pub(crate) fn readiness_under_gate(
    services: &ServiceHandle,
    _gate: &std::sync::MutexGuard<'_, ()>,
) -> Result<crate::RecoveryReadiness, ServiceFailure> {
    services
        .instance
        .checked_backup_key_recovery_readiness()
        .map_err(|failure| match failure {
            positron_kernel::RecoveryFailure::Admission
            | positron_kernel::RecoveryFailure::LimitExceeded => {
                ServiceFailure::CapacityUnavailable
            },
            positron_kernel::RecoveryFailure::Storage
            | positron_kernel::RecoveryFailure::Custody
            | positron_kernel::RecoveryFailure::Missing => ServiceFailure::StorageUnavailable,
            _ => ServiceFailure::CorruptState,
        })
}

#[cfg(test)]
pub(in crate::services) use execution::test_stops::{StopPoint, hit as hit_stop, stop_after};
