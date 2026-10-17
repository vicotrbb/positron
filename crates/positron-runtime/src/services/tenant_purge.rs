//! Administration binds one confirmed tenant before the maintenance owner executes purge.
mod checkpoint;
mod execution;
mod inventory;
mod repositories;
use super::{ServiceFailure, ServiceHandle, maintenance_api::MaintenanceServiceFailure};
pub(super) use execution::{complete, recover_accepted_task};
pub(super) use inventory::PurgeWork;
use positron_domain::identity::{TenantId, TenantSlug};
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperation, DurableOperationAdministration,
    DurableOperationKind, DurableOperationRequest, OperationId, TenantAdministration,
};
use positron_kernel::{MaintenancePreconditions, RepositoryOperationBinding};
use sha2::{Digest, Sha256};

fn live_proof(
    snapshot: &positron_kernel::CatalogSnapshot,
    tenant: TenantId,
    fallback: [u8; 32],
) -> Result<[u8; 32], ServiceFailure> {
    Ok(TenantAdministration::restore_purge_exclusions(snapshot)
        .map_err(|_| ServiceFailure::CorruptState)?
        .into_iter()
        .find(|entry| entry.tenant_id() == tenant)
        .map_or(fallback, |entry| entry.proof_digest()))
}

fn confirmation(tenant: TenantId, slug: &str, generation: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron.tenant-purge.confirmation.v1\0");
    hash.update(tenant.to_bytes());
    hash.update(generation.to_be_bytes());
    hash.update(slug.as_bytes());
    hash.finalize().into()
}
fn require(operation: DurableOperation) -> Result<DurableOperation, MaintenanceServiceFailure> {
    if operation.kind() != DurableOperationKind::TenantPurge {
        return Err(MaintenanceServiceFailure::SourceUnavailable);
    }
    Ok(operation)
}
impl ServiceHandle {
    pub(crate) fn manage_tenant_purge(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<positron_api::tenant_purge::TenantPurgeResponse, MaintenanceServiceFailure> {
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let input = positron_api::tenant_purge::TenantPurgeRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let catalog = self.open_maintenance_catalog()?;
        let now = self.maintenance_status_now()?;
        let key = || {
            let text = input
                .idempotency_key
                .as_deref()
                .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
            super::maintenance_api::administrative_key(text)
        };
        let id = || {
            OperationId::from_bytes(
                super::maintenance_verification::decode_fixed_hex(
                    input
                        .operation_id
                        .as_deref()
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                )
                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
            )
            .map_err(super::provider_migration::operation_failure)
        };
        let operation = match input.action.as_str() {
            "lookup" => {
                let operation = require(
                    DurableOperationAdministration::inspect_by_idempotency(&catalog, key()?)
                        .map_err(super::provider_migration::operation_failure)?
                        .ok_or(MaintenanceServiceFailure::SourceUnavailable)?,
                )?;
                DurableOperationAdministration::inspect_authorized(
                    &catalog,
                    actor,
                    operation.operation_id(),
                )
                .map_err(super::provider_migration::operation_failure)?
            },
            "status" => Some(require(
                DurableOperationAdministration::inspect_authorized(&catalog, actor, id()?)
                    .map_err(super::provider_migration::operation_failure)?
                    .ok_or(MaintenanceServiceFailure::SourceUnavailable)?,
            )?),
            "cancel" => {
                let id = id()?;
                require(
                    DurableOperationAdministration::inspect_authorized(&catalog, actor, id)
                        .map_err(super::provider_migration::operation_failure)?
                        .ok_or(MaintenanceServiceFailure::SourceUnavailable)?,
                )?;
                if catalog
                    .pin()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                    .number()
                    != input
                        .expected_catalog_generation
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?
                {
                    return Err(MaintenanceServiceFailure::PreconditionFailed);
                }
                Some(
                    DurableOperationAdministration::cancel(&catalog, actor, id, key()?, now)
                        .map_err(|failure| match failure {
                            positron_governance::DurableOperationFailure::CancellationUnavailable => MaintenanceServiceFailure::PreconditionFailed,
                            failure => super::provider_migration::operation_failure(failure),
                        })?,
                )
            },
            "start" => {
                let tenant = TenantId::parse_canonical(
                    input
                        .tenant_id
                        .as_deref()
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                )
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                let slug = TenantSlug::parse_canonical(
                    input
                        .confirmation_slug
                        .as_deref()
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                )
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
                let expected = input
                    .expected_lifecycle_generation
                    .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
                let request = DurableOperationRequest::tenant_purge(
                    actor.principal_id(),
                    tenant,
                    key()?,
                    input
                        .expected_catalog_generation
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    now,
                    confirmation(tenant, slug.as_str(), expected),
                )
                .map_err(super::provider_migration::operation_failure)?;
                if DurableOperationAdministration::inspect_by_idempotency(&catalog, key()?)
                    .map_err(super::provider_migration::operation_failure)?
                    .is_none()
                {
                    let snapshot = catalog
                        .pin()
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    let tenants = TenantAdministration::list(&snapshot)
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                    let current = tenants
                        .iter()
                        .find(|current| current.tenant_id() == tenant)
                        .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
                    if current.slug() != slug.as_str()
                        || TenantAdministration::lifecycle_state(&snapshot, tenant)
                            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                            .1
                            .get()
                            != expected
                        || current.lifecycle()
                            == positron_domain::lifecycle::TenantLifecycleState::Purged
                    {
                        return Err(MaintenanceServiceFailure::PreconditionFailed);
                    }
                    if DurableOperationAdministration::next_tenant_purge(&catalog)
                        .map_err(super::provider_migration::operation_failure)?
                        .is_some()
                    {
                        return Err(MaintenanceServiceFailure::PreconditionFailed);
                    }
                }
                let operation =
                    DurableOperationAdministration::accept_tenant_purge(&catalog, actor, request)
                        .map_err(super::provider_migration::operation_failure)?;
                if !operation.status().is_terminal() {
                    submit(self, &catalog, operation, now)
                        .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
                }
                Some(operation)
            },
            _ => return Err(MaintenanceServiceFailure::InvalidRequest),
        };
        self.notify_maintenance_worker();
        Ok(positron_api::tenant_purge::TenantPurgeResponse {
            catalog_generation: catalog
                .pin()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                .number(),
            operation: operation.map(super::provider_migration::operation_response),
            managed_scope: positron_api::tenant_purge::MANAGED_SCOPE.into(),
        })
    }
}
fn submit(
    services: &ServiceHandle,
    catalog: &positron_kernel::Catalog<'_>,
    operation: DurableOperation,
    now: u64,
) -> Result<(), ServiceFailure> {
    services
        .instance
        .maintenance_coordinator()
        .submit_tenant_purge_and_persist(
            catalog,
            RepositoryOperationBinding::new(
                operation.operation_id().to_bytes(),
                operation.request().canonical_digest(),
            )
            .map_err(|_| ServiceFailure::CorruptState)?,
            MaintenancePreconditions::new(
                operation
                    .request()
                    .accepted_generation()
                    .checked_add(1)
                    .ok_or(ServiceFailure::CorruptState)?,
                1,
            )
            .map_err(|_| ServiceFailure::CorruptState)?,
            operation
                .request()
                .applicable_tenant()
                .ok_or(ServiceFailure::CorruptState)?,
            now,
        )
        .map_err(super::maintenance::map_failure)?;
    Ok(())
}
