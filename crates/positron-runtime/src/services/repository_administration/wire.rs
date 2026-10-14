//! Canonical HTTP projection. Native locator values never enter responses.
use super::*;
use positron_api::repository::{
    RepositoryDoctorResult, RepositoryIdentity, RepositoryRequest, RepositoryResponse,
};
use positron_domain::identity::TenantId;
use positron_governance::DurableOperationStatus;
impl ServiceHandle {
    pub(crate) fn manage_repository(
        &self,
        bearer: &str,
        bytes: &[u8],
    ) -> Result<RepositoryResponse, MaintenanceServiceFailure> {
        let actor = self.authorize_system_administration(bearer)?;
        let request = RepositoryRequest::decode(bytes)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let operation = match request.action.as_str() {
            "status" => request
                .operation_id
                .as_deref()
                .map(|id| self.repository_operation_status(bearer, operation_id(id)?))
                .transpose()?,
            "lookup" => Some(self.repository_operation_by_idempotency(
                bearer,
                idempotency(request.idempotency_key.as_deref())?,
            )?),
            "cancel" => {
                let id = operation_id(
                    request
                        .operation_id
                        .as_deref()
                        .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                )?;
                let _gate = self
                    .catalog_operation()
                    .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                let catalog = self.open_maintenance_catalog()?;
                let operation =
                    DurableOperationAdministration::inspect_authorized(&catalog, actor, id)
                        .map_err(super::super::provider_migration::operation_failure)?
                        .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
                require_operation(operation, self.instance.instance.to_bytes())
                    .map_err(|_| MaintenanceServiceFailure::SourceUnavailable)?;
                Some(
                    DurableOperationAdministration::cancel_repository(
                        &catalog,
                        actor,
                        id,
                        idempotency(request.idempotency_key.as_deref())?,
                        request
                            .expected_catalog_generation
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                        self.maintenance_status_now()?,
                    )
                    .map_err(super::super::provider_migration::operation_failure)?,
                )
            },
            "init" | "verify" | "doctor" => Some(
                self.accept_repository_operation(
                    bearer,
                    RepositoryAdmission {
                        action: match request.action.as_str() {
                            "init" => RepositoryAction::Initialize,
                            "verify" => RepositoryAction::Verify,
                            _ => RepositoryAction::Doctor,
                        },
                        locator: Path::new(
                            request
                                .locator
                                .as_deref()
                                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                        ),
                        repository: TenantId::parse_canonical(
                            request
                                .repository_id
                                .as_deref()
                                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                        )
                        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
                        .to_bytes(),
                        expected_generation: request
                            .expected_catalog_generation
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                        idempotency: idempotency(request.idempotency_key.as_deref())?,
                    },
                )?,
            ),
            _ => return Err(MaintenanceServiceFailure::InvalidRequest),
        };
        self.notify_maintenance_worker();
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let generation = catalog
            .pin()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            .number();
        let parameters = operation
            .filter(|operation| operation.status() == DurableOperationStatus::Succeeded)
            .and_then(DurableOperation::repository_parameters);
        let identity = parameters
            .map(|parameters| {
                Ok(RepositoryIdentity {
                    repository_id: TenantId::from_bytes(parameters.repository_id())
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                        .to_string(),
                    instance_id: TenantId::from_bytes(self.instance.instance.to_bytes())
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
                        .to_string(),
                    provider_kind: "local_filesystem".into(),
                    format_epoch: 1,
                    integrity_fingerprint: super::super::maintenance_api::hex(
                        parameters.integrity_fingerprint(),
                    ),
                    prefix_commitment: super::super::maintenance_api::hex(
                        parameters.prefix_commitment(),
                    ),
                })
            })
            .transpose()?;
        Ok(RepositoryResponse {
            catalog_generation: generation,
            operation: operation.map(super::super::provider_migration::operation_response),
            identity,
            doctor: parameters
                .filter(|parameters| parameters.action() == RepositoryAction::Doctor)
                .map(|_| RepositoryDoctorResult {
                    verified: true,
                    probes_deleted: true,
                    external_retention: "not_observable".into(),
                }),
        })
    }
}
fn operation_id(text: &str) -> Result<OperationId, MaintenanceServiceFailure> {
    OperationId::from_bytes(
        super::super::maintenance_verification::decode_fixed_hex(text)
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
    )
    .map_err(super::super::provider_migration::operation_failure)
}
fn idempotency(
    text: Option<&str>,
) -> Result<AdministrativeIdempotencyKey, MaintenanceServiceFailure> {
    AdministrativeIdempotencyKey::new(
        TenantId::parse_canonical(text.ok_or(MaintenanceServiceFailure::InvalidRequest)?)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
            .to_bytes(),
    )
    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}
