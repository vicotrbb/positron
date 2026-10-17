//! Live Upgrade admission only selects the installed, independently trusted candidate.
use super::{ServiceHandle, maintenance_api::MaintenanceServiceFailure as Failure};
use positron_governance::{
    DurableOperationAdministration as Administration, DurableOperationKind, OperationId,
};
impl ServiceHandle {
    pub(crate) fn attach_upgrade_configuration(
        &self,
        configuration: std::sync::Arc<crate::RuntimeConfiguration>,
    ) -> Result<(), crate::ServiceFailure> {
        self.upgrade_configuration
            .set(configuration)
            .map_err(|_| crate::ServiceFailure::Internal)
    }
    pub(crate) fn manage_upgrade(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<positron_api::upgrade::UpgradeResponse, Failure> {
        self.manage_upgrade_until(bearer, body, None)
    }
    pub(crate) fn manage_upgrade_until(
        &self,
        bearer: &str,
        body: &[u8],
        deadline: Option<std::time::Instant>,
    ) -> Result<positron_api::upgrade::UpgradeResponse, Failure> {
        let actor = self.authorize_system_administration(bearer)?;
        let input = positron_api::upgrade::UpgradeRequest::decode(body)
            .map_err(|_| Failure::InvalidRequest)?;
        let key = || {
            super::maintenance_api::administrative_key(
                input
                    .idempotency_key
                    .as_deref()
                    .ok_or(Failure::InvalidRequest)?,
            )
        };
        let id = || {
            OperationId::from_bytes(
                super::maintenance_verification::decode_fixed_hex(
                    input
                        .operation_id
                        .as_deref()
                        .ok_or(Failure::InvalidRequest)?,
                )
                .ok_or(Failure::InvalidRequest)?,
            )
            .map_err(super::provider_migration::operation_failure)
        };
        if input.action == "start" {
            crate::upgrade::check_admission_deadline(deadline).map_err(upgrade_failure)?;
            {
                let _gate = self
                    .catalog_operation()
                    .map_err(|_| Failure::AdministrationUnavailable)?;
                let catalog = self.open_maintenance_catalog()?;
                if let Some(operation) = Administration::inspect_by_idempotency(&catalog, key()?)
                    .map_err(super::provider_migration::operation_failure)?
                {
                    let parameters = operation
                        .upgrade_parameters()
                        .ok_or(Failure::IdempotencyConflict)?;
                    let digest = super::maintenance_verification::decode_fixed_hex(
                        input
                            .candidate_manifest
                            .as_deref()
                            .ok_or(Failure::InvalidRequest)?,
                    )
                    .ok_or(Failure::InvalidRequest)?;
                    let repository = positron_domain::identity::TenantId::parse_canonical(
                        input
                            .repository_id
                            .as_deref()
                            .ok_or(Failure::InvalidRequest)?,
                    )
                    .map_err(|_| Failure::InvalidRequest)?
                    .to_bytes();
                    if digest != parameters.target().manifest_digest()
                        || repository != parameters.backup().repository().repository_id()
                        || input.retention_seconds != Some(parameters.backup().retention_seconds())
                    {
                        return Err(Failure::IdempotencyConflict);
                    }
                    let request = positron_governance::DurableOperationRequest::upgrade(
                        actor.principal_id(),
                        key()?,
                        self.instance.instance.to_bytes(),
                        input
                            .expected_catalog_generation
                            .ok_or(Failure::InvalidRequest)?,
                        self.maintenance_status_now()?,
                        parameters.intent_digest(),
                    )
                    .map_err(super::provider_migration::operation_failure)?;
                    let operation = Administration::replay_upgrade(&catalog, actor, request)
                        .map_err(super::provider_migration::operation_failure)?;
                    return Ok(positron_api::upgrade::UpgradeResponse {
                        catalog_generation: catalog
                            .pin()
                            .map_err(|_| Failure::AdministrationUnavailable)?
                            .number(),
                        details: Some(details(operation)?),
                        operation: Some(operation_response(operation)?),
                    });
                }
            }
            let configuration = self
                .upgrade_configuration
                .get()
                .ok_or(Failure::PreconditionFailed)?
                .observed()
                .map_err(|_| Failure::AdministrationUnavailable)?;
            let digest = super::maintenance_verification::decode_fixed_hex(
                input
                    .candidate_manifest
                    .as_deref()
                    .ok_or(Failure::InvalidRequest)?,
            )
            .ok_or(Failure::InvalidRequest)?;
            let repository = positron_domain::identity::TenantId::parse_canonical(
                input
                    .repository_id
                    .as_deref()
                    .ok_or(Failure::InvalidRequest)?,
            )
            .map_err(|_| Failure::InvalidRequest)?
            .to_bytes();
            let request = crate::upgrade::installed_upgrade_request(
                configuration.effective(),
                digest,
                repository,
                input.retention_seconds.ok_or(Failure::InvalidRequest)?,
                key()?,
                input
                    .expected_catalog_generation
                    .ok_or(Failure::InvalidRequest)?,
            )
            .map_err(upgrade_failure)?;
            let operation = crate::process::upgrade::accept_preflight(
                &self.instance,
                self,
                configuration.effective(),
                bearer,
                request,
                deadline,
            )
            .map_err(upgrade_failure)?;
            let catalog = self.open_maintenance_catalog()?;
            return Ok(positron_api::upgrade::UpgradeResponse {
                catalog_generation: catalog
                    .pin()
                    .map_err(|_| Failure::AdministrationUnavailable)?
                    .number(),
                details: Some(details(operation)?),
                operation: Some(operation_response(operation)?),
            });
        }
        let _gate = self
            .catalog_operation()
            .map_err(|_| Failure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let operation = match input.action.as_str() {
            "lookup" => Administration::inspect_by_idempotency(&catalog, key()?)
                .map_err(super::provider_migration::operation_failure)?,
            "status" | "cancel" => Administration::inspect_authorized(&catalog, actor, id()?)
                .map_err(super::provider_migration::operation_failure)?,
            _ => return Err(Failure::InvalidRequest),
        }
        .ok_or(Failure::SourceUnavailable)?;
        if operation.kind() != DurableOperationKind::Upgrade {
            return Err(Failure::SourceUnavailable);
        }
        Administration::inspect_authorized(&catalog, actor, operation.operation_id())
            .map_err(super::provider_migration::operation_failure)?
            .ok_or(Failure::SourceUnavailable)?;
        let operation = if input.action == "cancel" {
            if catalog
                .pin()
                .map_err(|_| Failure::AdministrationUnavailable)?
                .number()
                != input
                    .expected_catalog_generation
                    .ok_or(Failure::InvalidRequest)?
            {
                return Err(Failure::PreconditionFailed);
            }
            // Once offline child work exists its owner must finish/cancel it explicitly.
            if operation.upgrade_stage().is_some_and(|stage| {
                !matches!(
                    stage,
                    positron_governance::UpgradeStage::Preflight
                        | positron_governance::UpgradeStage::Draining
                )
            }) {
                return Err(Failure::PreconditionFailed);
            }
            Administration::cancel_upgrade(
                &catalog,
                actor,
                operation.operation_id(),
                key()?,
                operation.revision(),
                self.maintenance_status_now()?,
            )
            .map_err(super::provider_migration::operation_failure)?
        } else {
            operation
        };
        Ok(positron_api::upgrade::UpgradeResponse {
            catalog_generation: catalog
                .pin()
                .map_err(|_| Failure::AdministrationUnavailable)?
                .number(),
            details: Some(details(operation)?),
            operation: Some(operation_response(operation)?),
        })
    }
}
fn upgrade_failure(failure: crate::UpgradeFailure) -> Failure {
    use crate::UpgradeFailure as U;
    match failure {
        U::StaleGeneration => Failure::PreconditionFailed,
        U::IdempotencyConflict => Failure::IdempotencyConflict,
        U::AuthenticationFailed => Failure::AuthenticationRejected,
        U::InvalidRequest => Failure::InvalidRequest,
        U::CapacityUnavailable => Failure::CapacityUnavailable,
        U::PersistenceUnavailable => Failure::AdministrationUnavailable,
        _ => Failure::PreconditionFailed,
    }
}

fn details(
    operation: positron_governance::DurableOperation,
) -> Result<positron_api::upgrade::UpgradeDetails, Failure> {
    let p = operation
        .upgrade_parameters()
        .ok_or(Failure::AdministrationUnavailable)?;
    let version = |[major, minor, patch]: [u32; 3]| format!("{major}.{minor}.{patch}");
    use super::maintenance_api::hex;
    let repository = hex(p.backup().repository().repository_id());
    let mut repository_id = String::with_capacity(36);
    for (index, ch) in repository.chars().enumerate() {
        if matches!(index, 8 | 12 | 16 | 20) {
            repository_id.push('-');
        }
        repository_id.push(ch);
    }
    Ok(positron_api::upgrade::UpgradeDetails {
        source_version: version(p.source().version()),
        target_version: version(p.target().version()),
        source_manifest: hex(p.source().manifest_digest()),
        target_manifest: hex(p.target().manifest_digest()),
        source_artifact: hex(p.source().artifact_digest()),
        target_artifact: hex(p.target().artifact_digest()),
        configuration: hex(p.configuration_digest()),
        format_epoch: p.format_epoch(),
        repository_id,
        rollback_available: operation.upgrade_rollback_available(),
        snapshot_manifest: operation
            .upgrade_snapshot_evidence()
            .map(|e| hex(e.receipt().manifest())),
    })
}

fn operation_response(
    operation: positron_governance::DurableOperation,
) -> Result<positron_api::upgrade::UpgradeOperation, Failure> {
    use positron_api::upgrade::UpgradePhase as P;
    use positron_governance::{DurableOperationCancellation as C, UpgradeStage as S};
    let phase = match operation
        .upgrade_stage()
        .ok_or(Failure::AdministrationUnavailable)?
    {
        S::Preflight => P::Preflight,
        S::Draining => P::Draining,
        S::Snapshot => P::Snapshot,
        S::Publishing => P::Publishing,
        S::AwaitingRestart => P::AwaitingRestart,
        S::Verifying => P::Verifying,
        S::Succeeded => P::Succeeded,
    };
    let cancellation = match operation.cancellation() {
        C::AllowedBeforeDrain => "allowed_before_publication",
        C::NotAllowedAfterDrain => "unavailable_after_publication",
        C::Cancelled => "cancelled",
        C::Requested => return Err(Failure::AdministrationUnavailable),
    };
    let common = super::provider_migration::operation_response(operation);
    Ok(positron_api::upgrade::UpgradeOperation {
        id: common.id,
        status: common.status,
        phase,
        progress_percent: common.progress_percent,
        retry: common.retry,
        cancellation: cancellation.into(),
        irreversible_boundary: common.irreversible_boundary,
        lookup_expires_at_unix_seconds: common.lookup_expires_at_unix_seconds,
    })
}
