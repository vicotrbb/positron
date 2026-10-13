//! Admission binds the authenticated requester before the maintenance dispatch.
mod execution;
use super::{
    ServiceHandle,
    maintenance_api::{MaintenanceServiceFailure, hex},
    maintenance_verification::decode_fixed_hex,
};
pub(super) use execution::{complete, recover_accepted_task};
use positron_api::provider_migration::{
    ProviderMigrationIdentity, ProviderMigrationOperation, ProviderMigrationRequest,
    ProviderMigrationResponse,
};
use positron_domain::identity::TenantId;
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperation, DurableOperationAdministration,
    DurableOperationFailure, DurableOperationKind, DurableOperationRequest,
    KeyProviderMigrationAction, KeyProviderMigrationParameters, OperationId,
};
use positron_kernel::{MaintenancePreconditions, RootProviderMigrationBinding};
use std::path::Path;

impl ServiceHandle {
    pub(crate) fn manage_provider_migration(
        &self,
        bearer: &str,
        bytes: &[u8],
    ) -> Result<ProviderMigrationResponse, MaintenanceServiceFailure> {
        let actor = self.authorize_system_administration(bearer)?;
        let input = ProviderMigrationRequest::decode(bytes)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        // Configuration is owned by the configuration loader. Only a protected
        // reference and its complete semantic commitment enter the Catalog.
        let configuration = input
            .configuration_reference
            .as_deref()
            .map(load_configuration)
            .transpose()?;
        let parameters = match input.action.as_str() {
            "prepare" | "activate" | "verify" | "retire" | "cancel" | "resume" => {
                let action = match input.action.as_str() {
                    "prepare" => KeyProviderMigrationAction::Prepare,
                    "activate" => KeyProviderMigrationAction::Activate,
                    "verify" => KeyProviderMigrationAction::Verify,
                    "retire" => KeyProviderMigrationAction::Retire,
                    "cancel" => KeyProviderMigrationAction::Cancel,
                    _ => KeyProviderMigrationAction::Resume,
                };
                let digest = configuration
                    .as_ref()
                    .map(positron_config::EffectiveConfiguration::audit_binding_digest);
                Some(
                    KeyProviderMigrationParameters::new(
                        action,
                        input.configuration_reference.as_deref(),
                        digest,
                    )
                    .map_err(operation_failure)?,
                )
            },
            _ => None,
        };
        let operation = {
            let _gate = self
                .catalog_operation()
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            let catalog = self.open_maintenance_catalog()?;
            if let Some(configuration) = configuration.as_ref()
                && !crate::configuration_catalog::accepts_key_provider_migration_configuration(
                    &catalog
                        .pin()
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
                    configuration,
                )
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            {
                return Err(MaintenanceServiceFailure::InvalidRequest);
            }
            let now = self.maintenance_status_now()?;
            match input.action.as_str() {
                "status" => input
                    .operation_id
                    .as_deref()
                    .map(|id| {
                        let operation = DurableOperationAdministration::inspect_authorized(
                            &catalog,
                            actor,
                            operation_id(id)?,
                        )
                        .map_err(operation_failure)?
                        .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
                        require_root_operation(operation, self.instance.instance.to_bytes())?;
                        Ok(operation)
                    })
                    .transpose()?,
                "lookup" => {
                    let operation = DurableOperationAdministration::inspect_by_idempotency(
                        &catalog,
                        idempotency(input.idempotency_key.as_deref())?,
                    )
                    .map_err(operation_failure)?
                    .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
                    require_root_operation(operation, self.instance.instance.to_bytes())?;
                    Some(
                        DurableOperationAdministration::inspect_authorized(
                            &catalog,
                            actor,
                            operation.operation_id(),
                        )
                        .map_err(operation_failure)?
                        .ok_or(MaintenanceServiceFailure::SourceUnavailable)?,
                    )
                },
                "cancel_operation" => {
                    let id = operation_id(
                        input
                            .operation_id
                            .as_deref()
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                    )?;
                    let operation =
                        DurableOperationAdministration::inspect_authorized(&catalog, actor, id)
                            .map_err(operation_failure)?
                            .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
                    require_root_operation(operation, self.instance.instance.to_bytes())?;
                    Some(
                        DurableOperationAdministration::cancel_key_provider_migration(
                            &catalog,
                            actor,
                            id,
                            idempotency(input.idempotency_key.as_deref())?,
                            input
                                .expected_catalog_generation
                                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                            now,
                        )
                        .map_err(operation_failure)?,
                    )
                },
                _ => {
                    let parameters = parameters.ok_or(MaintenanceServiceFailure::InvalidRequest)?;
                    let request = DurableOperationRequest::key_provider_migration(
                        actor.principal_id(),
                        idempotency(input.idempotency_key.as_deref())?,
                        self.instance.instance.to_bytes(),
                        input
                            .expected_catalog_generation
                            .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
                        now,
                        parameters.intent_digest(),
                    )
                    .map_err(operation_failure)?;
                    let operation = DurableOperationAdministration::accept_key_provider_migration(
                        &catalog, actor, request, parameters,
                    )
                    .map_err(operation_failure)?;
                    if !operation.status().is_terminal() {
                        let binding = RootProviderMigrationBinding::new(
                            operation.operation_id().to_bytes(),
                            parameters.intent_digest(),
                        )
                        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
                        let accepted_generation = operation
                            .request()
                            .accepted_generation()
                            .checked_add(1)
                            .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
                        self.instance
                            .maintenance_coordinator()
                            .submit_root_provider_migration_and_persist(
                                &catalog,
                                binding,
                                MaintenancePreconditions::new(accepted_generation, 1).map_err(
                                    |_| MaintenanceServiceFailure::AdministrationUnavailable,
                                )?,
                                now,
                            )
                            .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
                    }
                    Some(operation)
                },
            }
        };
        self.notify_maintenance_worker();
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let root = self
            .instance
            .key_provider_migration_status_from_catalog(&catalog)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let rotation = root.rotation();
        let generation = catalog
            .pin()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            .number();
        Ok(ProviderMigrationResponse {
            catalog_generation: generation,
            root_phase: match rotation.phase() {
                crate::LocalKeyRotationPhase::Active => "active",
                crate::LocalKeyRotationPhase::Prepared => "prepared",
                crate::LocalKeyRotationPhase::Verifying => "verifying",
                crate::LocalKeyRotationPhase::Retiring => "retiring",
                crate::LocalKeyRotationPhase::Cancelled => "cancelled",
            }
            .into(),
            active_epoch: rotation.active_epoch(),
            active_provider: provider_identity(root.active_provider()),
            source_provider: provider_identity(root.source_provider()),
            target_provider: root.target_provider().map(provider_identity),
            successor_epoch: rotation.successor_epoch(),
            predecessor_epoch: rotation.predecessor_epoch(),
            operation: operation.map(operation_response),
        })
    }
}

pub(super) fn load_configuration(
    reference: &str,
) -> Result<positron_config::EffectiveConfiguration, MaintenanceServiceFailure> {
    let inputs = positron_config::ConfigurationInputs::try_from_sources(
        Some(Path::new(reference)),
        [] as [(&str, &str); 0],
        [] as [(&str, &str); 0],
    )
    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
    positron_config::resolve(inputs).map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}

fn idempotency(
    value: Option<&str>,
) -> Result<AdministrativeIdempotencyKey, MaintenanceServiceFailure> {
    AdministrativeIdempotencyKey::new(
        TenantId::parse_canonical(value.ok_or(MaintenanceServiceFailure::InvalidRequest)?)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
            .to_bytes(),
    )
    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)
}
fn operation_id(value: &str) -> Result<OperationId, MaintenanceServiceFailure> {
    OperationId::from_bytes(
        decode_fixed_hex(value).ok_or(MaintenanceServiceFailure::InvalidRequest)?,
    )
    .map_err(operation_failure)
}
fn require_root_operation(
    operation: DurableOperation,
    instance: [u8; 16],
) -> Result<(), MaintenanceServiceFailure> {
    if operation.kind() != DurableOperationKind::KeyProviderMigration
        || operation.target_identity() != Some(instance)
    {
        return Err(MaintenanceServiceFailure::SourceUnavailable);
    }
    Ok(())
}
pub(super) fn operation_failure(failure: DurableOperationFailure) -> MaintenanceServiceFailure {
    match failure {
        DurableOperationFailure::Unauthorized => MaintenanceServiceFailure::AuthenticationRejected,
        DurableOperationFailure::IdempotencyConflict => {
            MaintenanceServiceFailure::IdempotencyConflict
        },
        DurableOperationFailure::StaleGeneration => MaintenanceServiceFailure::PreconditionFailed,
        DurableOperationFailure::InvalidInput | DurableOperationFailure::InvalidState => {
            MaintenanceServiceFailure::InvalidRequest
        },
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}
fn operation_response(operation: DurableOperation) -> ProviderMigrationOperation {
    use positron_governance::{
        DurableOperationBoundary as B, DurableOperationCancellation as C,
        DurableOperationPhase as P, DurableOperationRetry as R, DurableOperationStatus as S,
    };
    ProviderMigrationOperation {
        id: hex(operation.operation_id().to_bytes()),
        status: match operation.status() {
            S::Pending => "pending",
            S::Running => "running",
            S::Succeeded => "succeeded",
            S::Failed => "failed",
            S::Cancelled => "cancelled",
        }
        .into(),
        phase: match operation.phase() {
            P::Accepted => "accepted",
            P::Preflight => "preflight",
            P::Draining => "draining",
            P::CatalogPublication => "catalog_publication",
            P::Published => "published",
            P::Cancelled => "cancelled",
        }
        .into(),
        progress_percent: u32::from(operation.progress_percent()),
        retry: match operation.retry_guidance() {
            R::InspectByOperationId => "inspect_by_operation_id",
            R::RetryAfterRecoveryCapacity => "retry_after_recovery_capacity",
            R::Never => "never",
        }
        .into(),
        cancellation: match operation.cancellation() {
            C::AllowedBeforeDrain => "allowed_before_drain",
            C::NotAllowedAfterDrain => "not_allowed_after_drain",
            C::Cancelled => "cancelled",
        }
        .into(),
        irreversible_boundary: match operation.irreversible_boundary() {
            B::NotCrossed => "not_crossed",
            B::CatalogGenerationPublished => "catalog_generation_published",
            B::ExportManifestPublished => "export_manifest_published",
        }
        .into(),
        lookup_expires_at_unix_seconds: operation.earliest_lookup_expiry_unix_seconds(),
    }
}

fn provider_identity(
    identity: &positron_kernel::key_provider::ProviderKeyUri,
) -> ProviderMigrationIdentity {
    ProviderMigrationIdentity {
        family: u32::from(identity.family() as u8),
        locator: identity.locator().into(),
        version: identity.version().into(),
    }
}
