//! Bounded qualification and intent publication share the existing Catalog gate.
use super::*;

pub(crate) fn accept_preflight(
    instance: &crate::InitializedInstance,
    services: &crate::ServiceHandle,
    configuration: &EffectiveConfiguration,
    actor: AuthorizedContext,
    request: UpgradeRequest,
) -> Result<DurableOperation, UpgradeFailure> {
    // Serialize the bounded physical qualification and intent publication with
    // existing Catalog writers. The caller's generation is never refreshed.
    let _gate = services
        .catalog_operation()
        .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
    if configuration.installed_release().is_some() {
        let verification = crate::upgrade::installed_upgrade_startup(configuration)?
            .ok_or(UpgradeFailure::UnsafeState)?;
        verification
            .query_context(instance)
            .map_err(|failure| match failure {
                UpgradeFailure::AuthenticationFailed => UpgradeFailure::UnsafeState,
                other => other,
            })?;
    }
    let epoch = instance
        .catalog_format_epoch()
        .map_err(|_| UpgradeFailure::UnsafeState)?
        .ok_or(UpgradeFailure::UnsafeState)?
        .value();
    let plan = request.verify_payload(instance, configuration.schema_version(), epoch)?;
    if crate::services::backup_recovery_readiness_under_gate(services, &_gate).map_err(
        |failure| match failure {
            crate::ServiceFailure::CapacityUnavailable => UpgradeFailure::CapacityUnavailable,
            _ => UpgradeFailure::SnapshotUnavailable,
        },
    )? != crate::RecoveryReadiness::Verified
    {
        return Err(UpgradeFailure::SnapshotUnavailable);
    }
    let backup = services.upgrade_backup_parameters_under_gate(
        request.repository,
        request.retention_seconds,
        &_gate,
    )?;
    let identity = |release: &positron_kernel::release_manifest::VerifiedReleaseManifest| {
        let version = release.manifest().version;
        UpgradeReleaseIdentity::new(
            release.digest(),
            crate::UpgradeReleasePlan::native_artifact(release)?.sha256,
            [version.major, version.minor, version.patch],
        )
        .map_err(|_| UpgradeFailure::InvalidRequest)
    };
    let parameters = UpgradeParameters::new(
        identity(plan.source())?,
        identity(plan.target())?,
        epoch,
        configuration.audit_binding_digest(),
        backup,
    )
    .map_err(|_| UpgradeFailure::InvalidRequest)?;
    let facts = instance
        .doctor_runtime_facts(actor)
        .map_err(|_| UpgradeFailure::UnsafeState)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| UpgradeFailure::UnsafeState)?,
    )
    .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
    let (registration_address, registration) = positron_backup::BackupRepositoryRegistration::find(
        &catalog
            .pin()
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?,
        instance.instance.to_bytes(),
        request.repository,
    )
    .map_err(|_| UpgradeFailure::SnapshotUnavailable)?
    .ok_or(UpgradeFailure::SnapshotUnavailable)?;
    if registration
        .binding_identity()
        .map_err(|_| UpgradeFailure::SnapshotUnavailable)?
        != backup.registration_identity()
    {
        return Err(UpgradeFailure::UnsafeState);
    }
    let existing =
        DurableOperationAdministration::inspect_by_idempotency(&catalog, request.idempotency)
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
    let replay_active = existing.is_some_and(|operation| !operation.status().is_terminal());
    if facts.active_durable_operations() > u32::from(replay_active) {
        return Err(UpgradeFailure::UnsafeState);
    }
    let estimate = catalog
        .backup_capture_resource_estimate(4 * 1024 * 1024)
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    instance
        ._authority
        .observe_disk()
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    let estimated = estimate.resources();
    let amounts =
        ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| estimated.get(dimension)));
    let _capacity = instance
        .resource_governor()
        .reserve(
            WorkClaim::upgrade_preflight(amounts)
                .map_err(|_| UpgradeFailure::CapacityUnavailable)?,
        )
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| UpgradeFailure::UnsafeState)?;
    let intent = DurableOperationRequest::upgrade(
        actor.principal_id(),
        request.idempotency,
        instance.instance.to_bytes(),
        request.expected_generation,
        now,
        parameters.intent_digest(),
    )
    .map_err(|_| UpgradeFailure::InvalidRequest)?;
    let operation = DurableOperationAdministration::accept_upgrade(
        &catalog,
        actor,
        intent,
        parameters,
        registration_address,
    )
    .map_err(|failure| match failure {
        positron_governance::DurableOperationFailure::StaleGeneration => {
            UpgradeFailure::StaleGeneration
        },
        positron_governance::DurableOperationFailure::IdempotencyConflict => {
            UpgradeFailure::IdempotencyConflict
        },
        _ => UpgradeFailure::PersistenceUnavailable,
    })?;
    Ok(operation)
}
