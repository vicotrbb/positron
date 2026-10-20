//! Bounded qualification and intent publication share the existing Catalog gate.
use super::*;
#[cfg(feature = "test-support")]
use std::io::Write;

pub(crate) fn accept_preflight(
    instance: &crate::InitializedInstance,
    services: &crate::ServiceHandle,
    configuration: &EffectiveConfiguration,
    bearer: &str,
    request: UpgradeRequest,
    deadline: Option<std::time::Instant>,
) -> Result<(DurableOperation, u64), UpgradeFailure> {
    #[cfg(feature = "test-support")]
    let measured = std::time::Instant::now();
    #[cfg(feature = "test-support")]
    let remaining_ms = deadline.map_or(0, |d| d.saturating_duration_since(measured).as_millis());
    #[cfg(feature = "test-support")]
    let source_bytes =
        crate::UpgradeReleasePlan::native_artifact(&request.source).map(|artifact| artifact.size);
    #[cfg(feature = "test-support")]
    let target_artifacts = request
        .target
        .verified_manifest()
        .manifest()
        .artifacts
        .len();
    #[cfg(feature = "test-support")]
    let mut stage_times = [None; 11];
    let result = (|| {
        crate::upgrade::check_admission_deadline(deadline)?;
        // Serialize the bounded physical qualification and intent publication with
        // existing Catalog writers. The caller's generation is never refreshed.
        let _gate = services
            .catalog_operation()
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        #[cfg(feature = "test-support")]
        {
            stage_times[0] = Some(measured.elapsed().as_millis());
        }
        if configuration.installed_release().is_none() {
            return Err(UpgradeFailure::AuthenticationFailed);
        }
        let refreshed = crate::upgrade::installed_upgrade_request(
            configuration,
            request.target.digest(),
            request.repository,
            request.retention_seconds,
            request.idempotency,
            request.expected_generation,
            &instance.retention_time,
        )?;
        if refreshed.source.digest() != request.source.digest() {
            return Err(UpgradeFailure::AuthenticationFailed);
        }
        #[cfg(feature = "test-support")]
        {
            stage_times[1] = Some(measured.elapsed().as_millis());
        }
        let request = refreshed;
        {
            let verification =
                crate::upgrade::installed_upgrade_startup(configuration, &instance.retention_time)?
                    .ok_or(UpgradeFailure::UnsafeState)?;
            verification
                .query_context(instance)
                .map_err(|failure| match failure {
                    UpgradeFailure::AuthenticationFailed => UpgradeFailure::UnsafeState,
                    other => other,
                })?;
        }
        #[cfg(feature = "test-support")]
        {
            stage_times[2] = Some(measured.elapsed().as_millis());
        }
        let epoch = instance
            .catalog_format_epoch()
            .map_err(|_| UpgradeFailure::UnsafeState)?
            .ok_or(UpgradeFailure::UnsafeState)?
            .value();
        #[cfg(feature = "test-support")]
        {
            stage_times[3] = Some(measured.elapsed().as_millis());
        }
        let plan = request.verify_payload_until(
            instance,
            configuration.schema_version(),
            epoch,
            deadline,
        )?;
        #[cfg(feature = "test-support")]
        {
            stage_times[4] = Some(measured.elapsed().as_millis());
        }
        if crate::services::backup_recovery_readiness_under_gate(services, &_gate).map_err(
            |failure| match failure {
                crate::ServiceFailure::CapacityUnavailable => UpgradeFailure::CapacityUnavailable,
                _ => UpgradeFailure::SnapshotUnavailable,
            },
        )? != crate::RecoveryReadiness::Verified
        {
            return Err(UpgradeFailure::SnapshotUnavailable);
        }
        #[cfg(feature = "test-support")]
        {
            stage_times[5] = Some(measured.elapsed().as_millis());
        }
        let backup = services.upgrade_backup_parameters_under_gate(
            request.repository,
            request.retention_seconds,
            &_gate,
        )?;
        #[cfg(feature = "test-support")]
        {
            stage_times[6] = Some(measured.elapsed().as_millis());
        }
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
        let actor = instance
            .attribute(
                PresentedCredential::parse(bearer)
                    .map_err(|_| UpgradeFailure::AuthenticationFailed)?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
        crate::upgrade::check_admission_deadline(deadline)?;
        let facts = instance
            .doctor_runtime_facts(actor)
            .map_err(|_| UpgradeFailure::UnsafeState)?;
        #[cfg(feature = "test-support")]
        {
            stage_times[7] = Some(measured.elapsed().as_millis());
        }
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| UpgradeFailure::UnsafeState)?,
        )
        .map_err(|_| UpgradeFailure::PersistenceUnavailable)?;
        let (registration_address, registration) =
            positron_backup::BackupRepositoryRegistration::find(
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
        #[cfg(feature = "test-support")]
        {
            stage_times[8] = Some(measured.elapsed().as_millis());
        }
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
        crate::upgrade::check_admission_deadline(deadline)?;
        #[cfg(feature = "test-support")]
        {
            stage_times[9] = Some(measured.elapsed().as_millis());
        }
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
        #[cfg(feature = "test-support")]
        {
            stage_times[10] = Some(measured.elapsed().as_millis());
        }
        // Capture the response basis before releasing the shared Catalog gate.
        let generation = catalog
            .pin()
            .map_err(|_| UpgradeFailure::PersistenceUnavailable)?
            .number();
        Ok((operation, generation))
    })();
    #[cfg(feature = "test-support")]
    {
        // Temporary hosted diagnosis: capture on stack, then emit after the Catalog guard drops.
        for (stage, elapsed) in [
            "gate_acquired",
            "request_refreshed",
            "startup_verified",
            "payload_begin",
            "payload_verified",
            "recovery_verified",
            "backup_parameters",
            "doctor_verified",
            "resource_estimated",
            "before_accept",
            "accepted",
        ]
        .into_iter()
        .zip(stage_times)
        {
            if let Some(elapsed_ms) = elapsed {
                let _diagnostic_failed = writeln!(
                    std::io::stderr(),
                    "upgrade_preflight_stage stage={stage} elapsed_ms={elapsed_ms}"
                )
                .is_err();
            }
        }
        let _diagnostic_failed = writeln!(std::io::stderr(), "upgrade_preflight_end elapsed_ms={} remaining_at_entry_ms={remaining_ms} source_bytes={source_bytes:?} target_artifacts={target_artifacts} outcome={:?}", measured.elapsed().as_millis(), result.as_ref().map(|_|())).is_err();
    }
    result
}
