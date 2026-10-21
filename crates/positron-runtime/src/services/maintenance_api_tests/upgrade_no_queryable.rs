//! Persisted telemetry does not grant Query authority to a suspended tenant.
use super::upgrade_end_to_end::DrainedFixture;
use super::*;
use positron_governance::{
    DurableOperationAdministration as Administration, DurableOperationStatus,
};
use positron_kernel::upgrade_verification::{UpgradeQueryVerification, UpgradeVerificationReport};

#[test]
fn upgrade_without_queryable_tenant_retains_signed_not_applicable_report_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    // This helper ingests representative data before a public suspension,
    // then authenticates actual source bytes and completes genuine Process Drain.
    let drained = super::upgrade_end_to_end::drain_suspended_source()?;
    super::upgrade_end_to_end::publish_offline(&drained)?;
    verify_target_restarts(&drained)
}

#[inline(never)]
fn verify_target_restarts(drained: &DrainedFixture) -> Result<(), Box<dyn std::error::Error>> {
    let process = start_target(drained)?;
    let report = verify_report(&process, drained)?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    let reopened = start_target(drained)?;
    assert_eq!(
        verify_report(&reopened, drained)?,
        report,
        "terminal proof remains retained across a cold restart"
    );
    expire_upgrade_lookup(&reopened, drained, report)?;
    assert_eq!(
        reopened.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    old_artifact_remains_fenced(drained, report)
}

#[inline(never)]
fn start_target(
    drained: &DrainedFixture,
) -> Result<crate::RunningProcess, Box<dyn std::error::Error>> {
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let mut verification = crate::UpgradeStartupVerification::new(
        positron_config::ExecutableDistribution::Native,
        drained.target.clone(),
        None,
    )?;
    // Synthetic target version metadata only; executable measurement stays real.
    verification.fixture_version = Some(drained.version);
    Ok(ApplicationRuntime::start(
        ServeConfiguration::new(drained.fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::clone(&drained.configuration))
            .with_upgrade_verification(verification),
        HostInputs::new(&listeners, &tasks),
    )?)
}

#[inline(never)]
fn verify_report(
    process: &crate::RunningProcess,
    drained: &DrainedFixture,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    assert_eq!(process.health().phase(), crate::ProcessPhase::Serving);
    let services = process.services().ok_or("target services")?;
    assert_eq!(
        services.query_log_bodies(
            &drained.query,
            "logs | range query_time 0 100 | limit 1",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 6)?,
        ),
        Err(crate::ServiceFailure::Unauthorized)
    );
    let catalog = open_catalog(&services.instance)?;
    let operation = Administration::inspect(&catalog, drained.id)?.ok_or("upgrade operation")?;
    assert_eq!(operation.status(), DurableOperationStatus::Succeeded);
    assert!(operation.upgrade_snapshot_evidence().is_some());
    let publication =
        Administration::current_upgrade_publication(&catalog)?.ok_or("publication")?;
    assert_eq!(publication.operation_id(), drained.id);
    let report_id = publication.verification_report().ok_or("retained report")?;
    assert_eq!(operation.upgrade_verification_report(), Some(report_id));
    let snapshot = catalog.pin()?;
    let object = snapshot
        .object_identities()
        .find(|id| id.to_bytes() == report_id)
        .ok_or("report object")?;
    let report =
        UpgradeVerificationReport::from_bytes(snapshot.object(object)?.ok_or("report bytes")?)?;
    let (_, governance) = snapshot.governance_object()?;
    report.verify(positron_kernel::BootstrapIntegrityIdentity::from_pinned(
        governance.integrity_public_key(),
        governance.integrity_key_fingerprint(),
    )?)?;
    assert_eq!(report.input().operation(), drained.id.to_bytes());
    assert_eq!(report.input().instance(), governance.instance());
    assert_eq!(
        report.input().query(),
        UpgradeQueryVerification::NotApplicableNoQueryableTenant
    );
    Ok(report_id)
}

#[inline(never)]
fn expire_upgrade_lookup(
    process: &crate::RunningProcess,
    drained: &DrainedFixture,
    report: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let services = process.services().ok_or("expiry services")?;
    let _gate = services.catalog_operation()?;
    let catalog = open_catalog(&services.instance)?;
    let operation = Administration::inspect(&catalog, drained.id)?.ok_or("pre-expiry operation")?;
    let actor = Administration::resume_upgrade_actor(
        &catalog,
        drained.id,
        services.instance.retention_time.security_time_seconds()?,
    )?;
    let publication =
        Administration::current_upgrade_publication(&catalog)?.ok_or("verified publication")?;
    // Controlled metadata-time fixture invokes the existing retention owner.
    // It accepts repository inspection without executing provider work;
    // the runtime's trusted clock is neither clamped nor advanced.
    let parameters = operation
        .upgrade_parameters()
        .ok_or("Upgrade parameters")?
        .backup()
        .repository();
    let request = positron_governance::DurableOperationRequest::repository(
        actor.principal_id(),
        positron_governance::AdministrativeIdempotencyKey::new([0x95; 16])?,
        services.instance.instance.to_bytes(),
        catalog.pin()?.number(),
        operation
            .earliest_lookup_expiry_unix_seconds()
            .ok_or("lookup expiry")?,
        parameters.intent_digest(),
    )?;
    Administration::accept_repository(&catalog, actor, request, parameters)?;
    assert!(Administration::inspect(&catalog, drained.id)?.is_none());
    assert_eq!(
        Administration::current_upgrade_publication(&catalog)?,
        Some(publication)
    );
    assert_eq!(publication.verification_report(), Some(report));
    assert!(
        catalog
            .pin()?
            .object_identities()
            .any(|identity| identity.to_bytes() == report)
    );
    Ok(())
}

#[inline(never)]
fn expired_binding(
    drained: &DrainedFixture,
    report: [u8; 32],
) -> Result<
    (
        positron_kernel::CatalogGenerationId,
        crate::GracefulShutdownRecord,
    ),
    Box<dyn std::error::Error>,
> {
    let reference = crate::OfflineUpgradeSession::restore_reference(
        &drained.fixture.paths()?,
        &drained.configuration,
        drained.id,
    )?;
    let instance = crate::InstanceBootstrap::reopen_configured(
        &drained.fixture.paths()?,
        &drained.configuration,
    )?;
    let catalog = open_catalog(&instance)?;
    assert!(Administration::inspect(&catalog, drained.id)?.is_none());
    let publication =
        Administration::current_upgrade_publication(&catalog)?.ok_or("retained publication")?;
    assert_eq!(publication.operation_id(), drained.id);
    assert_eq!(publication.verification_report(), Some(report));
    assert_eq!(
        reference.snapshot_id(),
        publication.snapshot().operation_id().to_bytes()
    );
    assert_eq!(
        reference.manifest_checksum(),
        publication.snapshot().receipt().manifest()
    );

    assert!(
        catalog
            .pin()?
            .object_identities()
            .any(|identity| identity.to_bytes() == report)
    );
    let identity = catalog.pin()?.identity();
    drop(catalog);
    Ok((
        identity,
        instance
            .graceful_shutdown_record()?
            .ok_or("retained Drain marker")?,
    ))
}

#[inline(never)]
fn old_artifact_remains_fenced(
    drained: &DrainedFixture,
    report: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let before = expired_binding(drained, report)?;
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    // No version override: the actual source executable is 0.0.0, whereas
    // the retained authenticated publication requires synthetic target 0.0.1.
    let verification = crate::UpgradeStartupVerification::new(
        positron_config::ExecutableDistribution::Native,
        drained.target.clone(),
        None,
    )?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(drained.fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::clone(&drained.configuration))
            .with_upgrade_verification(verification),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    assert_eq!(
        process
            .health()
            .integrity_fence_reason()
            .map(|reason| reason.redacted_label()),
        Some("unsafe_upgrade_state")
    );
    assert!(process.services().is_none());
    assert!(
        process
            .bound_endpoints()
            .iter()
            .all(|endpoint| !endpoint.role().is_data())
    );
    assert!(!tasks.events.borrow().iter().any(|event| matches!(
        event,
        crate::process_lifecycle::TaskEvent::Registered(crate::TaskRole::Maintenance)
            | crate::process_lifecycle::TaskEvent::Spawned(crate::TaskRole::Maintenance)
    )));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    assert_eq!(
        expired_binding(drained, report)?,
        before,
        "restricted startup and shutdown preserve the exact Catalog and retained Drain marker"
    );
    Ok(())
}
