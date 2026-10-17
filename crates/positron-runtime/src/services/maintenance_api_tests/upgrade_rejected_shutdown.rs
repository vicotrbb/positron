//! Rejected deployment cleanup must preserve the authenticated offline recovery basis.
use super::*;
use positron_kernel::Catalog;

#[test]
fn rejected_upgrade_shutdown_preserves_exact_drain_recovery_basis()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = super::upgrade_offline::configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = super::upgrade_offline::accept(&instance, &services, &administrator, &configuration)?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "Drain")?;
    drop(services);
    drop(instance);
    let session = crate::OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    let before = session.status()?;
    let evidence = before.upgrade_drain_evidence().ok_or("Drain evidence")?;
    drop(session);
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let basis = catalog.pin()?.identity();
    drop(catalog);
    drop(instance);
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::new(configuration.clone())),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    assert!(process.services().is_none());
    assert!(
        process
            .bound_endpoints()
            .iter()
            .all(|endpoint| !endpoint.role().is_data())
    );
    assert!(tasks.events.borrow().iter().all(|event| !matches!(
        event,
        crate::process_lifecycle::TaskEvent::Spawned(
            crate::TaskRole::Maintenance
                | crate::TaskRole::Api
                | crate::TaskRole::OtlpGrpc
                | crate::TaskRole::OtlpHttp
                | crate::TaskRole::LokiPush
        )
    )));
    let health = process.health();
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    assert_eq!(health.phase(), crate::ProcessPhase::Stopped);
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let record = instance
        .graceful_shutdown_record()?
        .ok_or("retained marker")?;
    assert_eq!(record.marker_identity(), evidence.marker_identity());
    assert_eq!(record.transaction(), evidence.transaction());
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    assert_eq!(
        catalog.pin()?.identity(),
        basis,
        "restricted lifetime must not publish"
    );
    drop(catalog);
    drop(instance);
    assert_eq!(
        crate::OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?.status()?,
        before
    );
    Ok(())
}

#[test]
fn rejected_pre_drain_intent_still_publishes_a_real_first_signal_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = super::upgrade_offline::configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "old Drain")?;
    drop(instance);
    let instance = Arc::new(crate::InstanceBootstrap::reopen_configured(
        &fixture.paths()?,
        &configuration,
    )?);
    let old = instance
        .graceful_shutdown_record()?
        .ok_or("old record")?
        .marker_identity();
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = super::upgrade_offline::accept(&instance, &services, &administrator, &configuration)?;
    drop(services);
    drop(instance);
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::new(configuration.clone())),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    let session = crate::OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    let evidence = session
        .status()?
        .upgrade_drain_evidence()
        .ok_or("new Drain")?;
    assert_ne!(evidence.marker_identity(), old);
    Ok(())
}

#[test]
fn rejected_upgrade_shutdown_does_not_reuse_drain_after_native_data_changed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = super::upgrade_offline::configuration(&fixture)?;
    let (instance, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = super::upgrade_offline::accept(&instance, &services, &administrator, &configuration)?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "Drain")?;
    drop(services);
    drop(instance);
    let session = crate::OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    drop(session);
    let instance = Arc::new(crate::InstanceBootstrap::reopen_configured(
        &fixture.paths()?,
        &configuration,
    )?);
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    services.ingest_otlp_logs(&ingest, request("after Upgrade Drain").encode_to_vec())?;
    drop(services);
    drop(instance);
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::new(configuration.clone())),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert!(process.services().is_none());
    let crate::ExitOutcome::InternalCleanupFailure(failure) =
        process.shutdown(ShutdownTrigger::FirstSignal)
    else {
        panic!("changed frontiers must refuse clean Upgrade marker reuse");
    };
    assert!(failure.durable_shutdown_failed());
    drop(crate::InstanceBootstrap::reopen_configured(
        &fixture.paths()?,
        &configuration,
    )?);
    Ok(())
}
