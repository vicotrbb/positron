//! Public Process startup must retain unsafe Upgrade intent behind minimal listeners.
use super::*;
#[test]
fn unfinished_upgrade_never_opens_ordinary_data_listeners() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    let configuration = super::upgrade_offline::configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    super::upgrade_offline::accept(&instance, &services, &administrator, &configuration)?;
    drop(services);
    drop(instance);
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::new(configuration.clone())),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert!(process.pending_upgrade_operation()?.is_some());
    assert!(
        process
            .resume_configured_upgrade_drain(&configuration)
            .is_err()
    );
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    assert_eq!(
        process
            .health()
            .integrity_fence_reason()
            .map(|reason| reason.redacted_label()),
        Some("unsafe_upgrade_state")
    );
    assert!(
        process
            .bound_endpoints()
            .iter()
            .all(|endpoint| !endpoint.role().is_data())
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}
