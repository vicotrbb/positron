use super::*;

#[test]
fn listener_bind_failure_is_typed_and_releases_the_volume_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("bind-fault")?;
    let listeners = ObservingListeners {
        fail_role: Some(ListenerRole::OtlpHttp),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks::default();
    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("listener bind failure must fail startup");
    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::ListenerUnavailable(ListenerRole::OtlpHttp)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter_map(|event| match event {
                TaskEvent::Spawned(role) => Some(*role),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [TaskRole::Control, TaskRole::Operations]
    );
    Ok(())
}

#[test]
fn listener_endpoint_role_mismatch_fails_closed_before_startup()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("listener-role-mismatch")?;
    let listeners = ObservingListeners {
        mismatched_role: Some(ListenerRole::Operations),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks::default();
    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("a listener claiming the wrong role must fail closed");
    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::ListenerUnavailable(ListenerRole::Operations)
    );
    assert!(tasks.no_task_spawned());
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn invalid_explicit_listener_generation_is_rejected_before_binding_or_initializing()
-> Result<(), Box<dyn std::error::Error>> {
    struct IncompleteProfiles(ObservingListeners);
    impl positron_runtime::ListenerFactory for IncompleteProfiles {
        fn profile_for(&self, role: ListenerRole) -> Option<positron_runtime::ListenerProfile> {
            (role == ListenerRole::Control).then(|| positron_runtime::ListenerProfile::Control {
                path: std::env::temp_dir().join("positron-incomplete-profile.sock"),
            })
        }
        fn bind(
            &self,
            request: positron_runtime::ListenerRequest,
        ) -> Result<Box<dyn positron_runtime::BoundListener>, positron_runtime::ListenerFailure>
        {
            self.0.bind(request)
        }
    }
    let roots = TestRoots::new("incomplete-generation")?;
    let listeners = IncompleteProfiles(ObservingListeners::default());
    let tasks = ObservingTasks::default();
    let result = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    );
    assert!(
        matches!(
            result,
            Err(positron_runtime::ExitOutcome::InvalidConfiguration)
        ),
        "partial explicit profile generation outcome: {result:?}"
    );
    assert!(listeners.0.bound.borrow().is_empty());
    assert!(tasks.no_task_spawned());
    assert_eq!(
        positron_runtime::InstanceBootstrap::classify(&roots.bootstrap_paths()?)?,
        positron_runtime::BootstrapState::Empty
    );
    Ok(())
}

#[test]
fn operations_bind_failure_reports_failure_to_close_the_already_bound_control_listener()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("early-bind-cleanup")?;
    let listeners = ObservingListeners {
        fail_role: Some(ListenerRole::Operations),
        fail_close: Some(ListenerRole::Control),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks::default();
    let result = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    );
    let Err(positron_runtime::ExitOutcome::InternalCleanupFailure(failure)) = result else {
        panic!("early listener cleanup failure must be reported: {result:?}");
    };
    assert_eq!(
        failure.primary(),
        positron_runtime::CleanupPrimary::ListenerUnavailable(ListenerRole::Operations)
    );
    assert_eq!(failure.listener_failures(), 1);
    assert!(tasks.no_task_spawned());
    Ok(())
}
