//! Registration-before-spawn failure contract.

#[path = "support/process_lifecycle.rs"]
mod lifecycle;

use lifecycle::{ObservingListeners, ObservingTasks, TaskEvent, TestRoots};
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, ProcessPhase, ServeConfiguration, TaskRole,
};

#[test]
fn data_task_registration_failure_preserves_recovery_staging_and_cleans_up()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("register-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_registration: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };
    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("registration failure must fail startup");
    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Api)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert_eq!(
        tasks.events.borrow().iter().cloned().collect::<Vec<_>>(),
        [
            TaskEvent::Registered(TaskRole::Control),
            TaskEvent::Registered(TaskRole::Operations),
            TaskEvent::Spawned(TaskRole::Control),
            TaskEvent::Spawned(TaskRole::Operations),
            TaskEvent::Registered(TaskRole::Api),
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true),
        ],
        "only recovery-safe tasks start before a data registration failure, and both roll back"
    );
    Ok(())
}
