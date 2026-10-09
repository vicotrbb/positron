//! Critical-worker termination through the process owner and host task boundary.
#[path = "support/process_lifecycle.rs"]
mod lifecycle;
use lifecycle::{ObservingListeners, ObservingTasks, TestRoots};
use positron_runtime::{
    ApplicationRuntime, ExitOutcome, HostInputs, InitializationMode, Liveness, ProcessPhase,
    Readiness, ServeConfiguration, ShutdownTrigger, TaskRole,
};

#[test]
fn failed_critical_worker_closes_admission_fails_liveness_and_preserves_typed_exit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("critical-worker-failure")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_join: Some(TaskRole::Control),
        ..ObservingTasks::default()
    };
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();
    assert_eq!(
        process.poll(),
        Err(ExitOutcome::TaskUnavailable(TaskRole::Control))
    );
    assert_eq!(health.phase(), ProcessPhase::Stopping);
    assert_eq!(health.readiness(), Readiness::NotReady);
    assert_eq!(health.liveness(), Liveness::Dead);
    assert_eq!(
        process.shutdown(ShutdownTrigger::DeadlineExpired),
        ExitOutcome::TaskUnavailable(TaskRole::Control)
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn draining_observes_later_worker_failure_while_an_earlier_worker_is_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("draining-task-failure")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        pending_join: Some(TaskRole::Control),
        fail_join: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let mut draining = process.begin_shutdown();
    assert_eq!(
        draining.poll(),
        Err(positron_runtime::TaskFailure::JoinUnavailable)
    );
    assert_eq!(
        draining.finish(ShutdownTrigger::DeadlineExpired),
        ExitOutcome::Forced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}
