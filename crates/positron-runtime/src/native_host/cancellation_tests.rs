use std::sync::mpsc;
use std::time::Duration;

use super::{NativeRunningTask, cancel_and_notify};
use crate::{RunningTask, TaskCancellation, TaskFailure, TaskJoinOutcome};

#[test]
fn cancellation_wake_retires_a_worker_that_consumes_the_notification()
-> Result<(), Box<dyn std::error::Error>> {
    let force = TaskCancellation::new();
    let worker_force = force.clone();
    let (wake, wait_for_wake) = mpsc::channel();
    let (observation, observed) = mpsc::channel();
    let (release, wait_for_release) = mpsc::channel();
    let mut task = NativeRunningTask {
        force,
        maintenance_wake: None,
        shutdown_cancellation: None,
        handle: Some(std::thread::spawn(move || {
            wait_for_wake
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| TaskFailure::JoinUnavailable)?;
            let cancelled = worker_force.is_cancelled();
            observation
                .send(cancelled)
                .map_err(|_| TaskFailure::JoinUnavailable)?;
            if !cancelled {
                // A consumed wake with no visible cancellation leaves the worker
                // parked until another notification, beyond the abort budget.
                wait_for_release
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| TaskFailure::JoinUnavailable)?;
            }
            Ok(())
        })),
    };
    let mut notification = Err(String::from("notification not delivered"));
    cancel_and_notify(&task.force, || {
        notification = wake
            .send(())
            .map_err(|error| error.to_string())
            .and_then(|()| {
                observed
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|error| error.to_string())
            });
    });
    let outcome = task.join_within(Duration::from_millis(250));
    // Release and join before asserting, including the failing old-order case.
    let released = release.send(());
    let cleanup = task.join_within(Duration::from_secs(5));
    let cancelled = notification?;
    assert!(cancelled || released.is_ok());
    assert_eq!(cleanup, Ok(TaskJoinOutcome::Joined));
    assert_eq!(outcome, Ok(TaskJoinOutcome::Joined));
    Ok(())
}

#[test]
fn global_shutdown_retires_a_worker_only_after_shutdown_is_requested() {
    let force = TaskCancellation::new();
    let worker_force = force.clone();
    let shutdown = TaskCancellation::new();
    let mut task = NativeRunningTask {
        force,
        maintenance_wake: None,
        shutdown_cancellation: Some(shutdown.clone()),
        handle: Some(std::thread::spawn(move || {
            while !worker_force.is_cancelled() {
                std::thread::yield_now();
            }
            Ok(())
        })),
    };
    let before_shutdown = task.join_within(Duration::ZERO);
    shutdown.cancel();
    let after_shutdown = task.join_within(Duration::from_secs(5));
    let cleanup = task.abort();
    assert_eq!(cleanup, Ok(()));
    assert_eq!(before_shutdown, Ok(TaskJoinOutcome::DeadlineExpired));
    assert_eq!(after_shutdown, Ok(TaskJoinOutcome::Joined));
}
