//! Process lifecycle contract through the public runtime seam.

#[path = "support/process_lifecycle.rs"]
mod lifecycle;

use lifecycle::{ObservingListeners, ObservingTasks, TaskEvent, TestRoots};
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, ListenerRole, ProcessPhase,
    PublicPlaintextApiStartupIntent, Readiness, ServeConfiguration, ShutdownTrigger, TaskRole,
};

#[test]
fn operational_worker_is_registered_before_spawn_and_retained_for_fenced_inspection()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("operational-worker")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    {
        let events = tasks.events.borrow();
        let registered = events
            .iter()
            .position(|event| *event == TaskEvent::Registered(TaskRole::OperationalTelemetry))
            .ok_or("worker registration")?;
        let spawned = events
            .iter()
            .position(|event| *event == TaskEvent::Spawned(TaskRole::OperationalTelemetry))
            .ok_or("worker spawn")?;
        assert!(registered < spawned);
    }
    process
        .services()
        .ok_or("serving services")?
        .request_integrity_fence();
    assert!(process.apply_pending_integrity_fence());
    assert!(!tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::OperationalTelemetry, _, _)
    )));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Joined(TaskRole::OperationalTelemetry, _, _)
    )));
    Ok(())
}

#[test]
fn partial_task_spawn_failure_aborts_started_tasks_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("spawn-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("task spawn failure must fail startup");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Api)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert_recovery_tasks_start_before_data_registration(&tasks);
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [
            TaskEvent::Aborted(
                TaskRole::OperationalTelemetry,
                ProcessPhase::Recovering,
                true
            ),
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true),
        ]
    );
    Ok(())
}

#[test]
fn partial_spawn_with_failed_rollback_reports_internal_cleanup_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("spawn-rollback-fault")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Api),
        fail_abort: Some(TaskRole::Operations),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("failed rollback must not report only the later spawn failure");

    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) = failure else {
        panic!("unexpected startup outcome: {failure:?}");
    };
    assert_eq!(cleanup.first_task(), Some(TaskRole::Operations));
    assert_eq!(cleanup.task_failures(), 1);
    assert_eq!(cleanup.listener_failures(), 1);
    assert!(roots.acquire_volume_again().is_ok());
    assert_recovery_tasks_start_before_data_registration(&tasks);
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true)
    )));
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [
            TaskEvent::Aborted(
                TaskRole::OperationalTelemetry,
                ProcessPhase::Recovering,
                true
            ),
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
        ]
    );
    Ok(())
}

fn assert_recovery_tasks_start_before_data_registration(tasks: &ObservingTasks) {
    let events = tasks.events.borrow();
    let expected = [
        TaskRole::Control,
        TaskRole::Operations,
        TaskRole::OperationalTelemetry,
        TaskRole::Api,
        TaskRole::OtlpGrpc,
        TaskRole::OtlpHttp,
        TaskRole::LokiPush,
        TaskRole::Maintenance,
    ];
    assert_eq!(
        &events[..6],
        [
            TaskEvent::Registered(TaskRole::Control),
            TaskEvent::Registered(TaskRole::Operations),
            TaskEvent::Registered(TaskRole::OperationalTelemetry),
            TaskEvent::Spawned(TaskRole::Control),
            TaskEvent::Spawned(TaskRole::Operations),
            TaskEvent::Spawned(TaskRole::OperationalTelemetry),
        ],
        "only recovery-safe Control, Operations, and OperationalTelemetry tasks may start before data-plane task registration"
    );
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event {
                TaskEvent::Registered(role) => Some(*role),
                _ => None,
            })
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        events
            .iter()
            .filter_map(|event| match event {
                TaskEvent::Spawned(role) => Some(*role),
                _ => None,
            })
            .collect::<Vec<_>>(),
        [
            TaskRole::Control,
            TaskRole::Operations,
            TaskRole::OperationalTelemetry,
            TaskRole::Api
        ]
    );
}

#[test]
fn nested_spawn_rollback_merges_data_control_and_listener_cleanup_truth()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("nested-cleanup")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::OtlpHttp),
        fail_abort: Some(TaskRole::Api),
        fail_abort_also: Some(TaskRole::Control),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("nested cleanup ambiguity must be preserved");
    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) = failure else {
        panic!("unexpected outcome: {failure:?}");
    };
    assert_eq!(cleanup.task_failures(), 2);
    assert_eq!(cleanup.listener_failures(), 1);
    assert_eq!(
        cleanup.primary(),
        positron_runtime::CleanupPrimary::TaskUnavailable(TaskRole::OtlpHttp)
    );
    assert_eq!(
        cleanup.failed_roles().collect::<Vec<_>>(),
        [
            positron_runtime::CleanupRole::Task(TaskRole::Api),
            positron_runtime::CleanupRole::Task(TaskRole::Control),
            positron_runtime::CleanupRole::Listener(ListenerRole::Api),
        ]
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn fenced_partial_task_spawn_failure_aborts_started_tasks_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("fenced-spawn-fault")?;
    std::fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Operations),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("fenced task spawn failure must fail startup");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Operations)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true)
    )));
    Ok(())
}

#[path = "process_lifecycle/cleanup_outcomes.rs"]
mod cleanup_outcomes;
#[path = "process_lifecycle/listeners.rs"]
mod listeners;
#[path = "process_lifecycle/outcomes.rs"]
mod outcomes;

#[test]
fn graceful_drain_publishes_authenticated_record_before_successful_restart()
-> Result<(), Box<dyn std::error::Error>> {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use prost::Message;
    let roots = TestRoots::new("graceful-record")?;
    let paths = roots.bootstrap_paths()?;
    drop(positron_runtime::InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = positron_runtime::InstanceBootstrap::claim(&paths)?;
    let ingest = claim.ingest_secret().ok_or("ingest credential")?.to_owned();
    let query = claim.query_secret().ok_or("query credential")?.to_owned();
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&listeners, &tasks),
    )?;
    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(
                            "final-durable-record".to_owned(),
                        )),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let outcome = process
        .services()
        .ok_or("services")?
        .ingest_otlp_logs(&ingest, request.encode_to_vec())?;
    assert_eq!(outcome.accepted_records(), 1);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let reopened = positron_runtime::InstanceBootstrap::reopen(&paths)?;
    let record = reopened
        .graceful_shutdown_record()?
        .ok_or("missing authenticated record")?;
    assert_eq!(record.catalog_generation(), reopened.catalog_generation());
    assert_eq!(
        record.governance_position(),
        reopened.governance_audit_frontier()
    );
    assert_eq!(
        record.sealed_scopes(),
        2,
        "both initialized Logs and Traces scopes must be sealed"
    );
    assert_eq!(
        std::fs::read_dir(roots.data.join("segments/active"))?.count(),
        0
    );
    assert!(std::fs::read_dir(roots.data.join("segments/sealed"))?.count() > 0);
    drop(reopened);
    let restarted = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(
        restarted
            .services()
            .ok_or("restarted services")?
            .query_log_bodies(
                &query,
                "logs | range query_time 0 100 | limit 16",
                positron_query::QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                    .with_cpu_work_units(16)?
            )?,
        ["final-durable-record"]
    );
    assert_eq!(
        restarted.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn pending_second_signal_skips_graceful_task_joins() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("pending-second-signal")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let outcome = process
        .begin_shutdown()
        .finish_with_termination_probe(ShutdownTrigger::FirstSignal, || true);
    assert_eq!(outcome, positron_runtime::ExitOutcome::Forced);
    assert!(
        !tasks
            .events
            .borrow()
            .iter()
            .any(|event| matches!(event, TaskEvent::Joined(..))),
        "a pending second signal must abort instead of beginning graceful joins"
    );
    assert!(roots.acquire_volume_again().is_ok());
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    assert_eq!(reopened.graceful_shutdown_record()?, None);
    Ok(())
}

#[test]
fn second_signal_during_pending_join_stops_before_another_graceful_join()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("second-signal-pending-join")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        first_join_expired: Some(TaskRole::Control),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(
        process.begin_shutdown().finish_with_termination_probe(
            ShutdownTrigger::FirstSignal,
            || tasks
                .events
                .borrow()
                .iter()
                .any(|event| matches!(event, TaskEvent::Joined(..))),
        ),
        positron_runtime::ExitOutcome::Forced
    );
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Joined(..)))
            .count(),
        1,
        "second signal must prevent waiting on the next task"
    );
    assert!(roots.acquire_volume_again().is_ok());
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    assert_eq!(reopened.graceful_shutdown_record()?, None);
    Ok(())
}

#[test]
fn pending_task_waits_are_bounded_and_retry_until_the_original_drain_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("bounded-drain-wait")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        first_join_expired: Some(TaskRole::Control),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful,
        "one short wait expiring must not exhaust the whole drain budget"
    );
    assert!(
        tasks
            .join_limits
            .borrow()
            .iter()
            .all(|limit| *limit <= std::time::Duration::from_millis(10)),
        "each wait must return promptly to the termination authority"
    );
    assert!(roots.acquire_volume_again().is_ok());
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    assert!(reopened.graceful_shutdown_record()?.is_some());
    Ok(())
}

#[test]
fn second_signal_before_final_visibility_leaves_no_drain_record()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful-interrupted")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let signal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let injected = signal.clone();
    let outcome = positron_kernel::with_catalog_publication_event_hook_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        5,
        move || {
            injected.store(true, std::sync::atomic::Ordering::Release);
        },
        || {
            process
                .begin_shutdown()
                .finish_with_termination_probe(ShutdownTrigger::FirstSignal, || {
                    signal.load(std::sync::atomic::Ordering::Acquire)
                })
        },
    );
    assert_eq!(outcome, positron_runtime::ExitOutcome::Forced);
    assert!(
        signal.load(std::sync::atomic::Ordering::Acquire),
        "the second signal must arrive at the final publication boundary"
    );
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    assert_eq!(reopened.graceful_shutdown_record()?, None);
    Ok(())
}

#[test]
fn second_signal_during_schema_checkpoint_prevents_visibility_and_recovers_acknowledged_data()
-> Result<(), Box<dyn std::error::Error>> {
    for acknowledgement_failure in [false, true] {
        let roots = TestRoots::new("schema-checkpoint-signal")?;
        let paths = roots.bootstrap_paths()?;
        drop(positron_runtime::InstanceBootstrap::initialize(
            &paths,
            positron_runtime::InitializationPlan::non_interactive(),
        )?);
        let claim = positron_runtime::InstanceBootstrap::claim(&paths)?;
        let ingest = claim.ingest_secret().ok_or("ingest credential")?.to_owned();
        let query = claim.query_secret().ok_or("query credential")?.to_owned();
        let listeners = ObservingListeners::default();
        let tasks = ObservingTasks::default();
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
            HostInputs::new(&listeners, &tasks),
        )?;
        {
            use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
            use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
            use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
            use prost::Message;
            let request = ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs {
                    scope_logs: vec![ScopeLogs {
                        log_records: vec![LogRecord {
                            time_unix_nano: 42,
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "acknowledged-before-signal".to_owned(),
                                )),
                            }),
                            attributes: vec![KeyValue {
                                key: "application".to_owned(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue(
                                        "shutdown-checkpoint".to_owned(),
                                    )),
                                }),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            };
            assert_eq!(
                process
                    .services()
                    .ok_or("services")?
                    .ingest_otlp_logs(&ingest, request.encode_to_vec())?
                    .accepted_records(),
                1
            );
        }
        let signal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let injected = signal.clone();
        let finish = || {
            process
                .begin_shutdown()
                .finish_with_termination_probe(ShutdownTrigger::FirstSignal, || {
                    signal.load(std::sync::atomic::Ordering::Acquire)
                })
        };
        let outcome = if acknowledgement_failure {
            positron_kernel::with_catalog_publication_ambiguity_hook_after(
                positron_kernel::CatalogPublicationFault::SynchronizeCommit,
                0,
                move |_| {
                    injected.store(true, std::sync::atomic::Ordering::Release);
                },
                finish,
            )
        } else {
            positron_kernel::with_catalog_publication_event_hook_after(
                positron_kernel::CatalogPublicationFault::SynchronizeCommit,
                0,
                move || {
                    injected.store(true, std::sync::atomic::Ordering::Release);
                },
                finish,
            )
        };
        assert!(
            signal.load(std::sync::atomic::Ordering::Acquire),
            "schema publication hook must fire"
        );
        assert_eq!(outcome, positron_runtime::ExitOutcome::Forced);
        let reopened = positron_runtime::InstanceBootstrap::reopen(&paths)?;
        let administrator = reopened.attribute(
            positron_governance::PresentedCredential::parse(claim.secret())?,
            positron_governance::RequestedIntent::SystemAdministration,
            positron_governance::CompatibilityHints::none(),
        )?;
        assert_eq!(
            reopened
                .inspect_governance_audit_history(administrator)?
                .records()
                .iter()
                .filter_map(positron_governance::GovernanceAuditEntry::as_schema_checkpoint)
                .count(),
            0,
            "second signal during unpublished checkpoint writes must stop publication"
        );
        assert_eq!(reopened.graceful_shutdown_record()?, None);
        drop(reopened);
        let restarted = ApplicationRuntime::start(
            ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
            HostInputs::new(&listeners, &tasks),
        )?;
        assert_eq!(
            restarted
                .services()
                .ok_or("restarted services")?
                .query_log_bodies(
                    &query,
                    "logs | range query_time 0 100 | limit 16",
                    positron_query::QueryBudget::new(
                        1_000_000, 100, 100, 1_000_000, 1_000_000, 10
                    )?
                    .with_cpu_work_units(16)?,
                )?,
            ["acknowledged-before-signal"]
        );
        assert_eq!(
            restarted.shutdown(ShutdownTrigger::FirstSignal),
            positron_runtime::ExitOutcome::Graceful
        );
    }
    Ok(())
}

#[test]
fn retained_service_reservations_block_graceful_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful-reservation")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let retained = process.services().ok_or("service authority")?.clone();
    let outcome = process.shutdown(ShutdownTrigger::FirstSignal);
    let positron_runtime::ExitOutcome::InternalCleanupFailure(failure) = outcome else {
        panic!("retained ownership outcome: {outcome:?}");
    };
    assert!(failure.ownership_release_failed());
    assert_eq!(failure.primary(), positron_runtime::CleanupPrimary::Forced);
    assert!(
        roots.acquire_volume_again().is_err(),
        "retained authority must still hold ownership"
    );
    drop(retained);
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    assert_eq!(reopened.graceful_shutdown_record()?, None);
    Ok(())
}

#[test]
fn failed_final_catalog_publication_reports_typed_cleanup_and_no_graceful_record()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful-publication-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let outcome = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || process.shutdown(ShutdownTrigger::FirstSignal),
    );
    let positron_runtime::ExitOutcome::InternalCleanupFailure(failure) = outcome else {
        panic!("publication fault outcome: {outcome:?}");
    };
    assert!(failure.durable_shutdown_failed());
    assert_eq!(failure.primary(), positron_runtime::CleanupPrimary::Forced);
    assert!(failure.failed_roles().any(|role| role
        == positron_runtime::CleanupRole::DurableShutdown(
            positron_runtime::BootstrapFailureCode::CatalogUnavailable
        )));
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    assert_eq!(reopened.graceful_shutdown_record()?, None);
    Ok(())
}

#[test]
fn lost_final_marker_acknowledgement_confirms_completed_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful-marker-acknowledgement")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let signal = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let injected = signal.clone();
    let observed = signal.clone();
    let outcome = positron_kernel::with_catalog_generation_ambiguity_hook_after(
        5,
        move |_| {
            injected.store(true, std::sync::atomic::Ordering::Release);
        },
        || {
            process
                .begin_shutdown()
                .finish_with_termination_probe(ShutdownTrigger::FirstSignal, || {
                    observed.load(std::sync::atomic::Ordering::Acquire)
                })
        },
    );
    assert!(
        signal.load(std::sync::atomic::Ordering::Acquire),
        "the final marker acknowledgement fault must be consumed"
    );
    assert_eq!(
        outcome,
        positron_runtime::ExitOutcome::Graceful,
        "the authenticated final marker confirms completion despite a later second signal"
    );
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    let record = reopened
        .graceful_shutdown_record()?
        .ok_or("durable completion record")?;
    assert_eq!(record.catalog_generation(), reopened.catalog_generation());
    Ok(())
}

#[test]
fn unresolved_final_marker_synchronization_never_reports_graceful()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful-marker-unresolved")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let outcome = positron_kernel::with_catalog_publication_fault_sequence_after(
        &[
            (
                positron_kernel::CatalogPublicationFault::SynchronizeGenerationDirectory,
                5,
            ),
            (
                positron_kernel::CatalogPublicationFault::SynchronizeGenerationDirectory,
                0,
            ),
        ],
        || process.shutdown(ShutdownTrigger::FirstSignal),
    );
    let positron_runtime::ExitOutcome::InternalCleanupFailure(failure) = outcome else {
        panic!("unresolved durable completion outcome: {outcome:?}");
    };
    assert!(failure.durable_shutdown_failed());
    assert_eq!(failure.primary(), positron_runtime::CleanupPrimary::Forced);
    // The visible transaction can survive recovery, but its uncertain sync
    // acknowledgement must never be converted into process success.
    let reopened = positron_runtime::InstanceBootstrap::reopen(&roots.bootstrap_paths()?)?;
    let failure = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || reopened.graceful_shutdown_record(),
    )
    .expect_err("inspection cannot certify durability while marker synchronization fails");
    assert_eq!(
        failure.code(),
        positron_runtime::BootstrapFailureCode::CatalogUnavailable
    );
    assert!(
        reopened.graceful_shutdown_record()?.is_some(),
        "later exact-marker durability confirmation restores historical proof"
    );
    Ok(())
}
