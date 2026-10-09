//! Forced-shutdown contract.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use positron_runtime::{
    ApplicationRuntime, BoundEndpoint, BoundListener, HostInputs, InitializationMode,
    InstanceBootstrap, ListenerFactory, ListenerFailure, ListenerRequest, ListenerRole,
    RegisteredTask, RunningTask, ServeConfiguration, ShutdownTrigger, TaskCancellation,
    TaskFailure, TaskJoinOutcome, TaskRegistrar, TaskRole,
};

#[path = "support/process_roots.rs"]
mod process_roots;
use process_roots::TestRoots;

#[derive(Default)]
struct Host {
    late_join_failure: bool,
    poll_join_failure: bool,
}

impl ListenerFactory for Host {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure> {
        let endpoint = if request.role() == ListenerRole::Control {
            BoundEndpoint::control(PathBuf::from("/tmp/positron-forced.sock"))?
        } else {
            BoundEndpoint::tcp(
                request.role(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_499)),
            )?
        };
        Ok(Box::new(Listener(endpoint)))
    }
}

struct Listener(BoundEndpoint);

impl BoundListener for Listener {
    fn endpoint(&self) -> &BoundEndpoint {
        &self.0
    }
}

impl TaskRegistrar for Host {
    fn register(&self, role: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
        if role == TaskRole::Control {
            if self.poll_join_failure {
                return Ok(Box::new(PollJoinFailureTask));
            }
            if self.late_join_failure {
                return Ok(Box::new(LateJoinFailureTask));
            }
        }
        Ok(Box::new(Task))
    }
}

struct Task;

impl RegisteredTask for Task {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        _health: positron_runtime::HealthState,
        _services: Option<positron_runtime::ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        Ok(Box::new(TaskHandle(cancellation)))
    }
}

struct TaskHandle(TaskCancellation);

impl RunningTask for TaskHandle {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        Ok(Some(TaskJoinOutcome::Joined))
    }

    fn join_within(
        &mut self,
        _remaining: std::time::Duration,
    ) -> Result<TaskJoinOutcome, TaskFailure> {
        Ok(TaskJoinOutcome::Joined)
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        assert!(self.0.is_cancelled());
        Ok(())
    }
}

struct LateJoinFailureTask;

impl RegisteredTask for LateJoinFailureTask {
    fn spawn(
        self: Box<Self>,
        _cancellation: TaskCancellation,
        _health: positron_runtime::HealthState,
        _services: Option<positron_runtime::ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        Ok(Box::new(LateJoinFailureTask))
    }
}

impl RunningTask for LateJoinFailureTask {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        Ok(None)
    }

    fn join_within(
        &mut self,
        _remaining: std::time::Duration,
    ) -> Result<TaskJoinOutcome, TaskFailure> {
        Err(TaskFailure::JoinUnavailable)
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        Ok(())
    }
}

struct PollJoinFailureTask;

impl RegisteredTask for PollJoinFailureTask {
    fn spawn(
        self: Box<Self>,
        _cancellation: TaskCancellation,
        _health: positron_runtime::HealthState,
        _services: Option<positron_runtime::ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        Ok(Box::new(PollJoinFailureTask))
    }
}

impl RunningTask for PollJoinFailureTask {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        Err(TaskFailure::JoinUnavailable)
    }

    fn join_within(
        &mut self,
        _remaining: std::time::Duration,
    ) -> Result<TaskJoinOutcome, TaskFailure> {
        Err(TaskFailure::JoinUnavailable)
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        Ok(())
    }
}

#[test]
fn second_signal_forces_abort_and_releases_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("second-signal")?;
    let host = Host::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&host, &host),
    )?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::SecondSignal),
        positron_runtime::ExitOutcome::Forced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn deadline_escalates_without_calling_a_blocking_join() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("deadline-preempt")?;
    let host = Host::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&host, &host),
    )?;
    let draining = process.begin_shutdown();
    assert_eq!(
        draining.health().phase(),
        positron_runtime::ProcessPhase::Draining
    );
    assert_eq!(
        draining.finish(ShutdownTrigger::DeadlineExpired),
        positron_runtime::ExitOutcome::Forced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn late_join_failure_persists_a_bounded_drain_record_without_changing_forced_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("late-join-drain-record")?;
    let paths = roots.bootstrap_paths()?;
    let host = Host {
        late_join_failure: true,
        ..Host::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;

    let mut draining = process.begin_shutdown();
    assert!(
        !draining.poll()?,
        "the failing control task remains live before its bounded drain join"
    );
    assert_eq!(
        draining.finish(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Forced
    );

    let reopened = InstanceBootstrap::reopen(&paths)?;
    let readout = reopened
        .crash_records()
        .map_err(|failure| format!("open crash records: {failure:?}"))?
        .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
        .map_err(|failure| format!("read crash records: {failure:?}"))?
        .render();
    assert!(readout.contains("phase=draining"));
    assert!(readout.contains("component=runtime"));
    assert!(readout.contains("finding_code=runtime_drain_failed"));
    Ok(())
}

#[test]
fn graceful_shutdown_without_a_task_failure_does_not_persist_a_drain_record()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful-drain-record")?;
    let paths = roots.bootstrap_paths()?;
    let host = Host::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        reopened
            .crash_records()
            .map_err(|failure| format!("open crash records: {failure:?}"))?
            .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
            .map_err(|failure| format!("read crash records: {failure:?}"))?
            .render(),
        "record_count=0\n"
    );
    Ok(())
}

#[test]
fn crash_record_storage_never_exposes_sanitized_record_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("encrypted-crash-record")?;
    let paths = roots.bootstrap_paths()?;
    let host = Host::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    process
        .persist_crash_record("draining", "runtime_drain_failed", "runtime")
        .map_err(|failure| format!("persist crash record: {failure:?}"))?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );

    let crash_directory = roots.data.join("diagnostics").join("crash-records");
    let persisted = fs::read_dir(&crash_directory)?
        .next()
        .transpose()?
        .ok_or("crash record was not persisted")?;
    let bytes = fs::read(persisted.path())?;
    assert!(
        !bytes
            .windows(b"finding_code=runtime_drain_failed".len())
            .any(|window| { window == b"finding_code=runtime_drain_failed" }),
        "managed crash-record storage exposed sanitized plaintext"
    );

    let reopened = positron_runtime::InstanceBootstrap::reopen(&paths)?;
    let rendered = reopened
        .crash_records()?
        .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
        .map_err(|failure| format!("read crash records: {failure:?}"))?
        .render();
    assert!(rendered.contains("finding_code=runtime_drain_failed"));
    Ok(())
}

#[test]
fn tampered_crash_record_is_omitted_before_trusted_rendering()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("tampered-crash-record")?;
    let paths = roots.bootstrap_paths()?;
    let host = Host::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    process
        .persist_crash_record("draining", "runtime_drain_failed", "runtime")
        .map_err(|failure| format!("persist crash record: {failure:?}"))?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );

    let crash_directory = roots.data.join("diagnostics").join("crash-records");
    let record = fs::read_dir(&crash_directory)?
        .next()
        .transpose()?
        .ok_or("crash record was not persisted")?;
    let mut bytes = fs::read(record.path())?;
    let byte = bytes.last_mut().ok_or("persisted crash record was empty")?;
    *byte ^= 1;
    fs::write(record.path(), bytes)?;

    let readout = InstanceBootstrap::reopen(&paths)?
        .crash_records()?
        .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
        .map_err(|failure| format!("read crash records: {failure:?}"))?;
    assert_eq!(readout.render(), "record_count=0\n");
    assert!(
        readout
            .omissions()
            .contains(&"unauthenticated_crash_record")
    );
    Ok(())
}

#[test]
fn foreign_instance_crash_record_is_omitted_before_trusted_rendering()
-> Result<(), Box<dyn std::error::Error>> {
    let source_roots = TestRoots::new("source-crash-record")?;
    let source_paths = source_roots.bootstrap_paths()?;
    let host = Host::default();
    let source = ApplicationRuntime::start(
        ServeConfiguration::new(source_paths, InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    source
        .persist_crash_record("draining", "runtime_drain_failed", "runtime")
        .map_err(|failure| format!("persist source crash record: {failure:?}"))?;
    assert_eq!(
        source.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let source_record = fs::read_dir(source_roots.data.join("diagnostics").join("crash-records"))?
        .next()
        .transpose()?
        .ok_or("source crash record was not persisted")?
        .path();

    let target_roots = TestRoots::new("foreign-crash-record")?;
    let target_paths = target_roots.bootstrap_paths()?;
    let target = ApplicationRuntime::start(
        ServeConfiguration::new(target_paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    assert_eq!(
        target.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let target_directory = target_roots.data.join("diagnostics").join("crash-records");
    fs::create_dir_all(&target_directory)?;
    fs::copy(
        source_record,
        target_directory.join("record-00000000000000000000.frame"),
    )?;

    let readout = InstanceBootstrap::reopen(&target_paths)?
        .crash_records()?
        .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
        .map_err(|failure| format!("read crash records: {failure:?}"))?;
    assert_eq!(readout.render(), "record_count=0\n");
    assert!(
        readout
            .omissions()
            .contains(&"unauthenticated_crash_record")
    );
    Ok(())
}

#[test]
fn legacy_plaintext_crash_record_is_an_explicit_omission() -> Result<(), Box<dyn std::error::Error>>
{
    let roots = TestRoots::new("legacy-crash-record")?;
    let paths = roots.bootstrap_paths()?;
    let host = Host::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let crash_directory = roots.data.join("diagnostics").join("crash-records");
    fs::create_dir_all(&crash_directory)?;
    fs::write(
        crash_directory.join("record-00000000000000000000.txt"),
        b"record_version=1\nproduct=positron\nbuild_identity=unavailable\nphase=draining\ncomponent=runtime\nfinding_code=runtime_drain_failed\nbacktrace_identity=unavailable\ncatalog_generation=unavailable\noperation_generation=unavailable\n",
    )?;

    let readout = InstanceBootstrap::reopen(&paths)?
        .crash_records()?
        .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
        .map_err(|failure| format!("read crash records: {failure:?}"))?;
    assert_eq!(readout.render(), "record_count=0\n");
    assert!(
        readout
            .omissions()
            .contains(&"unauthenticated_legacy_crash_record")
    );
    Ok(())
}

#[test]
fn deleted_crash_record_is_replaced_with_fresh_authenticated_ciphertext()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("replaced-crash-record")?;
    let paths = roots.bootstrap_paths()?;
    let host = Host::default();
    let first = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    first
        .persist_crash_record("draining", "runtime_drain_failed", "runtime")
        .map_err(|failure| format!("persist first crash record: {failure:?}"))?;
    assert_eq!(
        first.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let record = roots
        .data
        .join("diagnostics")
        .join("crash-records")
        .join("record-00000000000000000000.frame");
    let first_bytes = fs::read(&record)?;
    fs::remove_file(&record)?;

    let second = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    second
        .persist_crash_record("draining", "runtime_drain_failed", "runtime")
        .map_err(|failure| format!("persist replacement crash record: {failure:?}"))?;
    assert_eq!(
        second.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let replacement = fs::read(&record)?;
    assert_ne!(
        first_bytes, replacement,
        "a deleted record must not reuse an authenticated frame context"
    );
    let rendered = InstanceBootstrap::reopen(&paths)?
        .crash_records()?
        .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
        .map_err(|failure| format!("read crash records: {failure:?}"))?
        .render();
    assert!(rendered.contains("finding_code=runtime_drain_failed"));
    Ok(())
}

#[test]
fn full_crash_record_store_does_not_change_a_late_join_forced_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("late-join-full-crash-store")?;
    let host = Host {
        late_join_failure: true,
        ..Host::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&host, &host),
    )?;
    let mut persistence_failed = false;
    for _ in 0..64 {
        if process
            .persist_crash_record("draining", "runtime_drain_failed", "runtime")
            .is_err()
        {
            persistence_failed = true;
            break;
        }
    }
    assert!(
        persistence_failed,
        "the bounded crash record store eventually rejects another record"
    );

    let mut draining = process.begin_shutdown();
    assert!(!draining.poll()?);
    assert_eq!(
        draining.finish(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Forced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

const DRAIN_DIAGNOSTIC_CHILD_MODE: &str = "POSITRON_DRAIN_DIAGNOSTIC_CHILD_MODE";

#[test]
fn drain_diagnostic_child_reports_late_join_failure() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os(DRAIN_DIAGNOSTIC_CHILD_MODE).as_deref()
        != Some(std::ffi::OsStr::new("late_join"))
    {
        return Ok(());
    }

    let roots = TestRoots::new("drain-diagnostic-late-child")?;
    let host = Host {
        late_join_failure: true,
        ..Host::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&host, &host),
    )?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Forced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn drain_diagnostic_child_reports_poll_join_failure() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os(DRAIN_DIAGNOSTIC_CHILD_MODE).as_deref()
        != Some(std::ffi::OsStr::new("poll_join"))
    {
        return Ok(());
    }

    let roots = TestRoots::new("drain-diagnostic-poll-child")?;
    let host = Host {
        poll_join_failure: true,
        ..Host::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&host, &host),
    )?;
    let mut draining = process.begin_shutdown();
    assert_eq!(draining.poll(), Err(TaskFailure::JoinUnavailable));
    assert_eq!(
        draining.finish(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Forced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

fn child_drain_diagnostic(
    mode: &str,
    test_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(std::env::current_exe()?)
        .args(["--exact", test_name, "--nocapture"])
        .env(DRAIN_DIAGNOSTIC_CHILD_MODE, mode)
        .output()?;
    assert!(
        output.status.success(),
        "diagnostic child {test_name} failed with status {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stderr)?)
}

#[test]
fn drain_diagnostic_reports_closed_late_join_context_to_stderr()
-> Result<(), Box<dyn std::error::Error>> {
    let stderr = child_drain_diagnostic(
        "late_join",
        "drain_diagnostic_child_reports_late_join_failure",
    )?;
    assert!(
        stderr.contains(
            "positron: runtime drain task failure site=join_within role=control category=join_unavailable"
        ),
        "late-join drain failure did not emit its closed diagnostic: {stderr}"
    );
    Ok(())
}

#[test]
fn drain_diagnostic_reports_closed_poll_join_context_to_stderr()
-> Result<(), Box<dyn std::error::Error>> {
    let stderr = child_drain_diagnostic(
        "poll_join",
        "drain_diagnostic_child_reports_poll_join_failure",
    )?;
    assert!(
        stderr.contains(
            "positron: runtime drain task failure site=poll_join role=control category=join_unavailable"
        ),
        "poll-join drain failure did not emit its closed diagnostic: {stderr}"
    );
    Ok(())
}

#[test]
fn elapsed_drain_deadline_is_not_restarted_by_finish() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("retained-drain-deadline")?;
    let host = Host::default();
    let effective = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            None,
            std::iter::empty::<(String, String)>(),
            [("runtime.shutdown_grace_seconds", "1")],
        )
        .map_err(|error| format!("configuration input: {error:?}"))?,
    )?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(std::sync::Arc::new(effective)),
        HostInputs::new(&host, &host),
    )?;
    let draining = process.begin_shutdown();
    std::thread::sleep(Duration::from_millis(1_100));
    assert_eq!(
        draining.finish(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Forced,
        "finishing after the configured deadline must never publish graceful completion"
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}
