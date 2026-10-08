//! Forced-shutdown contract.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use positron_kernel::CrashRecordStore;
use positron_runtime::{
    ApplicationRuntime, BoundEndpoint, BoundListener, HostInputs, InitializationMode,
    ListenerFactory, ListenerFailure, ListenerRequest, ListenerRole, RegisteredTask, RunningTask,
    ServeConfiguration, ShutdownTrigger, TaskCancellation, TaskFailure, TaskJoinOutcome,
    TaskRegistrar, TaskRole,
};

#[path = "support/process_roots.rs"]
mod process_roots;
use process_roots::TestRoots;

struct Host {
    late_join_failure: bool,
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
        if self.late_join_failure && role == TaskRole::Control {
            return Ok(Box::new(LateJoinFailureTask));
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

#[test]
fn second_signal_forces_abort_and_releases_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("second-signal")?;
    let host = Host {
        late_join_failure: false,
    };
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
    let host = Host {
        late_join_failure: false,
    };
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
    let host = Host {
        late_join_failure: true,
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
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

    let volume = roots.acquire_volume_again()?;
    let readout = CrashRecordStore::from_volume(&volume)
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
    let host = Host {
        late_join_failure: false,
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
        positron_runtime::ExitOutcome::Graceful
    );

    let volume = roots.acquire_volume_again()?;
    assert_eq!(
        CrashRecordStore::from_volume(&volume)
            .map_err(|failure| format!("open crash records: {failure:?}"))?
            .read_recent(Duration::from_secs(60), 1, 384, SystemTime::now())
            .map_err(|failure| format!("read crash records: {failure:?}"))?
            .render(),
        "record_count=0\n"
    );
    Ok(())
}

#[test]
fn full_crash_record_store_does_not_change_a_late_join_forced_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("late-join-full-crash-store")?;
    let host = Host {
        late_join_failure: true,
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
