//! Lifecycle sequences at the runtime, listener, and task host interfaces.
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use crate::tail_fuzz_support::{FuzzRoot, describe};
use crate::*;

const ROLES: [TaskRole; 7] = [
    TaskRole::Control,
    TaskRole::Operations,
    TaskRole::Api,
    TaskRole::OtlpGrpc,
    TaskRole::OtlpHttp,
    TaskRole::LokiPush,
    TaskRole::Maintenance,
];

pub(super) fn run(data: &[u8]) {
    if let Err(error) = run_checked(data) {
        panic!("process lifecycle fuzz invariant: {error}");
    }
}

fn run_checked(data: &[u8]) -> Result<(), String> {
    let root = FuzzRoot::new()?;
    let selected = data.first().copied().unwrap_or(0);
    let role = ROLES
        .get(usize::from(selected % 7))
        .copied()
        .ok_or("task role")?;
    let failure = Arc::new(AtomicU8::new(0));
    let host = Host {
        role,
        startup_fault: selected % 8,
        failure: Arc::clone(&failure),
    };
    let recovery = Recovery {
        remaining: Cell::new(selected % 3),
        attempts: Cell::new(0),
    };
    let configuration =
        ServeConfiguration::new(root.paths()?, InitializationMode::InitializeIfEmpty);
    let mut process = match ApplicationRuntime::start(
        configuration,
        HostInputs::with_recovery(&host, &host, &recovery),
    ) {
        Ok(process) => process,
        Err(ExitOutcome::TaskUnavailable(failed)) if matches!(host.startup_fault, 1 | 2) => {
            assert_eq!(failed, role);
            assert!(InstanceBootstrap::classify(&root.paths()?).is_ok());
            return Ok(());
        },
        Err(outcome) => return Err(format!("unexpected startup outcome: {outcome:?}")),
    };
    let health = process.health();
    assert_eq!(health.phase(), ProcessPhase::Serving);
    assert_eq!(health.readiness(), Readiness::Ready);
    assert_eq!(health.liveness(), Liveness::Live);
    for action in data.iter().copied().skip(1).take(32) {
        match action % 8 {
            0 => process.poll().map_err(describe)?,
            1 | 2 => {
                failure.store(if action % 8 == 1 { 1 } else { 2 }, Ordering::Release);
                assert_eq!(process.poll(), Err(ExitOutcome::TaskUnavailable(role)));
                assert_eq!(health.readiness(), Readiness::NotReady);
                assert_eq!(health.liveness(), Liveness::Dead);
                assert_eq!(
                    process.shutdown(ShutdownTrigger::DeadlineExpired),
                    ExitOutcome::TaskUnavailable(role)
                );
                assert_eq!(health.phase(), ProcessPhase::Stopped);
                return Ok(());
            },
            3 => {
                let services = process.services().ok_or("serving services")?;
                services.request_integrity_fence_with(IntegrityFenceReason::AmbiguousIntegrity);
                drop(services);
                assert_eq!(health.readiness(), Readiness::NotReady);
                assert!(process.apply_pending_integrity_fence());
                assert_eq!(health.phase(), ProcessPhase::Fenced);
                assert!(
                    process
                        .bound_endpoints()
                        .iter()
                        .all(|endpoint| !endpoint.role().is_data())
                );
                assert!(process.services().is_none());
                let outcome = process.shutdown(ShutdownTrigger::FirstSignal);
                assert_eq!(outcome, ExitOutcome::Graceful);
                return Ok(());
            },
            4 | 5 => {
                let trigger = if action % 8 == 4 {
                    ShutdownTrigger::SecondSignal
                } else {
                    ShutdownTrigger::DeadlineExpired
                };
                assert_eq!(process.shutdown(trigger), ExitOutcome::Forced);
                assert_eq!(health.phase(), ProcessPhase::Stopped);
                assert_eq!(health.liveness(), Liveness::Dead);
                return Ok(());
            },
            _ => {
                let mut draining = process.begin_shutdown();
                assert_eq!(health.phase(), ProcessPhase::Draining);
                assert_eq!(health.readiness(), Readiness::NotReady);
                assert!(draining.poll().map_err(describe)?);
                assert_eq!(
                    draining.finish(ShutdownTrigger::FirstSignal),
                    ExitOutcome::Graceful
                );
                assert_eq!(health.liveness(), Liveness::Dead);
                return Ok(());
            },
        }
    }
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Graceful
    );
    Ok(())
}

struct Recovery {
    remaining: Cell<u8>,
    attempts: Cell<u8>,
}
impl RecoveryAttemptHost for Recovery {
    fn prerequisite_status(&self) -> Result<(), BootstrapFailureCode> {
        let remaining = self.remaining.get();
        if remaining == 0 {
            Ok(())
        } else {
            self.remaining.set(remaining - 1);
            Err(BootstrapFailureCode::KeyCustodyUnavailable)
        }
    }
    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision {
        self.attempts.set(self.attempts.get() + 1);
        assert_eq!(attempt.number(), self.attempts.get());
        assert_eq!(
            attempt.failure(),
            BootstrapFailureCode::KeyCustodyUnavailable
        );
        RecoveryDecision::Retry
    }
}

struct Host {
    role: TaskRole,
    startup_fault: u8,
    failure: Arc<AtomicU8>,
}
impl ListenerFactory for Host {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure> {
        let endpoint = if request.role() == ListenerRole::Control {
            BoundEndpoint::control(std::env::temp_dir().join("positron-lifecycle-fuzz.sock"))?
        } else {
            BoundEndpoint::tcp(
                request.role(),
                std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
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
        if self.startup_fault == 1 && role == self.role {
            return Err(TaskFailure::RegistrationUnavailable);
        }
        Ok(Box::new(Task {
            selected: role == self.role,
            spawn_fails: self.startup_fault == 2,
            failure: Arc::clone(&self.failure),
        }))
    }
}
struct Task {
    selected: bool,
    spawn_fails: bool,
    failure: Arc<AtomicU8>,
}
impl RegisteredTask for Task {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        _: HealthState,
        _: Option<ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        if self.selected && self.spawn_fails {
            return Err(TaskFailure::SpawnUnavailable);
        }
        Ok(Box::new(Running {
            selected: self.selected,
            failure: Arc::clone(&self.failure),
            cancellation,
        }))
    }
}
struct Running {
    selected: bool,
    failure: Arc<AtomicU8>,
    cancellation: TaskCancellation,
}
impl RunningTask for Running {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        if self.cancellation.is_cancelled() {
            return Ok(Some(TaskJoinOutcome::Joined));
        }
        match (self.selected, self.failure.load(Ordering::Acquire)) {
            (true, 1) => Ok(Some(TaskJoinOutcome::Joined)),
            (true, 2) => Err(TaskFailure::JoinPanicked),
            _ => Ok(None),
        }
    }
    fn join_within(&mut self, _: Duration) -> Result<TaskJoinOutcome, TaskFailure> {
        Ok(TaskJoinOutcome::Joined)
    }
    fn abort(&mut self) -> Result<(), TaskFailure> {
        Ok(())
    }
}
