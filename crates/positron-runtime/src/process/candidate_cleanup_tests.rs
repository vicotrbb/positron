use crate as positron_runtime;
use crate::{
    ApplicationRuntime, ExitOutcome, HostInputs, InitializationMode, ProcessPhase, Readiness,
    ServeConfiguration, ShutdownTrigger, TaskRole,
};
#[allow(dead_code)]
#[path = "../../tests/support/process_lifecycle.rs"]
mod lifecycle;
use lifecycle::{ObservingListeners, ObservingTasks, TestRoots};
#[test]
fn failed_candidate_cleanup_reconciles_the_owner_before_fenced_inspection()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("candidate-cleanup-fence")?;
    let listeners = CandidateHost(
        ObservingListeners::default(),
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let tasks = PendingTasks {
        released: std::rc::Rc::new(std::cell::Cell::new(false)),
        role: None,
        ordinary: ObservingTasks::default(),
    };
    let configuration = std::sync::Arc::new(positron_config::resolve(
        positron_config::ConfigurationInputs::try_new(
            None,
            positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?,
    )?);
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(std::sync::Arc::clone(&configuration)),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();
    assert_eq!(
        process
            .reload_configuration(configuration)
            .expect_err("candidate cleanup fails"),
        positron_runtime::ConfigurationRuntimeFailure::ListenerUnavailable
    );
    assert_eq!(health.readiness(), Readiness::NotReady);
    assert!(
        process.apply_pending_integrity_fence(),
        "cleanup uncertainty must reach the process owner"
    );
    assert_eq!(health.phase(), ProcessPhase::Fenced);
    assert_eq!(health.liveness(), positron_runtime::Liveness::Live);
    assert_eq!(
        health.integrity_fence_reason(),
        Some(positron_runtime::IntegrityFenceReason::UnreliableOwnership)
    );
    assert!(process.services().is_none());
    assert!(process.configuration().is_none());
    assert_eq!(
        process
            .bound_endpoints()
            .into_iter()
            .map(|endpoint| endpoint.role())
            .collect::<Vec<_>>(),
        [
            positron_runtime::ListenerRole::Control,
            positron_runtime::ListenerRole::Operations
        ]
    );
    assert!(tasks.ordinary.events.borrow().iter().any(|event| matches!(
        event,
        lifecycle::TaskEvent::Aborted(TaskRole::Maintenance, ProcessPhase::Fenced, _)
    )));
    for role in [
        TaskRole::Api,
        TaskRole::OtlpGrpc,
        TaskRole::OtlpHttp,
        TaskRole::LokiPush,
    ] {
        assert!(
            tasks
                .ordinary
                .events
                .borrow()
                .iter()
                .any(|event| matches!(event,
                    lifecycle::TaskEvent::Joined(joined, ProcessPhase::Fenced, _) if *joined == role
                )),
            "data worker {role:?} must be retired before inspection"
        );
    }
    assert!(
        roots.acquire_volume_again().is_err(),
        "unconfirmed candidate termination retains mutable ownership"
    );
    listeners
        .1
        .store(true, std::sync::atomic::Ordering::Release);
    process
        .poll()
        .map_err(|outcome| format!("candidate reconciliation failed: {outcome:?}"))?;
    assert!(roots.acquire_volume_again().is_ok());
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Fenced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

struct CandidateHost(
    ObservingListeners,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
);
impl positron_runtime::ListenerFactory for CandidateHost {
    fn bind(
        &self,
        request: positron_runtime::ListenerRequest,
    ) -> Result<Box<dyn positron_runtime::BoundListener>, positron_runtime::ListenerFailure> {
        self.0.bind(request)
    }
    fn generation_factory(
        &self,
    ) -> Option<std::sync::Arc<dyn positron_runtime::ListenerGenerationFactory>> {
        Some(std::sync::Arc::new(CandidateFactory(self.1.clone(), false)))
    }
}
struct CandidateFactory(std::sync::Arc<std::sync::atomic::AtomicBool>, bool);
impl positron_runtime::ListenerGenerationFactory for CandidateFactory {
    fn stage(
        &self,
        _: &positron_config::EffectiveConfiguration,
        health: positron_runtime::HealthState,
        _: Option<positron_runtime::ServiceHandle>,
    ) -> Result<positron_runtime::ListenerGeneration, positron_runtime::ListenerFailure> {
        use positron_runtime::{ListenerProfile, ListenerRole, ListenerTransport};
        let address = "127.0.0.1:0"
            .parse()
            .map_err(|_| positron_runtime::ListenerFailure::InvalidEndpoint)?;
        let candidate = positron_runtime::ValidatedListenerSet::new([
            ListenerProfile::control("/tmp/positron-candidate.sock".into())?,
            ListenerProfile::network(
                ListenerRole::Operations,
                address,
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::Api,
                address,
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::OtlpGrpc,
                address,
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::OtlpHttp,
                address,
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::LokiPush,
                address,
                ListenerTransport::PlaintextOptOut,
            )?,
        ])?;
        let generation = positron_runtime::ListenerGeneration::activate(
            candidate,
            &ObservingListeners::default(),
            health,
        )?
        .with_staged_tasks(
            vec![(
                TaskRole::Control,
                if self.1 {
                    Box::new(ReadyWorker) as Box<dyn crate::RunningTask>
                } else {
                    Box::new(CandidateWorker(self.0.clone()))
                },
            )],
            positron_runtime::TaskCancellation::new(),
            Box::new(CandidateActivation(self.1)),
        );
        Ok(if self.1 {
            generation.with_material_identity([7; 32])
        } else {
            generation
        })
    }
}
struct CandidateActivation(bool);
impl positron_runtime::ListenerGenerationActivation for CandidateActivation {
    fn prepare_and_wait_ready(&self) -> Result<(), positron_runtime::ListenerFailure> {
        if self.0 {
            Ok(())
        } else {
            Err(positron_runtime::ListenerFailure::BindUnavailable)
        }
    }
    fn open_admission(&self) {}
}
struct CandidateWorker(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl positron_runtime::RunningTask for CandidateWorker {
    fn poll_join(
        &mut self,
    ) -> Result<Option<positron_runtime::TaskJoinOutcome>, positron_runtime::TaskFailure> {
        Ok(self
            .0
            .load(std::sync::atomic::Ordering::Acquire)
            .then_some(crate::TaskJoinOutcome::Joined))
    }
    fn join_within(
        &mut self,
        _: std::time::Duration,
    ) -> Result<positron_runtime::TaskJoinOutcome, positron_runtime::TaskFailure> {
        Ok(self
            .poll_join()?
            .unwrap_or(crate::TaskJoinOutcome::DeadlineExpired))
    }
    fn abort(&mut self) -> Result<(), positron_runtime::TaskFailure> {
        Err(positron_runtime::TaskFailure::AbortUnavailable)
    }
}

#[test]
fn fenced_owner_retains_pending_worker_until_confirmed_termination()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("pending-fenced-worker")?;
    let released = std::rc::Rc::new(std::cell::Cell::new(false));
    let tasks = PendingTasks {
        released: released.clone(),
        role: Some(TaskRole::Api),
        ordinary: ObservingTasks::default(),
    };
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&ObservingListeners::default(), &tasks),
    )?;
    process
        .health()
        .request_integrity_fence(crate::IntegrityFenceReason::UnreliableOwnership);
    assert!(process.apply_pending_integrity_fence());
    assert!(process.services().is_none());
    assert!(
        roots.acquire_volume_again().is_err(),
        "a pending worker must remain under the owner rather than detach"
    );
    assert_eq!(process.health().phase(), ProcessPhase::Fenced);
    released.set(true);
    process
        .poll()
        .map_err(|outcome| format!("owner reconciliation failed: {outcome:?}"))?;
    assert!(
        roots.acquire_volume_again().is_ok(),
        "confirmed worker termination releases mutable ownership"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Fenced
    );
    Ok(())
}

struct PendingTasks {
    released: std::rc::Rc<std::cell::Cell<bool>>,
    role: Option<TaskRole>,
    ordinary: ObservingTasks,
}
impl crate::TaskRegistrar for PendingTasks {
    fn register(
        &self,
        role: TaskRole,
    ) -> Result<Box<dyn crate::RegisteredTask>, crate::TaskFailure> {
        if Some(role) == self.role {
            Ok(Box::new(PendingRegistration(self.released.clone())))
        } else if matches!(
            role,
            TaskRole::Control | TaskRole::Operations | TaskRole::OperationalTelemetry
        ) {
            Ok(Box::new(InspectionRegistration(
                self.ordinary.register(role)?,
            )))
        } else {
            self.ordinary.register(role)
        }
    }
}
struct InspectionRegistration(Box<dyn crate::RegisteredTask>);
impl crate::RegisteredTask for InspectionRegistration {
    fn spawn(
        self: Box<Self>,
        cancellation: crate::TaskCancellation,
        health: crate::HealthState,
        services: Option<crate::ServiceHandle>,
    ) -> Result<Box<dyn crate::RunningTask>, crate::TaskFailure> {
        Ok(Box::new(InspectionWorker(self.0.spawn(
            cancellation,
            health,
            services,
        )?)))
    }
}
struct InspectionWorker(Box<dyn crate::RunningTask>);
impl crate::RunningTask for InspectionWorker {
    fn poll_join(&mut self) -> Result<Option<crate::TaskJoinOutcome>, crate::TaskFailure> {
        Ok(None)
    }
    fn join_within(
        &mut self,
        remaining: std::time::Duration,
    ) -> Result<crate::TaskJoinOutcome, crate::TaskFailure> {
        self.0.join_within(remaining)
    }
    fn abort(&mut self) -> Result<(), crate::TaskFailure> {
        self.0.abort()
    }
}
struct PendingRegistration(std::rc::Rc<std::cell::Cell<bool>>);
impl crate::RegisteredTask for PendingRegistration {
    fn spawn(
        self: Box<Self>,
        _: crate::TaskCancellation,
        _: crate::HealthState,
        services: Option<crate::ServiceHandle>,
    ) -> Result<Box<dyn crate::RunningTask>, crate::TaskFailure> {
        Ok(Box::new(PendingWorker {
            released: self.0,
            services,
        }))
    }
}
struct PendingWorker {
    released: std::rc::Rc<std::cell::Cell<bool>>,
    services: Option<crate::ServiceHandle>,
}
impl crate::RunningTask for PendingWorker {
    fn poll_join(&mut self) -> Result<Option<crate::TaskJoinOutcome>, crate::TaskFailure> {
        if self.released.get() {
            self.services.take();
            Ok(Some(crate::TaskJoinOutcome::Joined))
        } else {
            Ok(None)
        }
    }
    fn join_within(
        &mut self,
        _: std::time::Duration,
    ) -> Result<crate::TaskJoinOutcome, crate::TaskFailure> {
        Ok(self
            .poll_join()?
            .unwrap_or(crate::TaskJoinOutcome::DeadlineExpired))
    }
    fn abort(&mut self) -> Result<(), crate::TaskFailure> {
        if self.released.get() {
            self.services.take();
            Ok(())
        } else {
            Err(crate::TaskFailure::AbortUnavailable)
        }
    }
}

struct ReadyWorker;
impl crate::RunningTask for ReadyWorker {
    fn poll_join(&mut self) -> Result<Option<crate::TaskJoinOutcome>, crate::TaskFailure> {
        Ok(None)
    }
    fn join_within(
        &mut self,
        _: std::time::Duration,
    ) -> Result<crate::TaskJoinOutcome, crate::TaskFailure> {
        Ok(crate::TaskJoinOutcome::Joined)
    }
    fn abort(&mut self) -> Result<(), crate::TaskFailure> {
        Ok(())
    }
}
struct ReplacementHost(ObservingListeners);
impl crate::ListenerFactory for ReplacementHost {
    fn bind(
        &self,
        request: crate::ListenerRequest,
    ) -> Result<Box<dyn crate::BoundListener>, crate::ListenerFailure> {
        self.0.bind(request)
    }
    fn generation_factory(&self) -> Option<std::sync::Arc<dyn crate::ListenerGenerationFactory>> {
        Some(std::sync::Arc::new(CandidateFactory(
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            true,
        )))
    }
}
#[test]
fn failed_old_control_retirement_remains_owned_until_joined()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("pending-old-control")?;
    let released = std::rc::Rc::new(std::cell::Cell::new(false));
    let tasks = PendingTasks {
        released: released.clone(),
        role: Some(TaskRole::Control),
        ordinary: ObservingTasks::default(),
    };
    let listeners = ReplacementHost(ObservingListeners {
        fail_close: Some(crate::ListenerRole::Api),
        ..ObservingListeners::default()
    });
    let configuration = std::sync::Arc::new(positron_config::resolve(
        positron_config::ConfigurationInputs::try_new(
            None,
            positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?,
    )?);
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        )
        .with_effective_configuration(configuration.clone()),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(
        process
            .reload_configuration(configuration.clone())
            .expect_err("old listener close fails"),
        crate::ConfigurationRuntimeFailure::ListenerUnavailable
    );
    assert_eq!(
        process
            .reload_configuration(configuration)
            .expect_err("pending fence rejects reload"),
        crate::ConfigurationRuntimeFailure::Unavailable,
        "a pending fence cannot accumulate another retired generation"
    );
    assert!(process.apply_pending_integrity_fence());
    assert!(
        roots.acquire_volume_again().is_err(),
        "old Control is a retiree, not the active inspection worker"
    );
    assert!(process.services().is_none());
    assert_eq!(
        process
            .bound_endpoints()
            .into_iter()
            .map(|endpoint| endpoint.role())
            .collect::<Vec<_>>(),
        [
            crate::ListenerRole::Control,
            crate::ListenerRole::Operations
        ]
    );
    released.set(true);
    process
        .poll()
        .map_err(|outcome| format!("old Control reconciliation failed: {outcome:?}"))?;
    assert!(roots.acquire_volume_again().is_ok());
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Fenced
    );
    Ok(())
}
#[test]
fn unresolved_fenced_worker_has_typed_terminal_cleanup_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("pending-terminal-worker")?;
    let tasks = PendingTasks {
        released: std::rc::Rc::new(std::cell::Cell::new(false)),
        role: Some(TaskRole::Api),
        ordinary: ObservingTasks::default(),
    };
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&ObservingListeners::default(), &tasks),
    )?;
    process
        .health()
        .request_integrity_fence(crate::IntegrityFenceReason::UnreliableOwnership);
    assert!(process.apply_pending_integrity_fence());
    assert!(roots.acquire_volume_again().is_err());
    let outcome = process.shutdown(ShutdownTrigger::SecondSignal);
    let ExitOutcome::InternalCleanupFailure(failure) = outcome else {
        return Err(
            format!("expected explicit unresolved cleanup failure, got {outcome:?}").into(),
        );
    };
    assert_eq!(failure.primary(), crate::CleanupPrimary::Fenced);
    assert_eq!(failure.first_task(), Some(TaskRole::Api));
    Ok(())
}

#[test]
fn polling_startup_fenced_inspection_retains_its_volume_until_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("startup-fenced-poll")?;
    std::fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let tasks = PendingTasks {
        released: std::rc::Rc::new(std::cell::Cell::new(false)),
        role: None,
        ordinary: ObservingTasks::default(),
    };
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&ObservingListeners::default(), &tasks),
    )?;
    assert_eq!(process.health().phase(), ProcessPhase::Fenced);
    assert!(roots.acquire_volume_again().is_err());
    process
        .poll()
        .map_err(|outcome| format!("startup inspection poll failed: {outcome:?}"))?;
    assert!(
        roots.acquire_volume_again().is_err(),
        "polling safe startup inspection must not release its retained volume"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Graceful
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}
