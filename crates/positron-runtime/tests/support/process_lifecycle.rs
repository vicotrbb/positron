use positron_runtime::{
    BoundEndpoint, BoundListener, ListenerFactory, ListenerFailure, ListenerRequest, ListenerRole,
    ProcessPhase, RegisteredTask, RunningTask, TaskCancellation, TaskFailure, TaskJoinOutcome,
    TaskRegistrar, TaskRole,
};
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::rc::Rc;

#[path = "process_roots.rs"]
pub mod process_roots;
pub(crate) use process_roots::TestRoots;

#[derive(Default)]
pub(crate) struct ObservingListeners {
    pub(crate) bound: RefCell<Vec<ListenerRole>>,
    pub(crate) health: RefCell<Vec<positron_runtime::HealthState>>,
    pub(crate) fail_role: Option<ListenerRole>,
    pub(crate) fail_close: Option<ListenerRole>,
    pub(crate) mismatched_role: Option<ListenerRole>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TaskEvent {
    Registered(TaskRole),
    Spawned(TaskRole),
    Joined(TaskRole, ProcessPhase, bool),
    Aborted(TaskRole, ProcessPhase, bool),
}

#[derive(Default)]
pub(crate) struct ObservingTasks {
    pub(crate) events: Rc<RefCell<Vec<TaskEvent>>>,
    pub(crate) join_limits: Rc<RefCell<Vec<std::time::Duration>>>,
    pub(crate) fail_registration: Option<TaskRole>,
    pub(crate) fail_spawn: Option<TaskRole>,
    pub(crate) fail_join: Option<TaskRole>,
    pub(crate) pending_join: Option<TaskRole>,
    pub(crate) first_join_expired: Option<TaskRole>,
    pub(crate) fail_recovery_join: Option<TaskRole>,
    pub(crate) fail_abort: Option<TaskRole>,
    pub(crate) fail_abort_also: Option<TaskRole>,
    pub(crate) fail_abort_all: bool,
    pub(crate) fail_abort_once: Option<TaskRole>,
}

impl ObservingTasks {
    #[allow(dead_code)]
    pub(crate) fn no_task_spawned(&self) -> bool {
        !self
            .events
            .borrow()
            .iter()
            .any(|event| matches!(event, TaskEvent::Spawned(_)))
    }
}

impl ListenerFactory for ObservingListeners {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure> {
        let role = request.role();
        self.bound.borrow_mut().push(role);
        self.health.borrow_mut().push(request.health());
        if self.fail_role == Some(role) {
            return Err(ListenerFailure::BindUnavailable);
        }
        let endpoint = if role == ListenerRole::Control {
            if self.mismatched_role == Some(role) {
                BoundEndpoint::tcp(
                    ListenerRole::Api,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_401)),
                )?
            } else {
                BoundEndpoint::control(PathBuf::from("/tmp/positron-test-control.sock"))?
            }
        } else {
            BoundEndpoint::tcp(
                if self.mismatched_role == Some(role) {
                    ListenerRole::Api
                } else {
                    role
                },
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, test_port(role))),
            )?
        };
        Ok(Box::new(ObservedListener {
            endpoint,
            fail_close: self.fail_close == Some(role),
        }))
    }
}

struct ObservedListener {
    endpoint: BoundEndpoint,
    fail_close: bool,
}

impl BoundListener for ObservedListener {
    fn endpoint(&self) -> &BoundEndpoint {
        &self.endpoint
    }

    fn close(&mut self) -> Result<(), ListenerFailure> {
        if self.fail_close {
            Err(ListenerFailure::BindUnavailable)
        } else {
            Ok(())
        }
    }
}

impl TaskRegistrar for ObservingTasks {
    fn register(&self, role: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
        self.events.borrow_mut().push(TaskEvent::Registered(role));
        if self.fail_registration == Some(role) {
            return Err(TaskFailure::RegistrationUnavailable);
        }
        Ok(Box::new(ObservedRegisteredTask {
            role,
            events: Rc::clone(&self.events),
            join_limits: Rc::clone(&self.join_limits),
            fail_spawn: self.fail_spawn == Some(role),
            fail_join: self.fail_join == Some(role),
            pending_join: self.pending_join == Some(role),
            first_join_expired: self.first_join_expired == Some(role),
            fail_recovery_join: self.fail_recovery_join == Some(role),
            fail_abort: self.fail_abort_all
                || self.fail_abort == Some(role)
                || self.fail_abort_also == Some(role),
            fail_abort_once: self.fail_abort_once == Some(role),
        }))
    }
}

struct ObservedRegisteredTask {
    role: TaskRole,
    events: Rc<RefCell<Vec<TaskEvent>>>,
    join_limits: Rc<RefCell<Vec<std::time::Duration>>>,
    fail_spawn: bool,
    fail_join: bool,
    pending_join: bool,
    first_join_expired: bool,
    fail_recovery_join: bool,
    fail_abort: bool,
    fail_abort_once: bool,
}

impl RegisteredTask for ObservedRegisteredTask {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        health: positron_runtime::HealthState,
        _services: Option<positron_runtime::ServiceHandle>,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        self.events.borrow_mut().push(TaskEvent::Spawned(self.role));
        if self.fail_spawn {
            return Err(TaskFailure::SpawnUnavailable);
        }
        Ok(Box::new(ObservedRunningTask {
            role: self.role,
            events: Rc::clone(&self.events),
            join_limits: Rc::clone(&self.join_limits),
            cancellation,
            health,
            fail_join: self.fail_join,
            pending_join: self.pending_join,
            first_join_expired: self.first_join_expired,
            fail_recovery_join: self.fail_recovery_join,
            fail_abort: self.fail_abort,
            fail_abort_once: self.fail_abort_once,
            abort_attempts: 0,
        }))
    }
}

struct ObservedRunningTask {
    role: TaskRole,
    events: Rc<RefCell<Vec<TaskEvent>>>,
    join_limits: Rc<RefCell<Vec<std::time::Duration>>>,
    cancellation: TaskCancellation,
    health: positron_runtime::HealthState,
    fail_join: bool,
    pending_join: bool,
    first_join_expired: bool,
    fail_recovery_join: bool,
    fail_abort: bool,
    fail_abort_once: bool,
    abort_attempts: u8,
}

impl RunningTask for ObservedRunningTask {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        if self.health.phase() == ProcessPhase::Recovering {
            if self.fail_recovery_join {
                Err(TaskFailure::JoinUnavailable)
            } else {
                Ok(None)
            }
        } else if self.pending_join
            || (self.health.phase() == ProcessPhase::Serving && !self.fail_join)
        {
            Ok(None)
        } else {
            self.join_within(std::time::Duration::ZERO).map(Some)
        }
    }

    fn join_within(
        &mut self,
        remaining: std::time::Duration,
    ) -> Result<TaskJoinOutcome, TaskFailure> {
        self.join_limits.borrow_mut().push(remaining);
        self.events.borrow_mut().push(TaskEvent::Joined(
            self.role,
            self.health.phase(),
            self.cancellation.is_cancelled(),
        ));
        if std::mem::take(&mut self.first_join_expired) {
            return Ok(TaskJoinOutcome::DeadlineExpired);
        }
        if self.fail_join {
            Err(TaskFailure::JoinUnavailable)
        } else {
            Ok(TaskJoinOutcome::Joined)
        }
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        self.abort_attempts = self.abort_attempts.saturating_add(1);
        self.events.borrow_mut().push(TaskEvent::Aborted(
            self.role,
            self.health.phase(),
            self.cancellation.is_cancelled(),
        ));
        if self.fail_abort || (self.fail_abort_once && self.abort_attempts == 1) {
            Err(TaskFailure::AbortUnavailable)
        } else {
            Ok(())
        }
    }
}

const fn test_port(role: ListenerRole) -> u16 {
    match role {
        ListenerRole::Control => 42_399,
        ListenerRole::Operations => 42_400,
        ListenerRole::Api => 42_401,
        ListenerRole::OtlpGrpc => 42_402,
        ListenerRole::OtlpHttp => 42_403,
        ListenerRole::LokiPush => 42_404,
    }
}
