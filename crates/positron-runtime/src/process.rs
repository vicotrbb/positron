use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use positron_config::{
    ConfigurationDiffPlan, ConfigurationDrift, ConfigurationDriftDisposition,
    EffectiveConfiguration, NetworkListenerRole, NetworkTransport,
};
use positron_kernel::OwnedPrimaryDataVolume;
use sha2::{Digest, Sha256};

use crate::health::ProcessState;
#[cfg(test)]
#[path = "process/candidate_cleanup_tests.rs"]
mod candidate_cleanup_tests;
use crate::{
    BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BoundEndpoint, BoundListener,
    CatalogConfigurationPublication, ConfigurationReloadOutcome, ConfigurationRuntimeFailure,
    HealthState, InitializationPlan, InstanceBootstrap, IntegrityFenceReason, ListenerFactory,
    ListenerGenerationFactory, ListenerRequest, ListenerRole, ProcessPhase, RegisteredTask,
    RunningTask, RuntimeConfiguration, ServiceHandle, TaskCancellation, TaskFailure,
    TaskJoinOutcome, TaskRegistrar, TaskRole,
};

/// Whether serving may initialize a provably empty instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationMode {
    ExistingOnly,
    InitializeIfEmpty,
}

/// A sanitized crash record could not be created through the current kernel
/// authority. The error deliberately contains no storage path or crash data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashRecordPersistenceFailure {
    Unavailable,
    Full,
    Invalid,
}

impl From<positron_kernel::CrashRecordFailure> for CrashRecordPersistenceFailure {
    fn from(value: positron_kernel::CrashRecordFailure) -> Self {
        match value {
            positron_kernel::CrashRecordFailure::Unavailable => Self::Unavailable,
            positron_kernel::CrashRecordFailure::Full => Self::Full,
            positron_kernel::CrashRecordFailure::Invalid => Self::Invalid,
        }
    }
}

/// A configuration-file-only plaintext API selection carried from the
/// composition root into startup. It is deliberately separate from public
/// administration and has no actor or credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicPlaintextApiStartupIntent {
    role: ListenerRole,
    listener_target: SocketAddr,
}

impl PublicPlaintextApiStartupIntent {
    #[must_use]
    pub const fn configuration_file(api_bind_address: SocketAddr) -> Self {
        Self::configuration_file_listener(ListenerRole::Api, api_bind_address)
    }

    #[must_use]
    pub const fn configuration_file_listener(
        role: ListenerRole,
        listener_target: SocketAddr,
    ) -> Self {
        Self {
            role,
            listener_target,
        }
    }

    #[must_use]
    pub const fn role(self) -> ListenerRole {
        self.role
    }

    #[must_use]
    pub const fn listener_target(self) -> SocketAddr {
        self.listener_target
    }

    #[must_use]
    pub const fn api_bind_address(self) -> SocketAddr {
        self.listener_target
    }
}

/// Fully typed inputs needed to establish the M1 database authorities.
pub struct ServeConfiguration {
    paths: BootstrapPaths,
    initialization: InitializationMode,
    max_registered_tenants: u16,
    plaintext_listener_intents: Vec<PublicPlaintextApiStartupIntent>,
    export_destination_resolver: Option<Arc<dyn positron_query::ExportDestinationResolver>>,
    effective_configuration: Option<Arc<EffectiveConfiguration>>,
    admission_group_planner: Option<Arc<dyn positron_ingest::AdmissionGroupPlanner>>,
}

impl ServeConfiguration {
    #[must_use]
    pub const fn new(paths: BootstrapPaths, initialization: InitializationMode) -> Self {
        Self {
            paths,
            initialization,
            max_registered_tenants: 2,
            plaintext_listener_intents: Vec::new(),
            export_destination_resolver: None,
            effective_configuration: None,
            admission_group_planner: None,
        }
    }

    /// Sets the configured ceiling for simultaneously registered governor tenant quotas.
    #[must_use]
    pub const fn with_max_registered_tenants(mut self, max_registered_tenants: u16) -> Self {
        self.max_registered_tenants = max_registered_tenants;
        self
    }

    #[must_use]
    pub fn with_admission_group_planner(
        mut self,
        planner: Arc<dyn positron_ingest::AdmissionGroupPlanner>,
    ) -> Self {
        self.admission_group_planner = Some(planner);
        self
    }

    /// Keeps the process ready while making an explicit public plaintext API
    /// selection continuously visible through its health state.
    #[must_use]
    pub fn with_public_plaintext_api_intent(self, intent: PublicPlaintextApiStartupIntent) -> Self {
        self.with_plaintext_listener_intent(intent)
    }

    /// Carries one configuration-file plaintext opt-out into the joint
    /// startup publication path for its exact listener role.
    #[must_use]
    pub fn with_plaintext_listener_intent(
        mut self,
        intent: PublicPlaintextApiStartupIntent,
    ) -> Self {
        self.plaintext_listener_intents.push(intent);
        self
    }

    #[must_use]
    pub(crate) fn plaintext_listener_intents(&self) -> &[PublicPlaintextApiStartupIntent] {
        &self.plaintext_listener_intents
    }

    #[must_use]
    pub fn with_export_destination_resolver(
        mut self,
        resolver: Arc<dyn positron_query::ExportDestinationResolver>,
    ) -> Self {
        self.export_destination_resolver = Some(resolver);
        self
    }

    /// Passes the canonical resolved Configuration Contract to the runtime.
    #[must_use]
    pub fn with_effective_configuration(
        mut self,
        configuration: Arc<EffectiveConfiguration>,
    ) -> Self {
        self.effective_configuration = Some(configuration);
        self
    }

    pub(crate) fn drain_deadline(&self) -> std::time::Duration {
        self.effective_configuration.as_ref().map_or_else(
            || std::time::Duration::from_secs(30),
            |configuration| {
                std::time::Duration::from_secs(u64::from(configuration.shutdown_grace_seconds()))
            },
        )
    }
}

fn plaintext_listener_intents_for(
    configuration: &EffectiveConfiguration,
) -> Vec<PublicPlaintextApiStartupIntent> {
    [
        (NetworkListenerRole::Operations, ListenerRole::Operations),
        (NetworkListenerRole::Api, ListenerRole::Api),
        (NetworkListenerRole::OtlpGrpc, ListenerRole::OtlpGrpc),
        (NetworkListenerRole::OtlpHttp, ListenerRole::OtlpHttp),
        (NetworkListenerRole::LokiPush, ListenerRole::LokiPush),
    ]
    .into_iter()
    .filter_map(|(configuration_role, runtime_role)| {
        configuration
            .network_listener_profile(configuration_role)
            .filter(|profile| profile.transport() == NetworkTransport::PlaintextOptOut)
            .map(|profile| {
                PublicPlaintextApiStartupIntent::configuration_file_listener(
                    runtime_role,
                    profile.bind_address(),
                )
            })
    })
    .collect()
}

fn tls_material_listener_set(
    configuration: &EffectiveConfiguration,
) -> Result<Option<positron_governance::TlsMaterialReloadListenerSet>, ConfigurationRuntimeFailure>
{
    let bits = [
        (NetworkListenerRole::Operations, ListenerRole::Operations),
        (NetworkListenerRole::Api, ListenerRole::Api),
        (NetworkListenerRole::OtlpGrpc, ListenerRole::OtlpGrpc),
        (NetworkListenerRole::OtlpHttp, ListenerRole::OtlpHttp),
        (NetworkListenerRole::LokiPush, ListenerRole::LokiPush),
    ]
    .into_iter()
    .filter(|(configuration_role, _)| {
        configuration
            .network_listener_profile(*configuration_role)
            .is_some_and(|profile| profile.transport() != NetworkTransport::PlaintextOptOut)
    })
    .try_fold(0_u8, |bits, (_, runtime_role)| {
        positron_governance::TlsMaterialReloadListenerSet::for_role(listener_transport_audit_role(
            runtime_role,
        ))
        .map(|listener_set| bits | listener_set.bits())
        .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)
    })?;
    if bits == 0 {
        Ok(None)
    } else {
        positron_governance::TlsMaterialReloadListenerSet::new(bits)
            .map(Some)
            .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)
    }
}

fn plaintext_listener_audit_requests(
    configuration: &EffectiveConfiguration,
) -> Vec<positron_governance::ListenerTransportAuditRequest> {
    plaintext_listener_intents_for(configuration)
        .into_iter()
        .map(|intent| {
            positron_governance::ListenerTransportAuditRequest::configuration_file_listener(
                listener_transport_audit_role(intent.role()),
                intent.listener_target(),
            )
        })
        .collect()
}

const fn listener_transport_audit_role(
    role: ListenerRole,
) -> positron_governance::ListenerTransportRole {
    match role {
        ListenerRole::Control => positron_governance::ListenerTransportRole::Control,
        ListenerRole::Operations => positron_governance::ListenerTransportRole::Operations,
        ListenerRole::Api => positron_governance::ListenerTransportRole::Api,
        ListenerRole::OtlpGrpc => positron_governance::ListenerTransportRole::OtlpGrpc,
        ListenerRole::OtlpHttp => positron_governance::ListenerTransportRole::OtlpHttp,
        ListenerRole::LokiPush => positron_governance::ListenerTransportRole::LokiPush,
    }
}

impl std::fmt::Debug for ServeConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServeConfiguration")
            .field("paths", &self.paths)
            .field("initialization", &self.initialization)
            .field("max_registered_tenants", &self.max_registered_tenants)
            .field(
                "plaintext_listener_intent_count",
                &self.plaintext_listener_intents.len(),
            )
            .field(
                "admission_group_planner",
                &self.admission_group_planner.is_some(),
            )
            .field(
                "export_destination_resolver",
                &self.export_destination_resolver.is_some(),
            )
            .field(
                "effective_configuration",
                &self.effective_configuration.is_some(),
            )
            .finish()
    }
}

/// Injected host boundaries; database modules remain concrete.
pub struct HostInputs<'host> {
    listeners: &'host dyn ListenerFactory,
    tasks: &'host dyn TaskRegistrar,
    recovery: &'host dyn RecoveryAttemptHost,
}

impl<'host> HostInputs<'host> {
    #[must_use]
    pub const fn new(
        listeners: &'host dyn ListenerFactory,
        tasks: &'host dyn TaskRegistrar,
    ) -> Self {
        Self {
            listeners,
            tasks,
            recovery: &BOUNDED_RECOVERY,
        }
    }

    #[must_use]
    pub const fn with_recovery(
        listeners: &'host dyn ListenerFactory,
        tasks: &'host dyn TaskRegistrar,
        recovery: &'host dyn RecoveryAttemptHost,
    ) -> Self {
        Self {
            listeners,
            tasks,
            recovery,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryAttempt {
    number: u8,
    failure: BootstrapFailureCode,
    ownership_held: bool,
}

impl RecoveryAttempt {
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(number: u8) -> Self {
        Self {
            number,
            failure: BootstrapFailureCode::StorageUnavailable,
            ownership_held: false,
        }
    }

    #[must_use]
    pub const fn number(self) -> u8 {
        self.number
    }

    #[must_use]
    pub const fn failure(self) -> BootstrapFailureCode {
        self.failure
    }

    #[must_use]
    pub const fn ownership_held(self) -> bool {
        self.ownership_held
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    Retry,
    Exhausted,
    Terminate(ShutdownTrigger),
}

pub trait RecoveryAttemptHost {
    fn prerequisite_status(&self) -> Result<(), BootstrapFailureCode> {
        Ok(())
    }

    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision;
}

struct BoundedRecovery;
static BOUNDED_RECOVERY: BoundedRecovery = BoundedRecovery;

impl RecoveryAttemptHost for BoundedRecovery {
    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision {
        std::thread::sleep(std::time::Duration::from_millis(
            10_u64.saturating_mul(u64::from(attempt.number)).min(100)
                + u64::from(std::process::id() % 17),
        ));
        RecoveryDecision::Retry
    }
}

/// The one stable process outcome mapped by native and managed launchers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitOutcome {
    Graceful,
    Forced,
    InvalidConfiguration,
    StartupUnavailable(BootstrapFailureCode),
    ListenerUnavailable(ListenerRole),
    TaskUnavailable(TaskRole),
    InternalCleanupFailure(CleanupFailure),
    Fenced,
}

impl std::fmt::Display for ExitOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Positron process exited")
    }
}

impl std::error::Error for ExitOutcome {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownTrigger {
    FirstSignal,
    SecondSignal,
    DeadlineExpired,
}

/// Owns all listeners, kernel authority, key custody, and process phase.
pub struct RunningProcess {
    state: ProcessState,
    listeners: Mutex<Vec<Box<dyn BoundListener>>>,
    listener_generation_factory: Option<Arc<dyn ListenerGenerationFactory>>,
    reload_lock: Mutex<()>,
    tasks: Mutex<RunningTasks>,
    retired_tasks: Mutex<RunningTasks>,
    listener_task_cancellations: Mutex<Vec<TaskCancellation>>,
    cancellation: TaskCancellation,
    instance: Option<Arc<crate::InitializedInstance>>,
    fenced_volume: Option<OwnedPrimaryDataVolume>,
    services: Option<ServiceHandle>,
    configuration: Option<Arc<RuntimeConfiguration>>,
    configuration_publication: Option<CatalogConfigurationPublication>,
    cleanup: CleanupAccumulator,
    drain_deadline: std::time::Duration,
    next_resource_observation: std::time::Instant,
    terminal_cleanup_complete: bool,
}

/// A process that has stopped data admission and awaits one terminal trigger.
pub struct DrainingProcess(RunningProcess, std::time::Instant);

/// Closed crash evidence available only while the runtime still owns its
/// instance. It deliberately exposes no catalog contents or operation data.
#[derive(Clone, Copy)]
pub struct CrashInspection {
    catalog_generation: Option<u64>,
}
impl CrashInspection {
    #[must_use]
    pub const fn catalog_generation(self) -> Option<u64> {
        self.catalog_generation
    }
}

type RunningTasks = Vec<(TaskRole, Box<dyn RunningTask>)>;

fn critical_task_failure(tasks: &mut RunningTasks) -> Option<TaskRole> {
    tasks
        .iter_mut()
        .find_map(|(role, task)| match task.poll_join() {
            Ok(None) => None,
            Ok(Some(_)) | Err(_) => Some(*role),
        })
}

mod cleanup;
use cleanup::CleanupAccumulator;
pub use cleanup::{CleanupFailure, CleanupPrimary, CleanupRole};

impl std::fmt::Debug for RunningProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningProcess")
            .field("phase", &self.state.health().phase())
            .field("listener_count", &self.listeners().len())
            .field("task_count", &self.tasks().len())
            .finish_non_exhaustive()
    }
}

impl RunningProcess {
    fn listeners(&self) -> MutexGuard<'_, Vec<Box<dyn BoundListener>>> {
        match self.listeners.lock() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn reload_lock(&self) -> MutexGuard<'_, ()> {
        match self.reload_lock.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn tasks(&self) -> MutexGuard<'_, RunningTasks> {
        match self.tasks.lock() {
            Ok(tasks) => tasks,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn cancel_listener_tasks(&self) {
        let cancellations = match self.listener_task_cancellations.lock() {
            Ok(cancellations) => cancellations,
            Err(poisoned) => poisoned.into_inner(),
        };
        for cancellation in &*cancellations {
            cancellation.cancel();
        }
    }

    fn take_listeners(&self) -> Vec<Box<dyn BoundListener>> {
        let mut listeners = self.listeners();
        let taken = std::mem::take(&mut *listeners);
        self.state.replace_bound_listener_roles(0);
        taken
    }

    #[must_use]
    pub fn health(&self) -> HealthState {
        self.state.health()
    }

    /// Reconciles critical workers and pending safety findings at their sole
    /// owner. A worker that finishes while admission is open is a runtime
    /// failure, even when its thread returned successfully.
    pub fn poll(&mut self) -> Result<(), ExitOutcome> {
        self.apply_pending_integrity_fence();
        let has_retirees = !self
            .retired_tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        if self.state.health().phase() == ProcessPhase::Fenced && has_retirees {
            self.reconcile_retired_tasks();
        }
        let failed_role = {
            let mut tasks = self.tasks();
            critical_task_failure(&mut tasks)
        };
        if let Some(role) = failed_role {
            self.state.fail_critical_worker();
            let failure = ExitOutcome::TaskUnavailable(role);
            self.cleanup.set_primary(failure);
            return Err(failure);
        }
        if std::time::Instant::now() >= self.next_resource_observation {
            self.next_resource_observation =
                std::time::Instant::now() + std::time::Duration::from_secs(1);
            if let Some(instance) = self.instance.as_ref() {
                match instance._authority.observe_disk() {
                    Ok(_) => self.state.record_dependency_status(None),
                    Err(
                        positron_kernel::GovernorFailure::ObservedVolumeMismatch
                        | positron_kernel::GovernorFailure::InternalFenced,
                    ) => {
                        self.apply_integrity_fence(IntegrityFenceReason::UnreliableOwnership);
                    },
                    Err(positron_kernel::GovernorFailure::GovernorContended { .. }) => {
                        // Control contention defers this sample; it does not
                        // invalidate the previous verified dependency state.
                        self.state.record_resource_observation_deferred();
                    },
                    Err(_) => self
                        .state
                        .record_dependency_status(Some(BootstrapFailureCode::ResourceUnavailable)),
                }
            }
        }
        Ok(())
    }

    /// Returns only the stable crash context available while this process
    /// still owns the live instance. It never exposes catalog contents,
    /// operation state, or mutable authority.
    #[must_use]
    pub fn crash_inspection(&self) -> CrashInspection {
        CrashInspection {
            catalog_generation: self
                .instance
                .as_ref()
                .map(|instance| instance.catalog_generation()),
        }
    }

    /// Persists only closed, sanitized crash evidence through the Storage
    /// Kernel while this process still owns its initialized instance.
    pub fn persist_crash_record(
        &self,
        phase: &'static str,
        finding_code: &'static str,
        component: &'static str,
    ) -> Result<(), CrashRecordPersistenceFailure> {
        let instance = self
            .instance
            .as_ref()
            .ok_or(CrashRecordPersistenceFailure::Unavailable)?;
        let record = positron_kernel::CrashRecord::new(phase, finding_code, component)
            .map_err(CrashRecordPersistenceFailure::from)?
            .with_backtrace(&std::backtrace::Backtrace::capture());
        let record = match self.crash_inspection().catalog_generation() {
            Some(generation) => record.with_catalog_generation(generation),
            None => record,
        };
        instance
            .crash_records()
            .map_err(|_| CrashRecordPersistenceFailure::Unavailable)?
            .persist(&record)
            .map_err(CrashRecordPersistenceFailure::from)
    }

    #[must_use]
    pub fn bound_endpoints(&self) -> Vec<BoundEndpoint> {
        self.listeners()
            .iter()
            .map(|listener| listener.endpoint().clone())
            .collect()
    }

    #[must_use]
    pub fn services(&self) -> Option<ServiceHandle> {
        self.services.clone()
    }

    /// Applies one pending integrity-fence request at the sole owner of
    /// listeners, tasks, key custody, and mutable volume authority.
    ///
    /// The request is intentionally one-way and idempotent: verification code
    /// can only request fencing; it cannot partially tear down process state.
    pub fn apply_pending_integrity_fence(&mut self) -> bool {
        let Some(reason) = self.state.health().pending_integrity_fence_request() else {
            return false;
        };
        self.apply_integrity_fence(reason);
        true
    }

    fn apply_integrity_fence(&mut self, reason: IntegrityFenceReason) {
        self.state.health().record_integrity_fence(reason);

        let (mut retired_listeners, retained_listeners) = {
            let listeners = self
                .listeners
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(listeners)
                .into_iter()
                .partition(|listener| listener.endpoint().role().is_data())
        };
        *self
            .listeners
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = retained_listeners;
        self.state.replace_bound_listener_roles(listener_roles(
            self.listeners
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        ));
        let (mut retired_tasks, retained_tasks): (RunningTasks, RunningTasks) = self
            .tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
            .partition(|(role, _)| {
                matches!(
                    role,
                    TaskRole::Api
                        | TaskRole::OtlpGrpc
                        | TaskRole::OtlpHttp
                        | TaskRole::LokiPush
                        | TaskRole::Maintenance
                )
            });
        *self
            .tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = retained_tasks;

        self.cleanup.cleanup_listeners(&mut retired_listeners);
        let (mut retired_maintenance, mut retired_data): (RunningTasks, RunningTasks) =
            retired_tasks
                .drain(..)
                .partition(|(role, _)| *role == TaskRole::Maintenance);
        let deadline = std::time::Instant::now() + self.drain_deadline;
        // Maintenance has no listener whose admission closure can wake it. Its
        // task-local cancellation does not affect retained Control or
        // Operations, so retire it before waiting for the network tasks.
        let maintenance_failed = abort_retired_tasks(&mut retired_maintenance, deadline).is_err();
        let data_failed = join_retired_tasks_until(&mut retired_data, deadline).is_err()
            && abort_retired_tasks(&mut retired_data, deadline).is_err();
        if maintenance_failed || data_failed {
            self.cleanup.set_primary(ExitOutcome::Fenced);
        }
        if self
            .instance
            .as_ref()
            .is_some_and(|instance| instance.begin_shutdown().is_err())
        {
            self.cleanup.set_primary(ExitOutcome::Fenced);
        }
        self.retain_retired_tasks(&mut retired_maintenance);
        self.retain_retired_tasks(&mut retired_data);
        self.services.take();
        // A fenced process has retired its active Configuration generation.
        // Keeping its publication would retain the just-shut-down instance,
        // causing restricted inspection to read through stale authority rather
        // than reopen the current durable owner-local view.
        self.configuration_publication.take();
        self.configuration.take();
        self.reconcile_retired_tasks();
    }

    fn retain_retired_tasks(&self, tasks: &mut RunningTasks) {
        self.retired_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .append(tasks);
    }

    fn reconcile_retired_tasks(&mut self) {
        let tasks = self
            .retired_tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Reconciliation does not restart the original retirement deadline.
        // Native abort is bounded; retain handles until it or a join confirms
        // termination, and avoid aborting an already joined worker.
        tasks.retain_mut(|(_, task)| {
            if matches!(task.poll_join(), Ok(Some(TaskJoinOutcome::Joined))) {
                return false;
            }
            let abort_failed = task.abort().is_err();
            let pending =
                abort_failed && !matches!(task.poll_join(), Ok(Some(TaskJoinOutcome::Joined)));
            if abort_failed && pending {
                self.cleanup.set_primary(ExitOutcome::Fenced);
            }
            pending
        });
        if tasks.is_empty() {
            self.instance.take();
            self.fenced_volume.take();
        }
    }

    fn absorb_retired_tasks(&mut self) {
        let retired = self
            .retired_tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .append(retired);
    }

    /// Returns the only complete Configuration generation visible to runtime
    /// consumers and authenticated inspection.
    #[must_use]
    pub fn configuration(&self) -> Option<Arc<RuntimeConfiguration>> {
        self.configuration.clone()
    }

    /// Publishes an already resolved candidate only through the joint Catalog
    /// and Governance Audit commit point.
    pub fn reload_configuration(
        &self,
        candidate: Arc<EffectiveConfiguration>,
    ) -> Result<ConfigurationReloadOutcome, ConfigurationRuntimeFailure> {
        let _reload = self.reload_lock();
        if self.state.health().phase() != ProcessPhase::Serving
            || self
                .state
                .health()
                .pending_integrity_fence_request()
                .is_some()
        {
            return Err(ConfigurationRuntimeFailure::Unavailable);
        }
        let runtime = self
            .configuration
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let publication = self
            .configuration_publication
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let observed = runtime.observed()?;
        let plan = observed.effective().semantic_diff(&candidate).plan();
        let tls_material_listener_set = tls_material_listener_set(&candidate)?;
        if !matches!(
            plan,
            ConfigurationDiffPlan::DrainThenPublish | ConfigurationDiffPlan::NoChange
        ) {
            return self.with_catalog_operation(|| runtime.reload_with(candidate, publication));
        }
        let Some(factory) = self.listener_generation_factory.as_ref() else {
            return self.with_catalog_operation(|| runtime.reload_with(candidate, publication));
        };
        let staged = match factory.stage(&candidate, self.health(), self.services()) {
            Ok(staged) => staged,
            Err(_) => {
                if plan != ConfigurationDiffPlan::NoChange {
                    self.with_catalog_operation(|| {
                        publication
                            .record_rejected_listener_staging(observed.effective(), &candidate)
                    })?;
                } else if let Some(listener_set) = tls_material_listener_set {
                    let listener_set_identity =
                        crate::configuration_catalog::configuration_digest(&candidate);
                    self.with_catalog_operation(|| {
                        publication.record_tls_material_reload(
                            listener_set,
                            positron_governance::TlsMaterialReloadOutcome::Rejected,
                            listener_set_identity,
                            Self::rejected_tls_attempt_identity(listener_set_identity),
                        )
                    })?;
                }
                return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
            },
        };
        if staged.prepare_tasks().is_err() {
            let material_identity = staged.material_identity();
            self.discard_listener_candidate(staged)?;
            if plan != ConfigurationDiffPlan::NoChange {
                self.with_catalog_operation(|| {
                    publication.record_rejected_listener_staging(observed.effective(), &candidate)
                })?;
            } else if let (Some(listener_set), Some(material_identity)) =
                (tls_material_listener_set, material_identity)
            {
                self.with_catalog_operation(|| {
                    publication.record_tls_material_reload(
                        listener_set,
                        positron_governance::TlsMaterialReloadOutcome::Rejected,
                        crate::configuration_catalog::configuration_digest(&candidate),
                        material_identity,
                    )
                })?;
            }
            return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
        }
        if plan == ConfigurationDiffPlan::NoChange
            && let Some(listener_set) = tls_material_listener_set
        {
            let publication_result = staged
                .material_identity()
                .ok_or(ConfigurationRuntimeFailure::ListenerUnavailable)
                .and_then(|material_identity| {
                    self.with_catalog_operation(|| {
                        publication.record_tls_material_reload(
                            listener_set,
                            positron_governance::TlsMaterialReloadOutcome::Applied,
                            crate::configuration_catalog::configuration_digest(&candidate),
                            material_identity,
                        )
                    })
                });
            if let Err(failure) = publication_result {
                self.discard_listener_candidate(staged)?;
                return Err(failure);
            }
        }
        let outcome = match self.with_catalog_operation(|| {
            if plan == ConfigurationDiffPlan::NoChange {
                runtime.reload_with(Arc::clone(&candidate), publication)
            } else {
                runtime.publish_staged_listener_reload(
                    Arc::clone(&candidate),
                    publication,
                    &plaintext_listener_audit_requests(&candidate),
                )
            }
        }) {
            Ok(outcome) => {
                self.state
                    .set_plaintext_listener_warnings(&plaintext_listener_intents_for(&candidate));
                outcome
            },
            Err(error) => {
                self.discard_listener_candidate(staged)?;
                return Err(error);
            },
        };
        let mut retired = {
            let mut active = self.listeners();
            std::mem::take(&mut *active)
        };
        let retired_tasks = {
            let mut active = self.tasks();
            std::mem::take(&mut *active)
        };
        // The maintenance role is process-owned: it has no listener and is
        // not controlled by a listener-generation cancellation capability.
        // Keep it active while listener roles are replaced; shutdown still
        // owns and joins it through `self.tasks`.
        let (mut retired_tasks, retained_tasks) = split_listener_tasks(retired_tasks);
        {
            let mut active = self.tasks();
            *active = retained_tasks;
        }
        let retired_cancellations = {
            let mut active = match self.listener_task_cancellations.lock() {
                Ok(cancellations) => cancellations,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *active)
        };
        let retirement_deadline = std::time::Instant::now() + self.drain_deadline;
        let close_failed = close_listeners(&mut retired).is_err();
        if close_failed {
            self.state
                .health()
                .request_integrity_fence(IntegrityFenceReason::UnreliableOwnership);
        }
        staged.open_admission();
        let (successor, mut successor_tasks, successor_cancellation) = staged.into_active();
        {
            let mut active = self.listeners();
            *active = successor;
        }
        {
            let mut active = self.tasks();
            active.append(&mut successor_tasks);
        }
        if let Some(cancellation) = successor_cancellation {
            let mut active = match self.listener_task_cancellations.lock() {
                Ok(cancellations) => cancellations,
                Err(poisoned) => poisoned.into_inner(),
            };
            active.push(cancellation);
        }
        for cancellation in retired_cancellations {
            cancellation.cancel();
        }
        if close_failed {
            if abort_retired_tasks(&mut retired_tasks, retirement_deadline).is_err() {
                self.retain_retired_tasks(&mut retired_tasks);
            }
            return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
        }
        if drain_listeners_until(&mut retired, retirement_deadline).is_err()
            || join_retired_tasks_until(&mut retired_tasks, retirement_deadline).is_err()
        {
            self.state
                .health()
                .request_integrity_fence(IntegrityFenceReason::UnreliableOwnership);
            if abort_retired_tasks(&mut retired_tasks, retirement_deadline).is_err() {
                self.retain_retired_tasks(&mut retired_tasks);
            }
            return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
        }
        Ok(outcome)
    }

    fn discard_listener_candidate(
        &self,
        candidate: crate::ListenerGeneration,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        let (result, mut unresolved) = candidate.discard_retaining();
        self.retain_retired_tasks(&mut unresolved);
        result.map_err(|_| {
            self.state
                .health()
                .request_integrity_fence(IntegrityFenceReason::UnreliableOwnership);
            ConfigurationRuntimeFailure::ListenerUnavailable
        })
    }

    fn rejected_tls_attempt_identity(listener_set_identity: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"positron/tls-material-reload/rejected-attempt/v1");
        hasher.update(listener_set_identity);
        hasher.finalize().into()
    }

    fn with_catalog_operation<T>(
        &self,
        operation: impl FnOnce() -> Result<T, ConfigurationRuntimeFailure>,
    ) -> Result<T, ConfigurationRuntimeFailure> {
        // Publication owns the Catalog writer lease only for its durable
        // transaction. Listener retirement may wait for accepted foreground
        // work, which can itself need this gate, so it must run after the
        // guard has been dropped.
        let _catalog_operation = self
            .services
            .as_ref()
            .map(|services| services.catalog_operation())
            .transpose()
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)?;
        operation()
    }

    /// Records a rejected source document while retaining the current complete
    /// runtime configuration.
    pub fn record_invalid_configuration_reload(&self) -> Result<(), ConfigurationRuntimeFailure> {
        let runtime = self
            .configuration
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let active = runtime.observed()?;
        let publication = self
            .configuration_publication
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        self.with_catalog_operation(|| publication.record_invalid(active.effective()))
    }

    /// Reconciles ordinary desired-state drift through the durable reload
    /// path. Security, storage, and identity drift are instead durably
    /// reported and immediately stop data admission.
    pub fn reconcile_configuration_drift(
        &self,
        desired: Arc<EffectiveConfiguration>,
    ) -> Result<ConfigurationDrift, ConfigurationRuntimeFailure> {
        let runtime = self
            .configuration
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        if let Some(drift) = runtime.clear_matching_desired_configuration(&desired)? {
            return Ok(drift);
        }
        let drift = runtime.drift_against(Arc::clone(&desired))?;
        match drift.disposition() {
            ConfigurationDriftDisposition::None => Ok(drift),
            ConfigurationDriftDisposition::Reconcile => {
                self.reload_configuration(desired)?;
                Ok(drift)
            },
            ConfigurationDriftDisposition::Fence => {
                let publication = self
                    .configuration_publication
                    .as_ref()
                    .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
                let drift = self.with_catalog_operation(|| {
                    runtime.record_fenced_drift_with(Arc::clone(&desired), publication)
                })?;
                self.state
                    .health()
                    .request_integrity_fence(IntegrityFenceReason::UnreliableOwnership);
                self.state.transition(ProcessPhase::Fenced);
                Ok(drift)
            },
        }
    }

    #[must_use]
    pub fn shutdown(mut self, trigger: ShutdownTrigger) -> ExitOutcome {
        if trigger != ShutdownTrigger::FirstSignal {
            return self.abort_shutdown();
        }
        self.begin_shutdown().finish(ShutdownTrigger::FirstSignal)
    }

    #[must_use]
    pub fn begin_shutdown(mut self) -> DrainingProcess {
        let deadline = std::time::Instant::now() + self.drain_deadline;
        self.absorb_retired_tasks();
        self.state.transition(ProcessPhase::Draining);
        let failed_roles = {
            let mut listeners = self.listeners();
            let mut failed_roles = Vec::new();
            listeners.retain_mut(|listener| {
                if listener.endpoint().role().is_data() {
                    if listener.close().is_err() {
                        failed_roles.push(listener.endpoint().role());
                    }
                    false
                } else {
                    true
                }
            });
            self.state
                .replace_bound_listener_roles(listener_roles(&listeners));
            failed_roles
        };
        for role in failed_roles {
            self.cleanup.record_listener(role);
        }
        if self.cleanup.has_failures() {
            self.state.transition(ProcessPhase::Stopping);
        }
        if self
            .services
            .as_ref()
            .is_some_and(|services| services.prepare_shutdown_schema_checkpoint().is_err())
        {
            self.cleanup.record_schema_checkpoint();
        }
        self.cancellation.cancel();
        self.cancel_listener_tasks();
        DrainingProcess(self, deadline)
    }
}

fn listener_roles(listeners: &[Box<dyn BoundListener>]) -> u8 {
    listeners.iter().fold(0_u8, |roles, listener| {
        roles | crate::health::listener_role_bit(listener.endpoint().role())
    })
}

fn split_listener_tasks(tasks: RunningTasks) -> (RunningTasks, RunningTasks) {
    tasks
        .into_iter()
        .partition(|(role, _)| *role != TaskRole::Maintenance)
}

fn close_listeners(listeners: &mut [Box<dyn BoundListener>]) -> Result<(), ()> {
    let mut failed = false;
    for listener in &mut *listeners {
        if listener.close().is_err() {
            failed = true;
        }
    }
    if failed { Err(()) } else { Ok(()) }
}

fn drain_listeners_until(
    listeners: &mut [Box<dyn BoundListener>],
    deadline: std::time::Instant,
) -> Result<(), ()> {
    for listener in listeners {
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return Err(());
        };
        if !listener.drain_within(remaining).map_err(|_| ())? {
            return Err(());
        }
    }
    Ok(())
}

fn join_retired_tasks_until(
    tasks: &mut RunningTasks,
    deadline: std::time::Instant,
) -> Result<(), ()> {
    let mut failed = false;
    tasks.retain_mut(|(_, task)| {
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            failed = true;
            return true;
        };
        match task.join_within(remaining) {
            Ok(TaskJoinOutcome::Joined) => false,
            Ok(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal) | Err(_) => {
                failed = true;
                true
            },
        }
    });
    if failed { Err(()) } else { Ok(()) }
}

fn abort_retired_tasks(tasks: &mut RunningTasks, deadline: std::time::Instant) -> Result<(), ()> {
    let mut failed = false;
    tasks.retain_mut(|(_, task)| {
        if task.abort().is_err() {
            failed = true;
            true
        } else {
            false
        }
    });
    if join_retired_tasks_until(tasks, deadline).is_err() {
        failed = true;
    }
    tasks.retain_mut(|(_, task)| !matches!(task.poll_join(), Ok(Some(TaskJoinOutcome::Joined))));
    if failed { Err(()) } else { Ok(()) }
}

#[cfg(test)]
mod retirement_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{RunningTasks, abort_retired_tasks};
    use crate::{RunningTask, TaskFailure, TaskJoinOutcome, TaskRole};

    struct AbortTask {
        attempts: Arc<AtomicUsize>,
        fails: bool,
    }

    impl RunningTask for AbortTask {
        fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
            Ok(Some(TaskJoinOutcome::Joined))
        }

        fn join_within(&mut self, _: std::time::Duration) -> Result<TaskJoinOutcome, TaskFailure> {
            Ok(TaskJoinOutcome::Joined)
        }

        fn abort(&mut self) -> Result<(), TaskFailure> {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            if self.fails {
                Err(TaskFailure::AbortUnavailable)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn retirement_attempts_every_task_after_an_abort_failure() {
        let failed = Arc::new(AtomicUsize::new(0));
        let succeeding = Arc::new(AtomicUsize::new(0));
        let mut tasks: RunningTasks = vec![
            (
                TaskRole::Api,
                Box::new(AbortTask {
                    attempts: Arc::clone(&failed),
                    fails: true,
                }),
            ),
            (
                TaskRole::OtlpGrpc,
                Box::new(AbortTask {
                    attempts: Arc::clone(&succeeding),
                    fails: false,
                }),
            ),
        ];

        assert_eq!(
            abort_retired_tasks(
                &mut tasks,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            ),
            Err(())
        );
        assert_eq!(failed.load(Ordering::Acquire), 1);
        assert_eq!(succeeding.load(Ordering::Acquire), 1);
    }
}

#[derive(Clone, Copy)]
enum DrainFailureSite {
    PollJoin,
    JoinWithin,
}

impl DrainFailureSite {
    const fn token(self) -> &'static str {
        match self {
            Self::PollJoin => "poll_join",
            Self::JoinWithin => "join_within",
        }
    }
}

struct DrainTaskFailureDiagnostic {
    site: DrainFailureSite,
    role: TaskRole,
    failure: TaskFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainDiagnosticDelivery {
    Delivered,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashRecordDiagnosticDelivery {
    Delivered,
    Unavailable,
}

fn preserve_crash_record_diagnostic(
    delivery: CrashRecordDiagnosticDelivery,
    primary: ExitOutcome,
) -> ExitOutcome {
    match delivery {
        CrashRecordDiagnosticDelivery::Delivered | CrashRecordDiagnosticDelivery::Unavailable => {
            primary
        },
    }
}

fn report_crash_record_persistence_failure() -> CrashRecordDiagnosticDelivery {
    let mut stderr = std::io::stderr().lock();
    report_crash_record_persistence_failure_to(&mut stderr)
}

fn report_crash_record_persistence_failure_to(
    sink: &mut impl std::io::Write,
) -> CrashRecordDiagnosticDelivery {
    match writeln!(
        sink,
        "positron: unable to persist sanitized runtime crash record"
    ) {
        Ok(()) => CrashRecordDiagnosticDelivery::Delivered,
        Err(_) => CrashRecordDiagnosticDelivery::Unavailable,
    }
}

fn preserve_drain_task_failure(
    delivery: DrainDiagnosticDelivery,
    primary: TaskFailure,
) -> TaskFailure {
    match delivery {
        DrainDiagnosticDelivery::Delivered => primary,
        // The existing task failure still drives process shutdown and its
        // bounded crash record. A closed stderr sink must not replace that
        // primary failure or skip the forced shutdown path.
        DrainDiagnosticDelivery::Unavailable => primary,
    }
}

impl std::fmt::Display for DrainTaskFailureDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "positron: runtime drain task failure site={} role={} category={}",
            self.site.token(),
            drain_task_role_token(self.role),
            drain_task_failure_token(self.failure),
        )
    }
}

const fn drain_task_role_token(role: TaskRole) -> &'static str {
    match role {
        TaskRole::Control => "control",
        TaskRole::Operations => "operations",
        TaskRole::Maintenance => "maintenance",
        TaskRole::Api => "api",
        TaskRole::OtlpGrpc => "otlp_grpc",
        TaskRole::OtlpHttp => "otlp_http",
        TaskRole::LokiPush => "loki_push",
    }
}

const fn drain_task_failure_token(failure: TaskFailure) -> &'static str {
    match failure {
        TaskFailure::RegistrationUnavailable => "registration_unavailable",
        TaskFailure::SpawnUnavailable => "spawn_unavailable",
        TaskFailure::JoinUnavailable => "join_unavailable",
        TaskFailure::JoinPanicked => "join_panicked",
        TaskFailure::AbortUnavailable => "abort_unavailable",
    }
}

fn report_drain_task_failure(
    site: DrainFailureSite,
    role: TaskRole,
    failure: TaskFailure,
) -> DrainDiagnosticDelivery {
    let mut stderr = std::io::stderr().lock();
    report_drain_task_failure_to(&mut stderr, site, role, failure)
}

fn report_drain_task_failure_to(
    sink: &mut impl std::io::Write,
    site: DrainFailureSite,
    role: TaskRole,
    failure: TaskFailure,
) -> DrainDiagnosticDelivery {
    match writeln!(
        sink,
        "{}",
        DrainTaskFailureDiagnostic {
            site,
            role,
            failure,
        }
    ) {
        Ok(()) => DrainDiagnosticDelivery::Delivered,
        Err(_) => DrainDiagnosticDelivery::Unavailable,
    }
}

#[cfg(test)]
mod drain_failure_diagnostic_tests {
    use super::{
        CrashRecordDiagnosticDelivery, DrainDiagnosticDelivery, DrainFailureSite,
        DrainTaskFailureDiagnostic, preserve_crash_record_diagnostic, preserve_drain_task_failure,
        report_crash_record_persistence_failure_to, report_drain_task_failure_to,
    };
    use crate::{TaskFailure, TaskRole};

    #[test]
    fn drain_failure_diagnostic_uses_every_closed_token() {
        let roles = [
            (TaskRole::Control, "control"),
            (TaskRole::Operations, "operations"),
            (TaskRole::Maintenance, "maintenance"),
            (TaskRole::Api, "api"),
            (TaskRole::OtlpGrpc, "otlp_grpc"),
            (TaskRole::OtlpHttp, "otlp_http"),
            (TaskRole::LokiPush, "loki_push"),
        ];
        let failures = [
            (
                TaskFailure::RegistrationUnavailable,
                "registration_unavailable",
            ),
            (TaskFailure::SpawnUnavailable, "spawn_unavailable"),
            (TaskFailure::JoinUnavailable, "join_unavailable"),
            (TaskFailure::JoinPanicked, "join_panicked"),
            (TaskFailure::AbortUnavailable, "abort_unavailable"),
        ];
        let sites = [
            (DrainFailureSite::PollJoin, "poll_join"),
            (DrainFailureSite::JoinWithin, "join_within"),
        ];

        for (site, site_token) in sites {
            for (role, role_token) in roles {
                for (failure, failure_token) in failures {
                    assert_eq!(
                        DrainTaskFailureDiagnostic {
                            site,
                            role,
                            failure,
                        }
                        .to_string(),
                        format!(
                            "positron: runtime drain task failure site={site_token} role={role_token} category={failure_token}"
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn unavailable_drain_diagnostic_preserves_the_primary_task_failure() {
        struct ClosedDiagnosticSink;

        impl std::io::Write for ClosedDiagnosticSink {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut sink = ClosedDiagnosticSink;
        let delivery = report_drain_task_failure_to(
            &mut sink,
            DrainFailureSite::JoinWithin,
            TaskRole::Maintenance,
            TaskFailure::JoinUnavailable,
        );

        assert_eq!(delivery, DrainDiagnosticDelivery::Unavailable);
        assert_eq!(
            preserve_drain_task_failure(delivery, TaskFailure::JoinUnavailable),
            TaskFailure::JoinUnavailable
        );
    }

    #[test]
    fn unavailable_crash_record_diagnostic_is_explicit_and_keeps_the_forced_path() {
        struct ClosedDiagnosticSink;

        impl std::io::Write for ClosedDiagnosticSink {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut sink = ClosedDiagnosticSink;
        assert_eq!(
            report_crash_record_persistence_failure_to(&mut sink),
            CrashRecordDiagnosticDelivery::Unavailable
        );
        assert_eq!(
            preserve_crash_record_diagnostic(
                CrashRecordDiagnosticDelivery::Unavailable,
                crate::ExitOutcome::Forced
            ),
            crate::ExitOutcome::Forced
        );
    }
}

impl DrainingProcess {
    #[must_use]
    pub fn crash_inspection(&self) -> CrashInspection {
        self.0.crash_inspection()
    }
    pub fn persist_crash_record(
        &self,
        phase: &'static str,
        finding_code: &'static str,
        component: &'static str,
    ) -> Result<(), CrashRecordPersistenceFailure> {
        self.0.persist_crash_record(phase, finding_code, component)
    }
    #[must_use]
    pub fn health(&self) -> HealthState {
        self.0.health()
    }

    pub fn poll(&mut self) -> Result<bool, TaskFailure> {
        let tasks = self
            .0
            .tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut complete = true;
        for (role, task) in &mut *tasks {
            let joined = match task.poll_join() {
                Ok(joined) => joined,
                Err(failure) => {
                    return Err(preserve_drain_task_failure(
                        report_drain_task_failure(DrainFailureSite::PollJoin, *role, failure),
                        failure,
                    ));
                },
            };
            match joined {
                Some(TaskJoinOutcome::Joined) => {},
                Some(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal) => {
                    complete = false;
                },
                None => complete = false,
            }
        }
        Ok(complete)
    }

    #[must_use]
    pub fn finish(self, trigger: ShutdownTrigger) -> ExitOutcome {
        self.finish_with_termination_probe(trigger, || false)
    }

    /// Retains the host's termination authority throughout final durable
    /// publication. Every publication boundary shares the original deadline.
    pub fn finish_with_termination_probe(
        mut self,
        trigger: ShutdownTrigger,
        mut termination_requested: impl FnMut() -> bool,
    ) -> ExitOutcome {
        if trigger != ShutdownTrigger::FirstSignal
            || std::time::Instant::now() >= self.1
            || self.0.state.health().phase() == ProcessPhase::Stopping
        {
            return self.0.abort_shutdown();
        }
        if trigger == ShutdownTrigger::FirstSignal {
            let deadline = self.1;
            let late_failure = {
                let tasks = self
                    .0
                    .tasks
                    .get_mut()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut late_failure = None;
                for (role, task) in &mut *tasks {
                    let Some(remaining) =
                        deadline.checked_duration_since(std::time::Instant::now())
                    else {
                        return self.0.abort_shutdown();
                    };
                    match task.join_within(remaining) {
                        Ok(TaskJoinOutcome::Joined) => {},
                        Ok(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal) => {
                            return self.0.abort_shutdown();
                        },
                        Err(failure) => {
                            late_failure = Some(preserve_drain_task_failure(
                                report_drain_task_failure(
                                    DrainFailureSite::JoinWithin,
                                    *role,
                                    failure,
                                ),
                                failure,
                            ));
                            break;
                        },
                    }
                }
                late_failure
            };
            if let Some(failure) = late_failure {
                let finding_code = if failure == TaskFailure::JoinPanicked {
                    "joined_task_panicked"
                } else {
                    "runtime_drain_failed"
                };
                if self
                    .persist_crash_record("draining", finding_code, "runtime")
                    .is_err()
                {
                    return preserve_crash_record_diagnostic(
                        report_crash_record_persistence_failure(),
                        self.0.abort_shutdown(),
                    );
                }
                return self.0.abort_shutdown();
            }
        }
        self.0
            .tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let mut listeners = self.0.take_listeners();
        self.0.cleanup.cleanup_listeners(&mut listeners);
        if self.0.services.as_ref().is_some_and(|services| {
            services
                .publish_prepared_shutdown_schema_checkpoint()
                .is_err()
        }) {
            self.0.cleanup.record_schema_checkpoint();
        }
        self.0.services.take();
        if self.0.cleanup.has_failures() {
            // Preserve the attempted graceful cleanup context, while its
            // typed failure prevents a success outcome or durable marker.
            self.0.cleanup.set_primary(ExitOutcome::Graceful);
            return self.0.abort_shutdown();
        }
        // Retire process-owned configuration adapters before testing whether
        // external capabilities still retain the instance authority.
        self.0.configuration_publication.take();
        self.0.configuration.take();
        let owned_instance = match self.0.instance.take() {
            Some(instance) => match Arc::try_unwrap(instance) {
                Ok(instance) => Some(instance),
                Err(instance) => {
                    self.0.instance = Some(instance);
                    self.0.cleanup.record_ownership_release();
                    return self.0.abort_shutdown();
                },
            },
            None => None,
        };
        let deadline = self.1;
        let mut cancelled = || std::time::Instant::now() >= deadline || termination_requested();
        if let Some(instance) = owned_instance.as_ref()
            && let Err(failure) = instance.publish_graceful_shutdown(&mut cancelled)
        {
            match failure {
                crate::instance_bootstrap::ShutdownPublicationFailure::Interrupted => {},
                crate::instance_bootstrap::ShutdownPublicationFailure::Publication(failure) => {
                    self.0.cleanup.record_durable_shutdown(failure.code());
                },
            }
            return self.0.abort_shutdown();
        }
        self.0.state.transition(ProcessPhase::Stopping);
        self.0.cleanup.set_primary(ExitOutcome::Graceful);
        self.0.instance.take();
        self.0.fenced_volume.take();
        self.0.services.take();
        self.0.state.transition(ProcessPhase::Stopped);
        self.0.terminal_cleanup_complete = true;
        self.0.cleanup.outcome()
    }
}

impl RunningProcess {
    fn abort_shutdown(&mut self) -> ExitOutcome {
        self.absorb_retired_tasks();
        self.state.transition(ProcessPhase::Stopping);
        self.cleanup.set_primary(ExitOutcome::Forced);
        self.cancel_listener_tasks();
        self.cleanup.cleanup_tasks(
            &self.cancellation,
            self.tasks
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut listeners = self.take_listeners();
        self.cleanup.cleanup_listeners(&mut listeners);
        self.instance.take();
        self.fenced_volume.take();
        self.services.take();
        self.state.transition(ProcessPhase::Stopped);
        self.terminal_cleanup_complete = true;
        self.cleanup.outcome()
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        if self.terminal_cleanup_complete {
            return;
        }
        self.absorb_retired_tasks();
        self.state.transition(ProcessPhase::Stopping);
        self.cancel_listener_tasks();
        self.cleanup.cleanup_tasks(
            &self.cancellation,
            self.tasks
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let listeners = match self.listeners.get_mut() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.cleanup.cleanup_listeners(listeners);
        self.instance.take();
        self.fenced_volume.take();
        self.services.take();
        self.state.transition(if self.cleanup.has_failures() {
            ProcessPhase::Fenced
        } else {
            ProcessPhase::Stopped
        });
    }
}

/// Sole owner of the runnable database lifecycle.
pub enum ApplicationRuntime {}

mod startup;

#[cfg(all(test, feature = "test-support"))]
#[path = "process/resource_observation_tests.rs"]
mod resource_observation_tests;
