use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{LifecycleClockState, MaintenanceTaskPhase, WorkClass};

use crate::{
    ConfigurationObservation, ConfigurationRuntimeFailure, InitializedInstance, ListenerRole,
    RuntimeConfiguration,
};

/// The one runtime phase that controls admission and shutdown behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProcessPhase {
    Starting = 0,
    Recovering = 1,
    Serving = 2,
    Draining = 3,
    Fenced = 4,
    Stopping = 5,
    Stopped = 6,
}

/// Whether data traffic can be admitted safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    Ready,
    NotReady,
}

/// Whether the process can still make progress and answer operational probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Liveness {
    Live,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigurationStatusFailure {
    AuthenticationRejected,
    Unavailable,
}

/// Bounded, aggregate maintenance facts derived from the coordinator and the
/// Resource Governor for authenticated Operations inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MaintenanceHealth {
    queued: u32,
    running: u32,
    deferred: u32,
    terminal: u32,
    failed: u32,
    clock_uncertain: bool,
    oldest_queued_age_seconds: Option<u64>,
    completed_inputs: u32,
    input_objects: u32,
    outstanding_reservations: u32,
    maximum_outstanding_reservations: u32,
    outstanding_maintenance_reservations: u32,
}

impl MaintenanceHealth {
    #[must_use]
    pub(crate) const fn queued(self) -> u32 {
        self.queued
    }
    #[must_use]
    pub(crate) const fn running(self) -> u32 {
        self.running
    }
    #[must_use]
    pub(crate) const fn deferred(self) -> u32 {
        self.deferred
    }
    #[must_use]
    pub(crate) const fn terminal(self) -> u32 {
        self.terminal
    }
    #[must_use]
    pub(crate) const fn failed(self) -> u32 {
        self.failed
    }
    #[must_use]
    pub(crate) const fn clock_uncertain(self) -> bool {
        self.clock_uncertain
    }
    #[must_use]
    pub(crate) const fn oldest_queued_age_seconds(self) -> Option<u64> {
        self.oldest_queued_age_seconds
    }
    #[must_use]
    pub(crate) const fn completed_inputs(self) -> u32 {
        self.completed_inputs
    }
    #[must_use]
    pub(crate) const fn input_objects(self) -> u32 {
        self.input_objects
    }
    #[must_use]
    pub(crate) const fn outstanding_reservations(self) -> u32 {
        self.outstanding_reservations
    }
    #[must_use]
    pub(crate) const fn maximum_outstanding_reservations(self) -> u32 {
        self.maximum_outstanding_reservations
    }
    #[must_use]
    pub(crate) const fn outstanding_maintenance_reservations(self) -> u32 {
        self.outstanding_maintenance_reservations
    }
}

pub(crate) struct OperationsStatus {
    pub(crate) configuration: Option<ConfigurationObservation>,
    pub(crate) maintenance: MaintenanceHealth,
}

/// A bounded operator-visible security condition that does not affect readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthWarning {
    /// One listener role is using the explicit plaintext transport opt-out.
    PlaintextListener(ListenerRole),
    /// Compatibility view for the public API plaintext opt-out.
    PublicPlaintextApi,
}

impl HealthWarning {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PlaintextListener(ListenerRole::Operations) => "operations_plaintext",
            Self::PlaintextListener(ListenerRole::Api) | Self::PublicPlaintextApi => {
                "public_plaintext_api"
            },
            Self::PlaintextListener(ListenerRole::OtlpGrpc) => "otlp_grpc_plaintext",
            Self::PlaintextListener(ListenerRole::OtlpHttp) => "otlp_http_plaintext",
            Self::PlaintextListener(ListenerRole::LokiPush) => "loki_push_plaintext",
            Self::PlaintextListener(ListenerRole::Control) => "control_plaintext",
        }
    }
}

/// A read-only view of the runtime's single phase authority.
#[derive(Clone)]
pub struct HealthState {
    phase: Arc<AtomicU8>,
    plaintext_listener_roles: Arc<AtomicU8>,
    configuration: Arc<OnceLock<Arc<RuntimeConfiguration>>>,
    inspection_authority: Arc<OnceLock<Weak<InitializedInstance>>>,
    catalog_operation: Arc<OnceLock<Weak<Mutex<()>>>>,
}

impl std::fmt::Debug for HealthState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HealthState")
            .field("phase", &self.phase())
            .field(
                "configuration_available",
                &self.configuration.get().is_some(),
            )
            .finish()
    }
}

impl HealthState {
    #[must_use]
    pub fn phase(&self) -> ProcessPhase {
        decode_phase(self.phase.load(Ordering::Acquire))
    }

    #[must_use]
    pub fn readiness(&self) -> Readiness {
        if self.phase() == ProcessPhase::Serving {
            Readiness::Ready
        } else {
            Readiness::NotReady
        }
    }

    #[must_use]
    pub fn liveness(&self) -> Liveness {
        if self.phase() == ProcessPhase::Stopped {
            Liveness::Dead
        } else {
            Liveness::Live
        }
    }

    /// Returns the active transport warning without changing admission readiness.
    #[must_use]
    pub fn security_warning(&self) -> Option<HealthWarning> {
        self.security_warnings().into_iter().next()
    }

    /// Returns every active, bounded plaintext transport warning.
    #[must_use]
    pub fn security_warnings(&self) -> Vec<HealthWarning> {
        let roles = self.plaintext_listener_roles.load(Ordering::Acquire);
        ListenerRole::all()
            .into_iter()
            .filter(|role| plaintext_role_bit(*role).is_some_and(|bit| roles & bit != 0))
            .map(|role| {
                if role == ListenerRole::Api {
                    HealthWarning::PublicPlaintextApi
                } else {
                    HealthWarning::PlaintextListener(role)
                }
            })
            .collect()
    }

    /// Returns the one canonical configuration observation available to
    /// authenticated Operations inspection.
    pub fn configuration_status(
        &self,
    ) -> Result<Option<ConfigurationObservation>, ConfigurationRuntimeFailure> {
        self.configuration
            .get()
            .map(|runtime| runtime.observed())
            .transpose()
    }

    /// Authorizes inspection through the immutable governance authority shared
    /// with runtime services.
    pub(crate) fn authorize_configuration_status(&self, bearer: &str) -> Result<(), ()> {
        self.inspection_authority
            .get()
            .and_then(Weak::upgrade)
            .ok_or(())?
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| ())?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map(|_| ())
            .map_err(|_| ())
    }

    pub(crate) fn authorized_configuration_status(
        &self,
        bearer: &str,
    ) -> Result<OperationsStatus, ConfigurationStatusFailure> {
        let catalog_operation = self
            .catalog_operation
            .get()
            .and_then(Weak::upgrade)
            .ok_or(ConfigurationStatusFailure::Unavailable)?;
        let _catalog_operation = catalog_operation
            .lock()
            .map_err(|_| ConfigurationStatusFailure::Unavailable)?;
        self.authorize_configuration_status(bearer)
            .map_err(|_| ConfigurationStatusFailure::AuthenticationRejected)?;
        let authority = self
            .inspection_authority
            .get()
            .and_then(Weak::upgrade)
            .ok_or(ConfigurationStatusFailure::Unavailable)?;
        let clock_uncertain =
            authority.retention_time.status().state() == LifecycleClockState::ClockUncertain;
        let now = if clock_uncertain {
            None
        } else {
            Some(
                authority
                    .retention_time
                    .governance_now_seconds()
                    .map_err(|_| ConfigurationStatusFailure::Unavailable)?,
            )
        };
        let statuses = authority
            .maintenance_coordinator()
            .statuses_with_clock_uncertainty(clock_uncertain)
            .map_err(|_| ConfigurationStatusFailure::Unavailable)?;
        let mut maintenance = MaintenanceHealth {
            queued: 0,
            running: 0,
            deferred: 0,
            terminal: 0,
            failed: 0,
            clock_uncertain,
            oldest_queued_age_seconds: None,
            completed_inputs: 0,
            input_objects: 0,
            outstanding_reservations: 0,
            maximum_outstanding_reservations: 0,
            outstanding_maintenance_reservations: 0,
        };
        for status in statuses {
            match status.phase() {
                MaintenanceTaskPhase::Queued => {
                    maintenance.queued = maintenance
                        .queued
                        .checked_add(1)
                        .ok_or(ConfigurationStatusFailure::Unavailable)?;
                    if let Some(now) = now {
                        let age = now.saturating_sub(status.submitted_at());
                        maintenance.oldest_queued_age_seconds = Some(
                            maintenance
                                .oldest_queued_age_seconds
                                .map_or(age, |oldest| oldest.max(age)),
                        );
                    }
                },
                MaintenanceTaskPhase::Running => {
                    maintenance.running = maintenance
                        .running
                        .checked_add(1)
                        .ok_or(ConfigurationStatusFailure::Unavailable)?
                },
                MaintenanceTaskPhase::Deferred => {
                    maintenance.deferred = maintenance
                        .deferred
                        .checked_add(1)
                        .ok_or(ConfigurationStatusFailure::Unavailable)?
                },
                MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed => {
                    maintenance.terminal = maintenance
                        .terminal
                        .checked_add(1)
                        .ok_or(ConfigurationStatusFailure::Unavailable)?;
                    if status.phase() == MaintenanceTaskPhase::Failed {
                        maintenance.failed = maintenance
                            .failed
                            .checked_add(1)
                            .ok_or(ConfigurationStatusFailure::Unavailable)?;
                    }
                },
            }
            maintenance.input_objects = maintenance
                .input_objects
                .checked_add(
                    u32::try_from(status.task().inputs().len())
                        .map_err(|_| ConfigurationStatusFailure::Unavailable)?,
                )
                .ok_or(ConfigurationStatusFailure::Unavailable)?;
            if let Some(checkpoint) = status.checkpoint() {
                maintenance.completed_inputs = maintenance
                    .completed_inputs
                    .checked_add(checkpoint.completed_inputs())
                    .ok_or(ConfigurationStatusFailure::Unavailable)?;
            }
        }
        let resources = authority
            .resource_governor()
            .inspect()
            .map_err(|_| ConfigurationStatusFailure::Unavailable)?;
        maintenance.outstanding_reservations = resources.outstanding_reservations();
        maintenance.maximum_outstanding_reservations = resources.maximum_outstanding_reservations();
        maintenance.outstanding_maintenance_reservations =
            resources.outstanding_for(WorkClass::OrdinaryMaintenanceBackup);
        Ok(OperationsStatus {
            configuration: self
                .configuration_status()
                .map_err(|_| ConfigurationStatusFailure::Unavailable)?,
            maintenance,
        })
    }
}

pub(crate) struct ProcessState {
    health: HealthState,
}

impl ProcessState {
    pub(crate) fn starting() -> Self {
        Self {
            health: HealthState {
                phase: Arc::new(AtomicU8::new(ProcessPhase::Starting as u8)),
                plaintext_listener_roles: Arc::new(AtomicU8::new(0)),
                configuration: Arc::new(OnceLock::new()),
                inspection_authority: Arc::new(OnceLock::new()),
                catalog_operation: Arc::new(OnceLock::new()),
            },
        }
    }

    pub(crate) fn health(&self) -> HealthState {
        self.health.clone()
    }

    pub(crate) fn transition(&self, phase: ProcessPhase) {
        self.health.phase.store(phase as u8, Ordering::Release);
    }

    pub(crate) fn set_plaintext_listener_warnings(
        &self,
        intents: &[crate::PublicPlaintextApiStartupIntent],
    ) {
        let roles = intents.iter().fold(0_u8, |roles, intent| {
            plaintext_role_bit(intent.role()).map_or(roles, |bit| roles | bit)
        });
        self.health
            .plaintext_listener_roles
            .store(roles, Ordering::Release);
    }

    pub(crate) fn set_configuration_runtime(
        &self,
        runtime: Arc<RuntimeConfiguration>,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        self.health
            .configuration
            .set(runtime)
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }

    pub(crate) fn set_inspection_authority(
        &self,
        authority: Arc<InitializedInstance>,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        self.health
            .inspection_authority
            .set(Arc::downgrade(&authority))
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }

    pub(crate) fn set_catalog_operation(
        &self,
        catalog_operation: Arc<Mutex<()>>,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        self.health
            .catalog_operation
            .set(Arc::downgrade(&catalog_operation))
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }
}

fn plaintext_role_bit(role: ListenerRole) -> Option<u8> {
    match role {
        ListenerRole::Control => None,
        ListenerRole::Operations => Some(1),
        ListenerRole::Api => Some(1 << 1),
        ListenerRole::OtlpGrpc => Some(1 << 2),
        ListenerRole::OtlpHttp => Some(1 << 3),
        ListenerRole::LokiPush => Some(1 << 4),
    }
}

fn decode_phase(value: u8) -> ProcessPhase {
    match value {
        0 => ProcessPhase::Starting,
        1 => ProcessPhase::Recovering,
        2 => ProcessPhase::Serving,
        3 => ProcessPhase::Draining,
        4 => ProcessPhase::Fenced,
        5 => ProcessPhase::Stopping,
        _ => ProcessPhase::Stopped,
    }
}
