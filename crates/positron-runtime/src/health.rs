use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{
    LifecycleClockState, MAX_LOWER_CLASS_QUEUE_DELAY_SECONDS, MaintenancePriority,
    MaintenanceTaskPhase, MaintenanceTerminalFailure, WorkClass,
};

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
    lower_class_queue_delay_breaches: u32,
    running_no_durable_progress_slo_breaches: u32,
    running_no_durable_progress_slo_unknown: u32,
    completed_inputs: u32,
    input_objects: u32,
    outstanding_reservations: u32,
    maximum_outstanding_reservations: u32,
    outstanding_maintenance_reservations: u32,
    durability_recovery_reservations: u32,
    security_lifecycle_reservations: u32,
    ingest_reservations: u32,
    interactive_query_tail_reservations: u32,
    ordinary_maintenance_backup_reservations: u32,
    failed_identity_mismatch: u32,
    failed_stale_generation: u32,
    failed_unclassified: u32,
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
    pub(crate) const fn lower_class_queue_delay_breaches(self) -> u32 {
        self.lower_class_queue_delay_breaches
    }
    #[must_use]
    pub(crate) const fn running_no_durable_progress_slo_breaches(self) -> u32 {
        self.running_no_durable_progress_slo_breaches
    }
    #[must_use]
    pub(crate) const fn running_no_durable_progress_slo_unknown(self) -> u32 {
        self.running_no_durable_progress_slo_unknown
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
    #[must_use]
    pub(crate) const fn durability_recovery_reservations(self) -> u32 {
        self.durability_recovery_reservations
    }
    #[must_use]
    pub(crate) const fn security_lifecycle_reservations(self) -> u32 {
        self.security_lifecycle_reservations
    }
    #[must_use]
    pub(crate) const fn ingest_reservations(self) -> u32 {
        self.ingest_reservations
    }
    #[must_use]
    pub(crate) const fn interactive_query_tail_reservations(self) -> u32 {
        self.interactive_query_tail_reservations
    }
    #[must_use]
    pub(crate) const fn ordinary_maintenance_backup_reservations(self) -> u32 {
        self.ordinary_maintenance_backup_reservations
    }
    #[must_use]
    pub(crate) const fn failed_identity_mismatch(self) -> u32 {
        self.failed_identity_mismatch
    }
    #[must_use]
    pub(crate) const fn failed_stale_generation(self) -> u32 {
        self.failed_stale_generation
    }
    #[must_use]
    pub(crate) const fn failed_unclassified(self) -> u32 {
        self.failed_unclassified
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
    integrity_degraded: Arc<AtomicBool>,
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
    pub(crate) fn degrade_integrity(&self) {
        self.integrity_degraded.store(true, Ordering::Release);
    }
    /// Records an integrity or ownership ambiguity in the one process
    /// lifecycle authority so readiness cannot remain serving afterward.
    pub(crate) fn fence(&self) {
        self.phase
            .store(ProcessPhase::Fenced as u8, Ordering::Release);
    }

    #[must_use]
    pub fn phase(&self) -> ProcessPhase {
        decode_phase(self.phase.load(Ordering::Acquire))
    }

    /// Whether a live data or mutation request may enter the runtime.
    ///
    /// Operations inspection remains available after fencing, but a process
    /// with ambiguous integrity or ownership evidence must not admit work that
    /// can expose or alter tenant data.
    #[must_use]
    pub(crate) fn admits_data_or_mutation(&self) -> bool {
        self.phase() == ProcessPhase::Serving
    }

    /// Reports localized immutable-data corruption while preserving the
    /// lifecycle phase that continues to govern traffic admission.
    #[must_use]
    pub fn integrity_degraded(&self) -> bool {
        self.integrity_degraded.load(Ordering::Acquire)
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
            .statuses_with_progress_slo(now, clock_uncertain)
            .map_err(|_| ConfigurationStatusFailure::Unavailable)?;
        let mut maintenance = MaintenanceHealth {
            queued: 0,
            running: 0,
            deferred: 0,
            terminal: 0,
            failed: 0,
            clock_uncertain,
            oldest_queued_age_seconds: None,
            lower_class_queue_delay_breaches: 0,
            running_no_durable_progress_slo_breaches: 0,
            running_no_durable_progress_slo_unknown: 0,
            completed_inputs: 0,
            input_objects: 0,
            outstanding_reservations: 0,
            maximum_outstanding_reservations: 0,
            outstanding_maintenance_reservations: 0,
            durability_recovery_reservations: 0,
            security_lifecycle_reservations: 0,
            ingest_reservations: 0,
            interactive_query_tail_reservations: 0,
            ordinary_maintenance_backup_reservations: 0,
            failed_identity_mismatch: 0,
            failed_stale_generation: 0,
            failed_unclassified: 0,
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
                        if lower_class_queue_delay_breached(&status, now) {
                            maintenance.lower_class_queue_delay_breaches = maintenance
                                .lower_class_queue_delay_breaches
                                .checked_add(1)
                                .ok_or(ConfigurationStatusFailure::Unavailable)?;
                        }
                    }
                },
                MaintenanceTaskPhase::Running => {
                    maintenance.running = maintenance
                        .running
                        .checked_add(1)
                        .ok_or(ConfigurationStatusFailure::Unavailable)?;
                    match status.no_durable_progress_slo_breached() {
                        Some(true) => {
                            maintenance.running_no_durable_progress_slo_breaches = maintenance
                                .running_no_durable_progress_slo_breaches
                                .checked_add(1)
                                .ok_or(ConfigurationStatusFailure::Unavailable)?;
                        },
                        Some(false) => {},
                        None => {
                            maintenance.running_no_durable_progress_slo_unknown = maintenance
                                .running_no_durable_progress_slo_unknown
                                .checked_add(1)
                                .ok_or(ConfigurationStatusFailure::Unavailable)?;
                        },
                    }
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
                        match status.terminal_failure() {
                            Some(MaintenanceTerminalFailure::IdentityMismatch) => {
                                maintenance.failed_identity_mismatch = maintenance
                                    .failed_identity_mismatch
                                    .checked_add(1)
                                    .ok_or(ConfigurationStatusFailure::Unavailable)?;
                            },
                            Some(MaintenanceTerminalFailure::StaleGeneration) => {
                                maintenance.failed_stale_generation = maintenance
                                    .failed_stale_generation
                                    .checked_add(1)
                                    .ok_or(ConfigurationStatusFailure::Unavailable)?;
                            },
                            Some(MaintenanceTerminalFailure::Unclassified) => {
                                maintenance.failed_unclassified = maintenance
                                    .failed_unclassified
                                    .checked_add(1)
                                    .ok_or(ConfigurationStatusFailure::Unavailable)?;
                            },
                            None => return Err(ConfigurationStatusFailure::Unavailable),
                        }
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
        maintenance.durability_recovery_reservations =
            resources.outstanding_for(WorkClass::DurabilityRecovery);
        maintenance.security_lifecycle_reservations =
            resources.outstanding_for(WorkClass::SecurityLifecycle);
        maintenance.ingest_reservations = resources.outstanding_for(WorkClass::Ingest);
        maintenance.interactive_query_tail_reservations =
            resources.outstanding_for(WorkClass::InteractiveQueryTail);
        maintenance.ordinary_maintenance_backup_reservations =
            resources.outstanding_for(WorkClass::OrdinaryMaintenanceBackup);
        Ok(OperationsStatus {
            configuration: self
                .configuration_status()
                .map_err(|_| ConfigurationStatusFailure::Unavailable)?,
            maintenance,
        })
    }
}

fn lower_class_queue_delay_breached(
    status: &positron_kernel::MaintenanceTaskStatus,
    now: u64,
) -> bool {
    matches!(
        status.task().priority(),
        MaintenancePriority::Ordinary | MaintenancePriority::Required
    ) && now.saturating_sub(status.submitted_at()) >= MAX_LOWER_CLASS_QUEUE_DELAY_SECONDS
}

pub(crate) struct ProcessState {
    health: HealthState,
}

impl ProcessState {
    pub(crate) fn starting() -> Self {
        Self {
            health: HealthState {
                phase: Arc::new(AtomicU8::new(ProcessPhase::Starting as u8)),
                integrity_degraded: Arc::new(AtomicBool::new(false)),
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
        6 => ProcessPhase::Stopped,
        _ => ProcessPhase::Fenced,
    }
}

#[cfg(test)]
mod tests {
    use positron_kernel::{
        MaintenanceCoordinator, MaintenanceTask, MaintenanceTaskClass, MaintenanceTaskId,
    };

    use super::{ProcessPhase, ProcessState, lower_class_queue_delay_breached};

    #[test]
    fn maintenance_integrity_failure_uses_the_canonical_process_phase() {
        let state = ProcessState::starting();
        state.transition(ProcessPhase::Serving);
        state.health().fence();
        assert_eq!(state.health().phase(), ProcessPhase::Fenced);
    }

    #[test]
    fn localized_quarantine_keeps_serving_and_reports_degraded_integrity() {
        let state = ProcessState::starting();
        state.transition(ProcessPhase::Serving);
        state.health().degrade_integrity();
        assert_eq!(state.health().phase(), ProcessPhase::Serving);
        assert_eq!(state.health().readiness(), super::Readiness::Ready);
        assert!(state.health().integrity_degraded());
    }

    #[test]
    fn queue_delay_breach_counts_only_promotable_priorities() {
        let coordinator = MaintenanceCoordinator::new();
        let required = MaintenanceTask::new(
            MaintenanceTaskId::new([0x71; 16]).expect("required identity"),
            MaintenanceTaskClass::SchemaStatistics,
        );
        let urgent = MaintenanceTask::new(
            MaintenanceTaskId::new([0x72; 16]).expect("urgent identity"),
            MaintenanceTaskClass::CatalogReclamation,
        );
        coordinator.submit_at(required, 10).expect("required task");
        coordinator.submit_at(urgent, 10).expect("urgent task");

        assert!(lower_class_queue_delay_breached(
            &coordinator
                .status(MaintenanceTaskId::new([0x71; 16]).expect("required identity"))
                .expect("required status"),
            70,
        ));
        assert!(!lower_class_queue_delay_breached(
            &coordinator
                .status(MaintenanceTaskId::new([0x72; 16]).expect("urgent identity"))
                .expect("urgent status"),
            70,
        ));
    }
}
