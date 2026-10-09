use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_kernel::{
    LifecycleClockState, MAX_LOWER_CLASS_QUEUE_DELAY_SECONDS, MaintenancePriority,
    MaintenanceTaskPhase, MaintenanceTerminalFailure, ResourceDimension, WorkClass,
};

use crate::{
    BootstrapPaths, ConfigurationObservation, ConfigurationRuntimeFailure, DoctorRuntimeFacts,
    InitializedInstance, InstanceBootstrap, ListenerRole, RuntimeConfiguration,
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

/// The closed set of non-secret integrity conditions that can require the
/// process owner to retire data-plane authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IntegrityFenceReason {
    AmbiguousIntegrity = 1,
    UnreliableOwnership = 2,
    IdentityMismatch = 3,
    KeyEnvelopeMismatch = 4,
    DurabilityAmbiguity = 5,
}

impl IntegrityFenceReason {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::AmbiguousIntegrity),
            2 => Some(Self::UnreliableOwnership),
            3 => Some(Self::IdentityMismatch),
            4 => Some(Self::KeyEnvelopeMismatch),
            5 => Some(Self::DurabilityAmbiguity),
            _ => None,
        }
    }

    #[must_use]
    pub const fn redacted_label(self) -> &'static str {
        match self {
            Self::AmbiguousIntegrity => "ambiguous_integrity",
            Self::UnreliableOwnership => "unreliable_storage_ownership",
            Self::IdentityMismatch => "instance_identity_mismatch",
            Self::KeyEnvelopeMismatch => "key_envelope_mismatch",
            Self::DurabilityAmbiguity => "durability_frontier_ambiguity",
        }
    }
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

/// The only externally relevant failures while collecting an authenticated
/// serving diagnostic. Authentication is distinct from a serving authority or
/// runtime inspection failure so Control endpoints can preserve their stable
/// HTTP status contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServingDiagnosticsFailure {
    AuthenticationRejected,
    Unavailable,
}

/// The only externally relevant failures while collecting a Fenced
/// diagnostic. The caller must distinguish a rejected bearer from the
/// unavailable durable inspection authority; neither outcome permits an
/// online key-unavailable fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FencedDiagnosticsFailure {
    AuthenticationRejected,
    Unavailable,
}

/// The process-owned operational-event ring could not be read. Its contents
/// are intentionally unavailable rather than recovered from another source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalLogFailure {
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
    checkpointed_tasks: u32,
    paused_tasks: u32,
    conflicted_tasks: u32,
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
    recovery_reserve_memory_bytes: u64,
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
    pub(crate) const fn checkpointed_tasks(self) -> u32 {
        self.checkpointed_tasks
    }
    #[must_use]
    pub(crate) const fn paused_tasks(self) -> u32 {
        self.paused_tasks
    }
    #[must_use]
    pub(crate) const fn conflicted_tasks(self) -> u32 {
        self.conflicted_tasks
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
    pub(crate) const fn recovery_reserve_memory_bytes(self) -> u64 {
        self.recovery_reserve_memory_bytes
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
    pub(crate) doctor: DoctorRuntimeFacts,
    pub(crate) bound_listener_roles: u8,
}

pub(crate) struct FencedDoctorStatus {
    pub(crate) doctor: DoctorRuntimeFacts,
    pub(crate) bound_listener_roles: u8,
    pub(crate) reason: Option<IntegrityFenceReason>,
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
    critical_worker_failed: Arc<AtomicBool>,
    dependency_unavailable: Arc<AtomicBool>,
    pending_integrity_fence: Arc<AtomicU8>,
    integrity_fence_reason: Arc<AtomicU8>,
    integrity_degraded: Arc<AtomicBool>,
    plaintext_listener_roles: Arc<AtomicU8>,
    bound_listener_roles: Arc<AtomicU8>,
    configuration: Arc<OnceLock<Arc<RuntimeConfiguration>>>,
    inspection_authority: Arc<OnceLock<Weak<InitializedInstance>>>,
    fenced_inspection: Arc<OnceLock<FencedInspection>>,
    catalog_operation: Arc<OnceLock<Weak<Mutex<()>>>>,
    operational_events: Arc<Mutex<Vec<&'static str>>>,
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
    /// Returns the bounded, allowlisted operational event snapshot owned by
    /// the process lifecycle. Event values are closed vocabulary only.
    pub fn operational_log_snapshot(&self) -> Result<String, OperationalLogFailure> {
        let events = self
            .operational_events
            .lock()
            .map_err(|_| OperationalLogFailure::Unavailable)?;
        let mut rendered = format!(
            "inspection_owner=process_lifecycle\nrecord_count={}\n",
            events.len()
        );
        for (index, event) in events.iter().enumerate() {
            rendered.push_str(&format!("record_{index}_event={event}\n"));
        }
        Ok(rendered)
    }

    fn record_operational_event(&self, event: &'static str) {
        if let Ok(mut events) = self.operational_events.lock() {
            if events.len() == 32 {
                events.remove(0);
            }
            events.push(event);
        }
    }

    /// Runs one bounded diagnostic collection against the current serving
    /// owner.  Callers receive neither key material nor an authorization
    /// cache: the bearer is attributed against the live instance immediately
    /// before collection and the opaque signer remains kernel-owned.
    pub fn with_authenticated_serving_diagnostics<T>(
        &self,
        bearer: &str,
        collect: impl FnOnce(
            &InitializedInstance,
            positron_governance::AuthorizedContext,
            Arc<RuntimeConfiguration>,
        ) -> Result<T, ()>,
    ) -> Result<T, ServingDiagnosticsFailure> {
        if self.phase() != ProcessPhase::Serving {
            return Err(ServingDiagnosticsFailure::Unavailable);
        }
        let catalog_operation = self
            .catalog_operation
            .get()
            .and_then(Weak::upgrade)
            .ok_or(ServingDiagnosticsFailure::Unavailable)?;
        let _catalog_operation = catalog_operation
            .lock()
            .map_err(|_| ServingDiagnosticsFailure::Unavailable)?;
        let authority = self
            .inspection_authority
            .get()
            .and_then(Weak::upgrade)
            .ok_or(ServingDiagnosticsFailure::Unavailable)?;
        let configuration = self
            .configuration
            .get()
            .cloned()
            .ok_or(ServingDiagnosticsFailure::Unavailable)?;
        let credential = PresentedCredential::parse(bearer)
            .map_err(|_| ServingDiagnosticsFailure::AuthenticationRejected)?;
        let actor = authority
            .attribute(
                credential,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| ServingDiagnosticsFailure::AuthenticationRejected)?;
        collect(&authority, actor, configuration)
            .map_err(|_| ServingDiagnosticsFailure::Unavailable)
    }

    /// Runs a bounded diagnostic collection through the Fenced inspection
    /// authority. The bearer is attributed for this request against either
    /// the still-current restricted owner or a newly reopened durable view;
    /// no serving configuration or previous authorization is retained.
    pub fn with_authenticated_fenced_diagnostics<T>(
        &self,
        bearer: &str,
        collect: impl FnOnce(
            &InitializedInstance,
            positron_governance::AuthorizedContext,
            DoctorRuntimeFacts,
        ) -> Result<T, ()>,
    ) -> Result<T, FencedDiagnosticsFailure> {
        if self.phase() != ProcessPhase::Fenced {
            return Err(FencedDiagnosticsFailure::Unavailable);
        }
        let inspection = self
            .fenced_inspection
            .get()
            .ok_or(FencedDiagnosticsFailure::Unavailable)?;
        if let Some(authority) = self.inspection_authority.get().and_then(Weak::upgrade) {
            let credential = PresentedCredential::parse(bearer)
                .map_err(|_| FencedDiagnosticsFailure::AuthenticationRejected)?;
            let actor = authority
                .attribute(
                    credential,
                    RequestedIntent::SystemAdministration,
                    CompatibilityHints::none(),
                )
                .map_err(|_| FencedDiagnosticsFailure::AuthenticationRejected)?;
            let facts = authority
                .doctor_runtime_facts(actor)
                .map_err(|_| FencedDiagnosticsFailure::Unavailable)?;
            return collect(&authority, actor, facts)
                .map_err(|_| FencedDiagnosticsFailure::Unavailable);
        }
        let authority = InstanceBootstrap::reopen_with_max_registered_tenants(
            &inspection.paths,
            inspection.max_registered_tenants,
        )
        .map_err(|_| FencedDiagnosticsFailure::Unavailable)?;
        let credential = PresentedCredential::parse(bearer)
            .map_err(|_| FencedDiagnosticsFailure::AuthenticationRejected)?;
        let actor = authority
            .attribute(
                credential,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| FencedDiagnosticsFailure::AuthenticationRejected)?;
        let facts = authority
            .doctor_runtime_facts(actor)
            .map_err(|_| FencedDiagnosticsFailure::Unavailable)?;
        collect(&authority, actor, facts).map_err(|_| FencedDiagnosticsFailure::Unavailable)
    }

    pub(crate) fn degrade_integrity(&self) {
        self.integrity_degraded.store(true, Ordering::Release);
    }
    /// Records an integrity or ownership ambiguity in the one process
    /// lifecycle authority so readiness cannot remain serving afterward.
    pub(crate) fn fence(&self) {
        self.phase
            .store(ProcessPhase::Fenced as u8, Ordering::Release);
        self.record_operational_event("process_fenced");
    }

    /// Records a bounded one-way request. The `RunningProcess` remains the
    /// only owner that can consume it and retire runtime authority.
    pub(crate) fn request_integrity_fence(&self, reason: IntegrityFenceReason) {
        let _ = self.pending_integrity_fence.compare_exchange(
            0,
            reason as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(crate) fn pending_integrity_fence_request(&self) -> Option<IntegrityFenceReason> {
        IntegrityFenceReason::from_byte(self.pending_integrity_fence.load(Ordering::Acquire))
    }

    pub(crate) fn record_integrity_fence(&self, reason: IntegrityFenceReason) {
        let _ = self.integrity_fence_reason.compare_exchange(
            0,
            reason as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.fence();
        self.pending_integrity_fence.store(0, Ordering::Release);
    }

    #[must_use]
    pub fn integrity_fence_reason(&self) -> Option<IntegrityFenceReason> {
        IntegrityFenceReason::from_byte(self.integrity_fence_reason.load(Ordering::Acquire))
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
            && self.pending_integrity_fence_request().is_none()
            && !self.dependency_unavailable.load(Ordering::Acquire)
    }

    fn required_resources_ready(&self) -> bool {
        let Some(inspection) = self.inspection_authority.get() else {
            // Serving is published only after runtime startup establishes all
            // authorities. Standalone phase views do not own an instance.
            return true;
        };
        let Some(authority) = inspection.upgrade() else {
            return false;
        };
        if authority.retention_time.status().state() == LifecycleClockState::ClockUncertain {
            return false;
        }
        let governor = authority.resource_governor();
        if governor.lifecycle() != positron_kernel::GovernorLifecycle::Open {
            return false;
        }
        match governor.inspect() {
            Ok(resources) => {
                resources.disk_pressure() != positron_kernel::DiskPressureState::HardPressure
                    && resources.lifecycle() == positron_kernel::GovernorLifecycle::Open
            },
            Err(positron_kernel::GovernorFailure::GovernorContended { pressure }) => {
                pressure != positron_kernel::DiskPressureState::HardPressure
                    && governor.lifecycle() == positron_kernel::GovernorLifecycle::Open
            },
            Err(_) => false,
        }
    }

    /// Reports localized immutable-data corruption while preserving the
    /// lifecycle phase that continues to govern traffic admission.
    #[must_use]
    pub fn integrity_degraded(&self) -> bool {
        self.integrity_degraded.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn readiness(&self) -> Readiness {
        if self.admits_data_or_mutation() && self.required_resources_ready() {
            Readiness::Ready
        } else {
            Readiness::NotReady
        }
    }

    #[must_use]
    pub fn liveness(&self) -> Liveness {
        if self.phase() == ProcessPhase::Stopped
            || self.critical_worker_failed.load(Ordering::Acquire)
        {
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
        if let Some(authority) = self.inspection_authority.get().and_then(Weak::upgrade) {
            return authority
                .attribute(
                    PresentedCredential::parse(bearer).map_err(|_| ())?,
                    RequestedIntent::SystemAdministration,
                    CompatibilityHints::none(),
                )
                .map(|_| ())
                .map_err(|_| ());
        }
        if self.phase() != ProcessPhase::Fenced {
            return Err(());
        }
        self.fenced_inspection.get().ok_or(())?.authorize(bearer)
    }

    pub(crate) fn set_fenced_inspection(
        &self,
        paths: BootstrapPaths,
        max_registered_tenants: u16,
    ) -> Result<(), ConfigurationRuntimeFailure> {
        self.fenced_inspection
            .set(FencedInspection {
                paths,
                max_registered_tenants,
            })
            .map_err(|_| ConfigurationRuntimeFailure::Unavailable)
    }

    /// Reopens only for the duration of a restricted inspection
    /// authorization, so Fenced keeps current durable authentication without
    /// retaining mutable runtime ownership between requests.
    fn authorize_fenced_inspection(
        paths: &BootstrapPaths,
        max_registered_tenants: u16,
        bearer: &str,
    ) -> Result<(), ()> {
        let authority =
            InstanceBootstrap::reopen_with_max_registered_tenants(paths, max_registered_tenants)
                .map_err(|_| ())?;
        authority
            .attribute(
                PresentedCredential::parse(bearer).map_err(|_| ())?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map(|_| ())
            .map_err(|_| ())
    }

    pub(crate) fn authorized_fenced_doctor_status(
        &self,
        bearer: &str,
    ) -> Result<FencedDoctorStatus, ConfigurationStatusFailure> {
        if self.phase() != ProcessPhase::Fenced {
            return Err(ConfigurationStatusFailure::Unavailable);
        }
        let doctor = self
            .with_authenticated_fenced_diagnostics(bearer, |_, _, doctor| Ok(doctor))
            .map_err(|failure| match failure {
                FencedDiagnosticsFailure::AuthenticationRejected => {
                    ConfigurationStatusFailure::AuthenticationRejected
                },
                FencedDiagnosticsFailure::Unavailable => ConfigurationStatusFailure::Unavailable,
            })?;
        Ok(FencedDoctorStatus {
            doctor,
            bound_listener_roles: self.bound_listener_roles.load(Ordering::Acquire),
            reason: self.integrity_fence_reason(),
        })
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
        let actor = authority
            .attribute(
                PresentedCredential::parse(bearer)
                    .map_err(|_| ConfigurationStatusFailure::AuthenticationRejected)?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none(),
            )
            .map_err(|_| ConfigurationStatusFailure::AuthenticationRejected)?;
        let doctor = authority
            .doctor_runtime_facts(actor)
            .map_err(|_| ConfigurationStatusFailure::Unavailable)?;
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
            checkpointed_tasks: 0,
            paused_tasks: 0,
            conflicted_tasks: 0,
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
            recovery_reserve_memory_bytes: 0,
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
                maintenance.checkpointed_tasks = maintenance
                    .checkpointed_tasks
                    .checked_add(1)
                    .ok_or(ConfigurationStatusFailure::Unavailable)?;
                maintenance.completed_inputs = maintenance
                    .completed_inputs
                    .checked_add(checkpoint.completed_inputs())
                    .ok_or(ConfigurationStatusFailure::Unavailable)?;
            }
            if status.pause_until().is_some() {
                maintenance.paused_tasks = maintenance
                    .paused_tasks
                    .checked_add(1)
                    .ok_or(ConfigurationStatusFailure::Unavailable)?;
            }
            if status.conflict_owner().is_some() {
                maintenance.conflicted_tasks = maintenance
                    .conflicted_tasks
                    .checked_add(1)
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
        maintenance.recovery_reserve_memory_bytes =
            resources.recovery_reserve_capacity(ResourceDimension::MemoryBytes);
        Ok(OperationsStatus {
            configuration: self
                .configuration_status()
                .map_err(|_| ConfigurationStatusFailure::Unavailable)?,
            maintenance,
            doctor,
            bound_listener_roles: self.bound_listener_roles.load(Ordering::Acquire),
        })
    }

    /// Renders bounded coordinator facts from the same authenticated runtime
    /// inspection path used by Operations status. This is an evidence adapter
    /// for diagnostics, not a second maintenance authority.
    pub fn authenticated_serving_maintenance_evidence(
        &self,
        bearer: &str,
    ) -> Result<String, ServingDiagnosticsFailure> {
        let status =
            self.authorized_configuration_status(bearer)
                .map_err(|failure| match failure {
                    ConfigurationStatusFailure::AuthenticationRejected => {
                        ServingDiagnosticsFailure::AuthenticationRejected
                    },
                    ConfigurationStatusFailure::Unavailable => {
                        ServingDiagnosticsFailure::Unavailable
                    },
                })?;
        let maintenance = status.maintenance;
        Ok(format!(
            "inspection_owner=maintenance_coordinator\ninspection_mode=online\nqueued={}\nrunning={}\ndeferred={}\nterminal={}\nfailed={}\nclock_uncertain={}\noldest_queued_age_seconds={}\nlower_class_queue_delay_breaches={}\nrunning_no_durable_progress_slo_breaches={}\nrunning_no_durable_progress_slo_unknown={}\ncheckpointed_tasks={}\npaused_tasks={}\nconflicted_tasks={}\ncheckpoint_completed_inputs={}\ninput_objects={}\noutstanding_reservations={}\n",
            maintenance.queued(),
            maintenance.running(),
            maintenance.deferred(),
            maintenance.terminal(),
            maintenance.failed(),
            maintenance.clock_uncertain(),
            maintenance
                .oldest_queued_age_seconds()
                .map_or_else(|| "unavailable".to_owned(), |age| age.to_string()),
            maintenance.lower_class_queue_delay_breaches(),
            maintenance.running_no_durable_progress_slo_breaches(),
            maintenance.running_no_durable_progress_slo_unknown(),
            maintenance.checkpointed_tasks(),
            maintenance.paused_tasks(),
            maintenance.conflicted_tasks(),
            maintenance.completed_inputs(),
            maintenance.input_objects(),
            maintenance.outstanding_reservations(),
        ))
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
                critical_worker_failed: Arc::new(AtomicBool::new(false)),
                dependency_unavailable: Arc::new(AtomicBool::new(false)),
                pending_integrity_fence: Arc::new(AtomicU8::new(0)),
                integrity_fence_reason: Arc::new(AtomicU8::new(0)),
                integrity_degraded: Arc::new(AtomicBool::new(false)),
                plaintext_listener_roles: Arc::new(AtomicU8::new(0)),
                bound_listener_roles: Arc::new(AtomicU8::new(0)),
                configuration: Arc::new(OnceLock::new()),
                inspection_authority: Arc::new(OnceLock::new()),
                fenced_inspection: Arc::new(OnceLock::new()),
                catalog_operation: Arc::new(OnceLock::new()),
                operational_events: Arc::new(Mutex::new(Vec::new())),
            },
        }
    }

    pub(crate) fn health(&self) -> HealthState {
        self.health.clone()
    }

    pub(crate) fn record_resource_observation_deferred(&self) {
        self.health
            .record_operational_event("resource_observation_deferred");
    }

    pub(crate) fn record_dependency_status(&self, failure: Option<crate::BootstrapFailureCode>) {
        let previously_unavailable = self
            .health
            .dependency_unavailable
            .swap(failure.is_some(), Ordering::AcqRel);
        if failure.is_none() && !previously_unavailable {
            return;
        }
        self.health.record_operational_event(match failure {
            Some(crate::BootstrapFailureCode::StorageUnavailable) => {
                "dependency_storage_unavailable"
            },
            Some(crate::BootstrapFailureCode::KeyCustodyUnavailable) => {
                "dependency_key_unavailable"
            },
            Some(crate::BootstrapFailureCode::ResourceUnavailable) => {
                "dependency_resources_unavailable"
            },
            Some(crate::BootstrapFailureCode::CatalogUnavailable) => {
                "dependency_catalog_unavailable"
            },
            Some(_) => "dependency_recovery_unavailable",
            None => "dependency_restored",
        });
    }

    pub(crate) fn fail_critical_worker(&self) {
        self.health
            .critical_worker_failed
            .store(true, Ordering::Release);
        self.transition(ProcessPhase::Stopping);
    }

    pub(crate) fn transition(&self, phase: ProcessPhase) {
        self.health.phase.store(phase as u8, Ordering::Release);
        self.health.record_operational_event(match phase {
            ProcessPhase::Starting => "process_starting",
            ProcessPhase::Recovering => "process_recovering",
            ProcessPhase::Serving => "process_serving",
            ProcessPhase::Draining => "process_draining",
            ProcessPhase::Fenced => "process_fenced",
            ProcessPhase::Stopping => "process_stopping",
            ProcessPhase::Stopped => "process_stopped",
        });
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

    pub(crate) fn record_bound_listener(&self, role: ListenerRole) {
        self.health
            .bound_listener_roles
            .fetch_or(listener_role_bit(role), Ordering::AcqRel);
    }

    pub(crate) fn replace_bound_listener_roles(&self, roles: u8) {
        self.health
            .bound_listener_roles
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

struct FencedInspection {
    paths: BootstrapPaths,
    max_registered_tenants: u16,
}

impl FencedInspection {
    fn authorize(&self, bearer: &str) -> Result<(), ()> {
        HealthState::authorize_fenced_inspection(&self.paths, self.max_registered_tenants, bearer)
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

pub(crate) const fn listener_role_bit(role: ListenerRole) -> u8 {
    match role {
        ListenerRole::Control => 1,
        ListenerRole::Operations => 1 << 1,
        ListenerRole::Api => 1 << 2,
        ListenerRole::OtlpGrpc => 1 << 3,
        ListenerRole::OtlpHttp => 1 << 4,
        ListenerRole::LokiPush => 1 << 5,
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
    fn operational_events_are_allowlisted_and_bounded_at_thirty_two_records() {
        let state = ProcessState::starting();
        for _ in 0..11 {
            state.transition(ProcessPhase::Starting);
            state.transition(ProcessPhase::Recovering);
            state.transition(ProcessPhase::Serving);
        }

        let snapshot = state
            .health()
            .operational_log_snapshot()
            .expect("process-owned event ring");
        assert!(snapshot.contains("inspection_owner=process_lifecycle"));
        assert!(snapshot.contains("record_count=32"));
        assert!(snapshot.contains("record_0_event=process_recovering"));
        assert!(snapshot.contains("record_31_event=process_serving"));
        assert!(!snapshot.contains("record_32_event="));
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
