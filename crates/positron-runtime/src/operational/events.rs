//! Operational records contain only closed classifications and generated identifiers.

#[derive(Clone, Copy, Debug)]
pub enum MaintenanceWorkerOperation {
    StartDispatch,
    CompleteInFlight,
    IntegrityDiscovery,
    RetentionDiscovery,
}

#[derive(Clone, Copy, Debug)]
pub enum IntegrityScrubFailureStage {
    PreVerification,
    VerificationFailure,
    IncompleteInvalid,
    VerificationOutcomeFenced,
}

impl IntegrityScrubFailureStage {
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::PreVerification => "pre_verification",
            Self::VerificationFailure => "verification_failure",
            Self::IncompleteInvalid => "incomplete_invalid",
            Self::VerificationOutcomeFenced => "verification_outcome_fenced",
        }
    }
}

impl MaintenanceWorkerOperation {
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::StartDispatch => "start_dispatch",
            Self::CompleteInFlight => "complete_in_flight",
            Self::IntegrityDiscovery => "integrity_discovery",
            Self::RetentionDiscovery => "retention_discovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalReloadRejection {
    ImmutableConfiguration,
    RequiresDrain,
    RuntimeUnavailable,
    PublicationUnavailable,
    ListenerUnavailable,
    SourceRejected,
}
impl OperationalReloadRejection {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ImmutableConfiguration => "immutable_configuration",
            Self::RequiresDrain => "requires_drain",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::PublicationUnavailable => "publication_unavailable",
            Self::ListenerUnavailable => "listener_unavailable",
            Self::SourceRejected => "source_rejected",
        }
    }
}

/// Closed process diagnostics shared by serving and terminal reporting.
#[derive(Clone, Copy, Debug)]
pub enum OperationalDiagnostic {
    LocalKeyCustodyWarning,
    IndependentKeyRecoveryRequired,
    InvalidCommandLine,
    ConfigurationRejected,
    StartupFailed,
    SignalHandlingUnavailable,
    TransportSecurityWarning(positron_config::ConfigurationWarning),
    ConfigurationReloadRejected(OperationalReloadRejection),
    ConfigurationReloadAuditUnavailable,
    RuntimeCrashRecordUnavailable,
    RuntimeCleanupFailure(crate::CleanupRole),
    MaintenanceWorkerFailure(crate::ServiceFailure),
    MaintenanceOperationFailure {
        operation: MaintenanceWorkerOperation,
        task: Option<positron_kernel::MaintenanceTaskClass>,
        stage: Option<IntegrityScrubFailureStage>,
        failure: crate::ServiceFailure,
    },
    DrainTaskFailure {
        joining: bool,
        role: crate::TaskRole,
        failure: crate::TaskFailure,
    },
}
impl OperationalDiagnostic {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::LocalKeyCustodyWarning => "local_key_custody_warning",
            Self::IndependentKeyRecoveryRequired => "independent_key_recovery_required",
            Self::InvalidCommandLine => "invalid_command_line",
            Self::ConfigurationRejected => "configuration_rejected",
            Self::StartupFailed => "startup_failed",
            Self::SignalHandlingUnavailable => "signal_handling_unavailable",
            Self::TransportSecurityWarning(_) => "transport_security_warning",
            Self::ConfigurationReloadRejected(_) => "configuration_reload_rejected",
            Self::ConfigurationReloadAuditUnavailable => "configuration_reload_audit_unavailable",
            Self::RuntimeCrashRecordUnavailable => "runtime_crash_record_unavailable",
            Self::RuntimeCleanupFailure(_) => "runtime_cleanup_failure",
            Self::MaintenanceWorkerFailure(_) | Self::MaintenanceOperationFailure { .. } => {
                "maintenance_worker_failure"
            },
            Self::DrainTaskFailure { .. } => "runtime_drain_task_failure",
        }
    }
}
/// Writes one closed diagnostic without blocking on a detached output consumer.
pub fn write_operational_diagnostic(diagnostic: OperationalDiagnostic) -> std::io::Result<()> {
    crate::native_host::operational_worker::write_diagnostic(diagnostic)
}
/// Renders a diagnostic to a caller-owned sink; callers own its I/O behavior.
pub fn render_operational_diagnostic(
    sink: &mut impl std::io::Write,
    terminal: bool,
    diagnostic: OperationalDiagnostic,
) -> std::io::Result<()> {
    crate::native_host::operational_worker::emit(
        sink,
        terminal,
        OperationalEvent::Diagnostic(diagnostic),
    )
}

/// Closed operational facts; arbitrary text cannot enter the process event ring.
#[derive(Clone, Copy, Debug)]
pub(crate) enum OperationalEvent {
    Diagnostic(OperationalDiagnostic),
    QueryCompleted {
        outcome: RequestOutcome,
        duration_micros: u64,
    },
    RequestCompleted {
        role: crate::ListenerRole,
        outcome: RequestOutcome,
        request_id: u64,
        duration_micros: u64,
    },
    ProcessStarting,
    ProcessRecovering,
    ProcessServing,
    ProcessDraining,
    ProcessFenced,
    ProcessStopping,
    ProcessStopped,
    ResourceObservationDeferred,
    DependencyStorageUnavailable,
    DependencyKeyUnavailable,
    DependencyResourcesUnavailable,
    DependencyCatalogUnavailable,
    DependencyRecoveryUnavailable,
    DependencyRestored,
}
impl OperationalEvent {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Diagnostic(diagnostic) => diagnostic.name(),
            Self::QueryCompleted { .. } => "query_completed",
            Self::RequestCompleted { .. } => "request_completed",
            Self::ProcessStarting => "process_starting",
            Self::ProcessRecovering => "process_recovering",
            Self::ProcessServing => "process_serving",
            Self::ProcessDraining => "process_draining",
            Self::ProcessFenced => "process_fenced",
            Self::ProcessStopping => "process_stopping",
            Self::ProcessStopped => "process_stopped",
            Self::ResourceObservationDeferred => "resource_observation_deferred",
            Self::DependencyStorageUnavailable => "dependency_storage_unavailable",
            Self::DependencyKeyUnavailable => "dependency_key_unavailable",
            Self::DependencyResourcesUnavailable => "dependency_resources_unavailable",
            Self::DependencyCatalogUnavailable => "dependency_catalog_unavailable",
            Self::DependencyRecoveryUnavailable => "dependency_recovery_unavailable",
            Self::DependencyRestored => "dependency_restored",
        }
    }
    pub(crate) const fn severity(self) -> &'static str {
        match self {
            Self::Diagnostic(
                OperationalDiagnostic::TransportSecurityWarning(_)
                | OperationalDiagnostic::LocalKeyCustodyWarning
                | OperationalDiagnostic::IndependentKeyRecoveryRequired,
            ) => "warn",
            Self::ProcessFenced | Self::Diagnostic(_) => "error",
            Self::RequestCompleted {
                outcome: RequestOutcome::Unavailable,
                ..
            }
            | Self::QueryCompleted {
                outcome: RequestOutcome::Unavailable,
                ..
            } => "error",
            Self::ResourceObservationDeferred
            | Self::DependencyStorageUnavailable
            | Self::DependencyKeyUnavailable
            | Self::DependencyResourcesUnavailable
            | Self::DependencyCatalogUnavailable
            | Self::DependencyRecoveryUnavailable => "warn",
            _ => "info",
        }
    }
    pub(crate) fn json(self) -> serde_json::Value {
        let mut value = serde_json::json!({"event": self.name(), "severity": self.severity(), "component": "runtime"});
        if let Self::QueryCompleted {
            outcome,
            duration_micros,
        } = self
        {
            value["outcome"] = outcome.label().into();
            value["duration_micros"] = duration_micros.into();
        }
        if let Self::Diagnostic(diagnostic) = self {
            match diagnostic {
                OperationalDiagnostic::LocalKeyCustodyWarning => {
                    value["warning"] = "Filesystem key custody does not protect against theft of both the key and encrypted data; use an external key provider when available.".into();
                },
                OperationalDiagnostic::IndependentKeyRecoveryRequired => {
                    value["warning"] = "Create and verify a Recovery Bundle stored separately from both data and secrets before relying on backups.".into();
                },
                OperationalDiagnostic::ConfigurationReloadRejected(category) => {
                    value["category"] = category.label().into();
                },
                OperationalDiagnostic::TransportSecurityWarning(warning) => {
                    value["warning"] = warning.message().into();
                },
                OperationalDiagnostic::MaintenanceWorkerFailure(failure) => {
                    value["category"] = crate::services::maintenance_failure_category(failure)
                        .unwrap_or("cancelled")
                        .into();
                },
                OperationalDiagnostic::MaintenanceOperationFailure {
                    operation,
                    task,
                    stage,
                    failure,
                } => {
                    value["operation"] = operation.token().into();
                    value["category"] = crate::services::maintenance_failure_category(failure)
                        .unwrap_or("cancelled")
                        .into();
                    if let Some(task) = task {
                        value["task"] = super::metrics::MAINTENANCE_CLASSES
                            .iter()
                            .find(|(candidate, _)| *candidate == task)
                            .map_or("unknown", |(_, label)| *label)
                            .into();
                    }
                    if let Some(stage) = stage {
                        value["stage"] = stage.token().into();
                    }
                },
                OperationalDiagnostic::RuntimeCleanupFailure(role) => {
                    value["role"] = format!("{role:?}").into();
                },
                OperationalDiagnostic::DrainTaskFailure {
                    joining,
                    role,
                    failure,
                } => {
                    value["site"] = if joining { "join_within" } else { "poll_join" }.into();
                    value["role"] = crate::process::drain_task_role_token(role).into();
                    value["category"] = crate::process::drain_task_failure_token(failure).into();
                },
                _ => {},
            }
        }
        if let Self::RequestCompleted {
            role,
            outcome,
            request_id,
            duration_micros,
        } = self
        {
            value["listener"] = listener_label(role).into();
            value["outcome"] = outcome.label().into();
            value["request_id"] = request_id.into();
            value["duration_micros"] = duration_micros.into();
        }
        value
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RequestOutcome {
    Success,
    AuthenticationRejected,
    CapacityRejected,
    RequestRejected,
    Unavailable,
}
impl RequestOutcome {
    pub(crate) const ALL: [Self; 5] = [
        Self::Success,
        Self::AuthenticationRejected,
        Self::CapacityRejected,
        Self::RequestRejected,
        Self::Unavailable,
    ];
    pub(crate) const fn from_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Success,
            401 | 403 => Self::AuthenticationRejected,
            429 => Self::CapacityRejected,
            400..=499 => Self::RequestRejected,
            _ => Self::Unavailable,
        }
    }
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::CapacityRejected => "capacity_rejected",
            Self::RequestRejected => "request_rejected",
            Self::Unavailable => "unavailable",
        }
    }
    pub(super) const fn index(self) -> usize {
        match self {
            Self::Success => 0,
            Self::AuthenticationRejected => 1,
            Self::CapacityRejected => 2,
            Self::RequestRejected => 3,
            Self::Unavailable => 4,
        }
    }
}
pub(super) const REQUEST_ROLES: [crate::ListenerRole; 4] = [
    crate::ListenerRole::Api,
    crate::ListenerRole::OtlpGrpc,
    crate::ListenerRole::OtlpHttp,
    crate::ListenerRole::LokiPush,
];
pub(crate) const fn listener_label(role: crate::ListenerRole) -> &'static str {
    match role {
        crate::ListenerRole::Control => "control",
        crate::ListenerRole::Operations => "operations",
        crate::ListenerRole::Api => "api",
        crate::ListenerRole::OtlpGrpc => "otlp_grpc",
        crate::ListenerRole::OtlpHttp => "otlp_http",
        crate::ListenerRole::LokiPush => "loki_push",
    }
}
