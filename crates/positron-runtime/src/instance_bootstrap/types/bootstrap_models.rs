use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapState {
    Empty,
    Incomplete,
    Initialized,
    Inconsistent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapFailureCode {
    InvalidRoots,
    InconsistentRoots,
    AlreadyInitialized,
    StorageUnavailable,
    KeyCustodyUnavailable,
    ResourceUnavailable,
    CatalogUnavailable,
    LedgerUnavailable,
    CorruptState,
    DurabilityFrontierAmbiguity,
    KeyEnvelopeMismatch,
    IdentityMismatch,
    ClaimUnavailable,
    ClaimDestructionFailed,
    EntropyUnavailable,
    ApiKeyUnauthorized,
    ApiKeyStaleGeneration,
    ApiKeyIdempotencyConflict,
    ApiKeyUnavailable,
    TenantLifecycleUnauthorized,
    TenantLifecycleUnknownTenant,
    TenantLifecycleInvalidTransition,
    TenantLifecyclePurgeCompletionUnavailable,
    TenantLifecycleStaleGeneration,
    TenantLifecycleIdempotencyConflict,
    TenantQuotaUnauthorized,
    TenantQuotaStaleGeneration,
    TenantQuotaIdempotencyConflict,
    TenantDisplayNameUnauthorized,
    TenantDisplayNameStaleGeneration,
    TenantDisplayNameIdempotencyConflict,
    TenantAliasUnauthorized,
    TenantAliasUnknownTenant,
    TenantAliasAlreadyBound,
    TenantAliasConflict,
    TenantAliasStaleGeneration,
    TenantAliasIdempotencyConflict,
    TenantRetentionUnauthorized,
    TenantRetentionUnknownTenant,
    TenantRetentionInvalidConfirmation,
    TenantRetentionStaleGeneration,
    TenantRetentionIdempotencyConflict,
    SystemAuditRetentionUnauthorized,
    SystemAuditRetentionStaleGeneration,
    SystemAuditRetentionIdempotencyConflict,
    LifecycleClockAcceptanceUnauthorized,
    LifecycleClockAcceptanceStaleCatalog,
    LifecycleClockAcceptanceIdempotencyConflict,
    LifecycleClockAcceptanceInvalidDiscontinuity,
    TenantCreateConflict,
    DurableOperationLookupExpired,
    DurableOperationUnknown,
    DurableOperationCancellationUnavailable,
    /// The exact authenticated governance-audit task is running; retry the
    /// same request using [`BootstrapFailure::maintenance_task`].
    GovernanceAuditCheckpointInProgress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapResourceStage {
    Observation,
    Governor,
    Catalog,
    Ledger,
    RestoreInitialGrant,
    RestoreCarryGrant,
    RestorePhaseGrant,
}
impl BootstrapResourceStage {
    const fn label(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Governor => "governor",
            Self::Catalog => "catalog",
            Self::Ledger => "ledger",
            Self::RestoreInitialGrant => "restore_initial_grant",
            Self::RestoreCarryGrant => "restore_carry_grant",
            Self::RestorePhaseGrant => "restore_phase_grant",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapResourceReason {
    UnsupportedPlatform,
    ObservationUnavailable,
    MalformedLimit,
    AmbiguousHierarchy,
    Arithmetic,
    AllocationUnavailable,
    ZeroCapacity,
    InvalidConfiguration,
    PolicyCardinalityExceeded,
    BootstrapInventoryUnavailable,
    InsufficientOutstandingProgress,
    TenantProgressUnavailable,
    SystemRecoveryProgressUnavailable,
    InvalidRecoveryScope,
    GovernorContended,
    PrimaryVolumeObservationUnavailable,
    ObservedVolumeMismatch,
    InternalFenced,
    ResourceAdmissionRefused,
    LimitExceeded,
    StorageExhausted,
    Cancelled,
}
impl BootstrapResourceReason {
    const fn label(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::ObservationUnavailable => "observation_unavailable",
            Self::MalformedLimit => "malformed_limit",
            Self::AmbiguousHierarchy => "ambiguous_hierarchy",
            Self::Arithmetic => "arithmetic",
            Self::AllocationUnavailable => "allocation_unavailable",
            Self::ZeroCapacity => "zero_capacity",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::PolicyCardinalityExceeded => "policy_cardinality_exceeded",
            Self::BootstrapInventoryUnavailable => "bootstrap_inventory_unavailable",
            Self::InsufficientOutstandingProgress => "insufficient_outstanding_progress",
            Self::TenantProgressUnavailable => "tenant_progress_unavailable",
            Self::SystemRecoveryProgressUnavailable => "system_recovery_progress_unavailable",
            Self::InvalidRecoveryScope => "invalid_recovery_scope",
            Self::GovernorContended => "governor_contended",
            Self::PrimaryVolumeObservationUnavailable => "primary_volume_observation_unavailable",
            Self::ObservedVolumeMismatch => "observed_volume_mismatch",
            Self::InternalFenced => "internal_fenced",
            Self::ResourceAdmissionRefused => "resource_admission_refused",
            Self::LimitExceeded => "limit_exceeded",
            Self::StorageExhausted => "storage_exhausted",
            Self::Cancelled => "cancelled",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapResourceSource {
    RegisteredBounds,
    HostCpu,
    HostMemory,
    CgroupMembership,
    CgroupMounts,
    CgroupCpu,
    CgroupMemory,
    ProcessFileDescriptors,
    PrimaryVolumeFilesystem,
}
impl BootstrapResourceSource {
    const fn label(self) -> &'static str {
        match self {
            Self::RegisteredBounds => "registered_bounds",
            Self::HostCpu => "host_cpu",
            Self::HostMemory => "host_memory",
            Self::CgroupMembership => "cgroup_membership",
            Self::CgroupMounts => "cgroup_mounts",
            Self::CgroupCpu => "cgroup_cpu",
            Self::CgroupMemory => "cgroup_memory",
            Self::ProcessFileDescriptors => "process_file_descriptors",
            Self::PrimaryVolumeFilesystem => "primary_volume_filesystem",
        }
    }
}
/// Closed bootstrap diagnostics; external error text and resource identities never enter here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapResourceContext {
    stage: BootstrapResourceStage,
    reason: BootstrapResourceReason,
    source: Option<BootstrapResourceSource>,
    dimension: Option<positron_kernel::ResourceDimension>,
    admission_code: Option<positron_kernel::AdmissionFailureCode>,
    admission_scope: positron_kernel::LimitingScope,
    admission_class: positron_kernel::WorkClass,
    admission_pressure: positron_kernel::DiskPressureState,
    admission_amounts: [u64; 3],
}
impl BootstrapResourceContext {
    pub(in crate::instance_bootstrap) const fn new(
        stage: BootstrapResourceStage,
        reason: BootstrapResourceReason,
        source: Option<BootstrapResourceSource>,
    ) -> Self {
        Self {
            stage,
            reason,
            source,
            dimension: None,
            admission_code: None,
            admission_scope: positron_kernel::LimitingScope::Global,
            admission_class: positron_kernel::WorkClass::OrdinaryMaintenanceBackup,
            admission_pressure: positron_kernel::DiskPressureState::Healthy,
            admission_amounts: [0; 3],
        }
    }
    pub(in crate::instance_bootstrap) const fn with_admission(
        mut self,
        failure: positron_kernel::AdmissionFailure,
    ) -> Self {
        // Keep only the closed projection, not unused retry/completion evidence in every Copy failure.
        self.admission_code = Some(failure.code());
        self.admission_scope = failure.limiting_scope();
        self.admission_class = failure.work_class();
        self.admission_pressure = failure.pressure_state();
        self.admission_amounts = [failure.allowed(), failure.in_use(), failure.requested()];
        self
    }
    pub(in crate::instance_bootstrap) const fn with_dimension(
        mut self,
        dimension: Option<positron_kernel::ResourceDimension>,
    ) -> Self {
        self.dimension = dimension;
        self
    }
    pub(crate) fn append_json(self, value: &mut serde_json::Value) {
        if let Some(code) = self.admission_code {
            // These getters return payload-free closed enums, never resource identities or external errors.
            value["admission_code"] = format!("{code:?}").into();
            value["admission_scope"] = format!("{:?}", self.admission_scope).into();
            value["admission_class"] = format!("{:?}", self.admission_class).into();
            value["admission_pressure"] = format!("{:?}", self.admission_pressure).into();
            let [allowed, in_use, requested] = self.admission_amounts;
            value["admission_allowed"] = allowed.into();
            value["admission_in_use"] = in_use.into();
            value["admission_requested"] = requested.into();
        }
        value["resource_stage"] = self.stage.label().into();
        value["resource_reason"] = self.reason.label().into();
        if let Some(source) = self.source {
            value["resource_source"] = source.label().into();
        }
        if let Some(dimension) = self.dimension {
            use positron_kernel::ResourceDimension::*;
            value["resource_dimension"] = match dimension {
                MemoryBytes => "memory_bytes",
                QueueSlots => "queue_slots",
                TaskSlots => "task_slots",
                BufferCacheBytes => "buffer_cache_bytes",
                BatchItems => "batch_items",
                LeaseSlots => "lease_slots",
                RetrySlots => "retry_slots",
                IoPermits => "io_permits",
                CpuWorkUnits => "cpu_work_units",
                FileDescriptors => "file_descriptors",
                DiskHeadroomBytes => "disk_headroom_bytes",
            }
            .into();
        }
    }
}

// The checkpoint task and resource refusal are distinct failure outcomes, never simultaneous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapDiagnostic {
    None,
    MaintenanceTask(MaintenanceTaskId),
    Resource(BootstrapResourceContext),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapFailure {
    code: BootstrapFailureCode,
    lifecycle_generation_conflict: Option<positron_governance::TenantLifecycleGenerationConflict>,
    quota_generation_conflict: Option<positron_governance::TenantQuotaGenerationConflict>,
    display_generation_conflict: Option<TenantDisplayGenerationConflict>,
    retention_generation_conflict: Option<positron_governance::TenantRetentionGenerationConflict>,
    diagnostic: BootstrapDiagnostic,
}

impl BootstrapFailure {
    /// Closed diagnostic fields only; omits unavailable context and every resource identity.
    #[must_use]
    pub fn resource_diagnostic(self) -> Option<serde_json::Value> {
        if self.code != BootstrapFailureCode::ResourceUnavailable {
            return None;
        }
        let mut value = serde_json::json!({});
        self.resource_context()?.append_json(&mut value);
        Some(value)
    }
    pub(in crate::instance_bootstrap) const fn with_resource_context(
        mut self,
        context: BootstrapResourceContext,
    ) -> Self {
        self.diagnostic = BootstrapDiagnostic::Resource(context);
        self
    }
    pub(crate) const fn resource_context(self) -> Option<BootstrapResourceContext> {
        match self.diagnostic {
            BootstrapDiagnostic::Resource(context) => Some(context),
            BootstrapDiagnostic::None | BootstrapDiagnostic::MaintenanceTask(_) => None,
        }
    }
    pub(crate) const fn new(code: BootstrapFailureCode) -> Self {
        Self {
            code,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: None,
            diagnostic: BootstrapDiagnostic::None,
        }
    }

    pub(super) const fn with_lifecycle_generation_conflict(
        conflict: positron_governance::TenantLifecycleGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantLifecycleStaleGeneration,
            lifecycle_generation_conflict: Some(conflict),
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: None,
            diagnostic: BootstrapDiagnostic::None,
        }
    }

    pub(super) const fn with_quota_generation_conflict(
        conflict: positron_governance::TenantQuotaGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantQuotaStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: Some(conflict),
            display_generation_conflict: None,
            retention_generation_conflict: None,
            diagnostic: BootstrapDiagnostic::None,
        }
    }

    pub(super) const fn with_display_generation_conflict(
        conflict: TenantDisplayGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantDisplayNameStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: Some(conflict),
            retention_generation_conflict: None,
            diagnostic: BootstrapDiagnostic::None,
        }
    }

    pub(super) const fn with_retention_generation_conflict(
        conflict: positron_governance::TenantRetentionGenerationConflict,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::TenantRetentionStaleGeneration,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: Some(conflict),
            diagnostic: BootstrapDiagnostic::None,
        }
    }

    pub(super) const fn governance_audit_checkpoint_in_progress(
        maintenance_task: MaintenanceTaskId,
    ) -> Self {
        Self {
            code: BootstrapFailureCode::GovernanceAuditCheckpointInProgress,
            lifecycle_generation_conflict: None,
            quota_generation_conflict: None,
            display_generation_conflict: None,
            retention_generation_conflict: None,
            diagnostic: BootstrapDiagnostic::MaintenanceTask(maintenance_task),
        }
    }

    #[must_use]
    pub const fn code(self) -> BootstrapFailureCode {
        self.code
    }

    #[must_use]
    pub const fn lifecycle_generation_conflict(
        self,
    ) -> Option<positron_governance::TenantLifecycleGenerationConflict> {
        self.lifecycle_generation_conflict
    }

    #[must_use]
    pub const fn quota_generation_conflict(&self) -> Option<ResourceGeneration> {
        match self.quota_generation_conflict {
            Some(conflict) => Some(conflict.current_generation()),
            None => None,
        }
    }

    #[must_use]
    pub const fn quota_generation_conflict_detail(
        &self,
    ) -> Option<positron_governance::TenantQuotaGenerationConflict> {
        self.quota_generation_conflict
    }

    #[must_use]
    pub const fn display_generation_conflict(&self) -> Option<TenantDisplayGenerationConflict> {
        self.display_generation_conflict
    }

    #[must_use]
    pub const fn retention_generation_conflict(
        &self,
    ) -> Option<positron_governance::TenantRetentionGenerationConflict> {
        self.retention_generation_conflict
    }

    /// Returns the stable maintenance identity for a retryable in-progress
    /// governance audit checkpoint request.
    #[must_use]
    pub const fn maintenance_task(&self) -> Option<MaintenanceTaskId> {
        match self.diagnostic {
            BootstrapDiagnostic::MaintenanceTask(task) => Some(task),
            BootstrapDiagnostic::None | BootstrapDiagnostic::Resource(_) => None,
        }
    }
}

impl Display for BootstrapFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        if self.code == BootstrapFailureCode::GovernanceAuditCheckpointInProgress
            && let Some(maintenance_task) = self.maintenance_task()
        {
            formatter.write_str(
                "governance audit checkpoint is in progress; retry the same request with maintenance task ",
            )?;
            for byte in maintenance_task.to_bytes() {
                write!(formatter, "{byte:02x}")?;
            }
            return Ok(());
        }
        formatter.write_str("instance bootstrap failed")
    }
}

impl Error for BootstrapFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapPaths {
    pub(in crate::instance_bootstrap) key_cache_lease: positron_kernel::key_provider::KeyCacheLease,
    pub(in crate::instance_bootstrap) storage: InstanceBootstrapStorage,
    #[cfg(test)]
    data: std::path::PathBuf,
    #[cfg(test)]
    secrets: std::path::PathBuf,
}

impl BootstrapPaths {
    /// Explicit mount preparation creates only private data/secrets leaf directories.
    pub fn prepare_storage(
        configuration: &positron_config::EffectiveConfiguration,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapFailure> {
        let data = Path::new(configuration.data_directory());
        let secrets = Path::new(configuration.secrets_directory());
        if configuration.local_key_file().as_path() != secrets.join("local-root-key.v1") {
            return Err(BootstrapFailure::new(BootstrapFailureCode::InvalidRoots));
        }
        let storage = InstanceBootstrapStorage::prepare(data, secrets, qualification)
            .map_err(super::super::storage::storage_failure)?;
        Ok(Self {
            key_cache_lease: positron_kernel::key_provider::KeyCacheLease::default(),
            storage,
            #[cfg(test)]
            data: data.to_owned(),
            #[cfg(test)]
            secrets: secrets.to_owned(),
        })
    }

    pub fn new(
        data: &Path,
        secrets: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapFailure> {
        Ok(Self {
            key_cache_lease: positron_kernel::key_provider::KeyCacheLease::default(),
            storage: InstanceBootstrapStorage::new(data, secrets, qualification)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?,
            #[cfg(test)]
            data: data.to_owned(),
            #[cfg(test)]
            secrets: secrets.to_owned(),
        })
    }

    /// Uses the checked product lease policy for startup and restore.
    #[must_use]
    pub fn with_key_cache_lease(
        mut self,
        lease: positron_kernel::key_provider::KeyCacheLease,
    ) -> Self {
        self.key_cache_lease = lease;
        self
    }

    /// Binds bootstrap custody to the exact effective local-key reference.
    pub fn with_local_key(
        data: &Path,
        secrets: &Path,
        local_key_file: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapFailure> {
        if local_key_file != secrets.join("local-root-key.v1") {
            return Err(BootstrapFailure::new(BootstrapFailureCode::InvalidRoots));
        }
        Self::new(data, secrets, qualification)
    }

    #[cfg(test)]
    pub(in crate::instance_bootstrap) fn data_root(&self) -> &Path {
        &self.data
    }

    #[cfg(test)]
    pub(in crate::instance_bootstrap) fn secrets_root(&self) -> &Path {
        &self.secrets
    }

    #[must_use]
    pub const fn mount_qualification(&self) -> MountQualification {
        self.storage.qualification()
    }

    pub(crate) fn retain_volume(&self) -> Result<OwnedPrimaryDataVolume, BootstrapFailure> {
        self.storage
            .acquire()
            .map(|(volume, _)| volume)
            .map_err(super::super::storage::storage_failure)
    }

    #[doc(hidden)]
    pub fn retain_volume_for_test(&self) -> Result<OwnedPrimaryDataVolume, BootstrapFailure> {
        self.retain_volume()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializationPlan {
    non_interactive: bool,
    external_alias: Option<ExternalTenantAlias>,
}

impl InitializationPlan {
    #[must_use]
    pub const fn non_interactive() -> Self {
        Self {
            non_interactive: true,
            external_alias: None,
        }
    }

    /// Creates a non-interactive plan with an explicitly bound protocol alias.
    pub fn non_interactive_with_external_tenant_alias(
        alias: &str,
    ) -> Result<Self, BootstrapFailure> {
        let external_alias = ExternalTenantAlias::parse(alias)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::InvalidRoots))?;
        Ok(Self {
            non_interactive: true,
            external_alias: Some(external_alias),
        })
    }

    pub(in crate::instance_bootstrap) const fn creates_claim(&self) -> bool {
        self.non_interactive
    }

    pub(in crate::instance_bootstrap) fn external_alias(
        &self,
    ) -> Result<ExternalTenantAlias, BootstrapFailure> {
        self.external_alias.clone().map_or_else(
            || {
                ExternalTenantAlias::parse("trace-external")
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
            },
            Ok,
        )
    }
}

pub struct InitializedInstance {
    pub(in crate::instance_bootstrap) bootstrap_storage: InstanceBootstrapStorage,
    pub(crate) key: BootstrapKeyCustody,
    // Fixture-only inspection data; product authorization always reads the
    // current durable identity through `durable_identity`.
    #[cfg(any(test, fuzzing))]
    pub(crate) identity: positron_governance::Identity,
    #[cfg(any(test, fuzzing))]
    pub(in crate::instance_bootstrap) audit: Vec<positron_governance::GovernanceAuditEntry>,
    pub(crate) _authority: StorageKernelResourceAuthority,
    /// The sole runtime-owned maintenance task registry. Its internal state
    /// serializes transitions; handlers retain only their narrow authorities.
    pub(crate) maintenance: positron_kernel::MaintenanceCoordinator,
    /// Serializes the complete public Governance Audit checkpoint attachment
    /// transaction. It holds no durable state or task authority: the Catalog
    /// and maintenance coordinator remain authoritative.
    pub(in crate::instance_bootstrap) governance_audit_checkpoint_gate: Mutex<()>,
    pub(crate) retention_time: RetentionTimeAuthority,
    pub(crate) instance: InstanceId,
    pub(crate) tenant: TenantId,
    pub(crate) logs_shard: positron_domain::routing::VirtualShardId,
    pub(crate) value_limit_profile: positron_domain::value::ValueLimitProfile,
    pub(crate) admission_group_planner: Arc<dyn positron_ingest::AdmissionGroupPlanner>,
    pub(in crate::instance_bootstrap) tenant_drains: TenantDrainRegistry,
    #[cfg(test)]
    pub(in crate::instance_bootstrap) lifecycle_preflight_hook:
        Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    pub(in crate::instance_bootstrap) catalog_migration_preflight_hook:
        Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub(in crate::instance_bootstrap) tenant_slug: TenantSlug,
    pub(in crate::instance_bootstrap) administrator: PrincipalId,
    pub(in crate::instance_bootstrap) integrity_key_fingerprint: [u8; 32],
    pub(in crate::instance_bootstrap) catalog_generation: std::sync::atomic::AtomicU64,
    pub(in crate::instance_bootstrap) governance_audit_frontier: u64,
    pub(in crate::instance_bootstrap) claim_available: std::sync::atomic::AtomicBool,
    pub(in crate::instance_bootstrap) bootstrap_claim_gate: Mutex<()>,
}

impl std::fmt::Debug for InitializedInstance {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitializedInstance")
            .field("instance", &self.instance)
            .field("tenant", &self.tenant)
            .field("catalog_generation", &self.catalog_generation())
            .field("claim_available", &self.claim_available)
            .finish_non_exhaustive()
    }
}

impl InitializedInstance {
    /// Current readiness and degradation from the owning KEK lease authority.
    pub fn data_protection_health(
        &self,
    ) -> Result<positron_kernel::key_provider::KeyCacheHealth, BootstrapFailure> {
        self.key
            .provider_health()
            .map_err(super::super::operation::support::key_failure)
    }

    pub(in crate::instance_bootstrap) fn record_catalog_generation(&self, generation: u64) {
        self.catalog_generation
            .store(generation, std::sync::atomic::Ordering::Release);
    }

    #[must_use]
    pub(crate) fn maintenance_coordinator(&self) -> &positron_kernel::MaintenanceCoordinator {
        &self.maintenance
    }

    /// Bounded maintenance and operation evidence for authenticated diagnostics.
    /// This reads the restored coordinator and current governance audit without
    /// exposing task identities, scopes, checkpoint payloads, or operation
    /// targets. Every active Snapshot Lease owns exactly one nonterminal expiry
    /// task, so that durable task count is the current lease inventory.
    pub fn maintenance_bundle_evidence(
        &self,
        facts: DoctorRuntimeFacts,
    ) -> Result<String, BootstrapFailure> {
        let statuses = self
            .maintenance
            .statuses()
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
        let mut queued = 0_u32;
        let mut running = 0_u32;
        let mut deferred = 0_u32;
        let mut terminal = 0_u32;
        let mut checkpoints = 0_u32;
        let mut pauses = 0_u32;
        let mut conflicts = 0_u32;
        for status in statuses {
            match status.phase() {
                positron_kernel::MaintenanceTaskPhase::Queued => queued = queued.saturating_add(1),
                positron_kernel::MaintenanceTaskPhase::Running => {
                    running = running.saturating_add(1)
                },
                positron_kernel::MaintenanceTaskPhase::Deferred => {
                    deferred = deferred.saturating_add(1)
                },
                positron_kernel::MaintenanceTaskPhase::Cancelled
                | positron_kernel::MaintenanceTaskPhase::Succeeded
                | positron_kernel::MaintenanceTaskPhase::Failed => {
                    terminal = terminal.saturating_add(1)
                },
            }
            checkpoints = checkpoints.saturating_add(u32::from(status.checkpoint().is_some()));
            pauses = pauses.saturating_add(u32::from(status.pause_until().is_some()));
            conflicts = conflicts.saturating_add(u32::from(status.conflict_owner().is_some()));
        }
        Ok(format!(
            "maintenance_inventory=coordinator_and_governance_audit\nqueued_tasks={queued}\nrunning_tasks={running}\ndeferred_tasks={deferred}\nterminal_tasks={terminal}\ncheckpointed_tasks={checkpoints}\npaused_tasks={pauses}\nconflicted_tasks={conflicts}\ndurable_operations={}\nactive_durable_operations={}\nsnapshot_leases={}\n",
            facts.durable_operations(),
            facts.active_durable_operations(),
            facts.snapshot_leases(),
        ))
    }
    /// Returns the bootstrap-pinned system administrator that acts for
    /// instance-owned maintenance transitions.
    #[must_use]
    pub(crate) const fn administrator(&self) -> PrincipalId {
        self.administrator
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn bootstrap_diagnostic_preserves_checkpoint_task_and_closed_resource_outcomes() {
        let task = MaintenanceTaskId::new([0x41; 16]).expect("task identity");
        let checkpoint = BootstrapFailure::governance_audit_checkpoint_in_progress(task);
        assert_eq!(checkpoint.maintenance_task(), Some(task));
        assert!(checkpoint.resource_context().is_none());
        assert!(checkpoint.resource_diagnostic().is_none());
        assert!(checkpoint.to_string().ends_with(&"41".repeat(16)));
        let resource = BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable)
            .with_resource_context(BootstrapResourceContext::new(
                BootstrapResourceStage::Governor,
                BootstrapResourceReason::InvalidConfiguration,
                None,
            ));
        assert!(resource.maintenance_task().is_none());
        assert_eq!(
            resource.resource_diagnostic(),
            Some(serde_json::json!({
                "resource_stage": "governor", "resource_reason": "invalid_configuration"
            }))
        );
        assert_eq!(resource.to_string(), "instance bootstrap failed");
        let unknown = BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable);
        assert!(unknown.maintenance_task().is_none());
        assert!(unknown.resource_diagnostic().is_none());
    }
}
