use super::*;

/// A stable, caller-supplied identity for one idempotent maintenance task.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MaintenanceTaskId([u8; 16]);

impl MaintenanceTaskId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, MaintenanceFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Closed Release 1 maintenance work classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenanceTaskClass {
    ActiveSegmentRoll,
    Compaction,
    RetentionPublication,
    RetentionReclamation,
    CatalogReclamation,
    OrphanReclamation,
    IntegrityScrub,
    QuarantineFollowUp,
    SchemaStatistics,
    SchemaPromotion,
    SchemaDemotion,
    GovernanceAuditCheckpoint,
    KeyRewrap,
    EnvelopeVerification,
    Migration,
    RepositoryVerification,
    RepositoryCleanup,
    BackupSnapshot,
    DurableExport,
    SnapshotLeaseExpiry,
    CompletedOperationExpiry,
    TenantPurge,
}

impl MaintenanceTaskClass {
    pub(super) const COUNT: usize = 22;

    pub(super) const fn deferrable(self) -> bool {
        matches!(
            self,
            Self::Compaction
                | Self::SchemaPromotion
                | Self::SchemaDemotion
                | Self::RepositoryVerification
                | Self::BackupSnapshot
                | Self::DurableExport
        )
    }

    /// Whether an audited, expiring maintenance pause may defer this class.
    /// This remains a coordinator-owned policy; callers cannot make another
    /// class deferrable by supplying a request field.
    #[must_use]
    pub const fn is_deferrable(self) -> bool {
        self.deferrable()
    }

    pub(super) const fn destructive(self) -> bool {
        matches!(
            self,
            Self::RetentionPublication
                | Self::RetentionReclamation
                | Self::CatalogReclamation
                | Self::OrphanReclamation
                | Self::RepositoryCleanup
                | Self::SnapshotLeaseExpiry
                | Self::CompletedOperationExpiry
        )
    }

    pub(super) const fn priority(
        self,
        trigger: MaintenanceTrigger,
        emergency_compaction: bool,
    ) -> MaintenancePriority {
        match self {
            Self::ActiveSegmentRoll | Self::GovernanceAuditCheckpoint => {
                MaintenancePriority::Durability
            },
            Self::RetentionPublication
            | Self::RetentionReclamation
            | Self::CatalogReclamation
            | Self::OrphanReclamation
            | Self::IntegrityScrub
            | Self::QuarantineFollowUp
            | Self::KeyRewrap
            | Self::EnvelopeVerification
            | Self::Migration
            | Self::SnapshotLeaseExpiry
            | Self::CompletedOperationExpiry
            | Self::TenantPurge => MaintenancePriority::Urgent,
            Self::SchemaStatistics | Self::RepositoryCleanup => MaintenancePriority::Required,
            Self::Compaction => match trigger {
                MaintenanceTrigger::Event if emergency_compaction => MaintenancePriority::Urgent,
                MaintenanceTrigger::Event => MaintenancePriority::Required,
                MaintenanceTrigger::Scheduled | MaintenanceTrigger::AgeDerived => {
                    MaintenancePriority::Ordinary
                },
            },

            Self::SchemaPromotion
            | Self::SchemaDemotion
            | Self::RepositoryVerification
            | Self::BackupSnapshot
            | Self::DurableExport => MaintenancePriority::Ordinary,
        }
    }

    pub(super) const fn is_window_deferrable(self, emergency_compaction: bool) -> bool {
        self.deferrable() && (!matches!(self, Self::Compaction) || !emergency_compaction)
    }
}

/// The bounded task scope used for fairness and conflicts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenanceScope {
    System,
    Tenant(TenantId),
    Segment {
        tenant: TenantId,
        signal: SignalKind,
        shard: VirtualShardId,
    },
}

impl MaintenanceScope {
    #[must_use]
    pub const fn system() -> Self {
        Self::System
    }

    #[must_use]
    pub const fn tenant(tenant: TenantId) -> Self {
        Self::Tenant(tenant)
    }

    #[must_use]
    pub const fn segment(tenant: TenantId, signal: SignalKind, shard: VirtualShardId) -> Self {
        Self::Segment {
            tenant,
            signal,
            shard,
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> Option<TenantId> {
        match self {
            Self::System => None,
            Self::Tenant(tenant) | Self::Segment { tenant, .. } => Some(tenant),
        }
    }
}

/// Opaque immutable input or copy-on-write output identity used in conflicts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MaintenanceObjectId([u8; 32]);

impl MaintenanceObjectId {
    pub fn new(bytes: [u8; 32]) -> Result<Self, MaintenanceFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Authenticated immutable-source basis for a bounded integrity scrub.
///
/// This is distinct from a physical object identity: it is a catalog-derived
/// precondition which the executor must revalidate before it reads a scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityScrubSourceBinding([u8; 32]);

impl IntegrityScrubSourceBinding {
    pub fn new(bytes: [u8; 32]) -> Result<Self, MaintenanceFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// The event provenance used to gate unsafe clock-derived work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceTrigger {
    Event,
    Scheduled,
    AgeDerived,
}

/// A coordinator-derived scheduling class. Callers cannot promote arbitrary work.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenancePriority {
    Ordinary,
    Required,
    Urgent,
    Durability,
}

/// Catalog and administration state that must still match at task start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenancePreconditions {
    pub(super) catalog_generation: u64,
    pub(super) resource_generation: u64,
}

impl MaintenancePreconditions {
    pub fn new(
        catalog_generation: u64,
        resource_generation: u64,
    ) -> Result<Self, MaintenanceFailure> {
        if resource_generation == 0 {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            catalog_generation,
            resource_generation,
        })
    }

    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn resource_generation(self) -> u64 {
        self.resource_generation
    }
}

/// A bounded durable progress point. Its opaque payload is written by the task handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceCheckpoint {
    pub(super) sequence: u64,
    pub(super) completed_inputs: u32,
    pub(super) opaque_progress: Vec<u8>,
}

impl MaintenanceCheckpoint {
    pub fn new(
        sequence: u64,
        completed_inputs: u32,
        opaque_progress: Vec<u8>,
    ) -> Result<Self, MaintenanceFailure> {
        if sequence == 0 || opaque_progress.len() > MAX_CHECKPOINT_BYTES {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            sequence,
            completed_inputs,
            opaque_progress,
        })
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn completed_inputs(&self) -> u32 {
        self.completed_inputs
    }
    #[must_use]
    pub fn opaque_progress(&self) -> &[u8] {
        &self.opaque_progress
    }
}

/// Public lifecycle state for one submitted maintenance identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceTaskPhase {
    Queued,
    Running,
    Deferred,
    Cancelled,
    Succeeded,
    Failed,
}

/// A bounded maintenance request submitted through the sole coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTask {
    pub(super) identity: MaintenanceTaskId,
    pub(super) class: MaintenanceTaskClass,
    pub(super) scope: MaintenanceScope,
    pub(super) trigger: MaintenanceTrigger,
    pub(super) emergency_compaction: bool,
    pub(super) preconditions: MaintenancePreconditions,
    pub(super) inputs: Vec<MaintenanceObjectId>,
    pub(super) outputs: Vec<MaintenanceObjectId>,
    pub(super) integrity_scrub_source: Option<IntegrityScrubSourceBinding>,
    pub(super) reservations: ResourceAmounts,
    pub(super) not_before: u64,
}

impl MaintenanceTask {
    #[must_use]
    pub fn new(identity: MaintenanceTaskId, class: MaintenanceTaskClass) -> Self {
        // A system-scoped task with a fixed, non-empty reservation is useful
        // only for the small set of catalog-owned maintenance tests. Production
        // submitters use `with_contract` to state their actual scope and peak.
        Self {
            identity,
            class,
            scope: MaintenanceScope::System,
            trigger: MaintenanceTrigger::Event,
            emergency_compaction: false,
            preconditions: MaintenancePreconditions {
                catalog_generation: 0,
                resource_generation: 1,
            },
            inputs: Vec::new(),
            outputs: Vec::new(),
            integrity_scrub_source: None,
            reservations: ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
            not_before: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_contract(
        identity: MaintenanceTaskId,
        class: MaintenanceTaskClass,
        scope: MaintenanceScope,
        trigger: MaintenanceTrigger,
        preconditions: MaintenancePreconditions,
        inputs: Vec<MaintenanceObjectId>,
        outputs: Vec<MaintenanceObjectId>,
        reservations: ResourceAmounts,
    ) -> Result<Self, MaintenanceFailure> {
        Self::with_contract_not_before(
            identity,
            class,
            scope,
            trigger,
            preconditions,
            inputs,
            outputs,
            reservations,
            0,
        )
    }

    /// Creates one source-bound integrity scrub descriptor.
    pub fn integrity_scrub(
        identity: MaintenanceTaskId,
        scope: MaintenanceScope,
        trigger: MaintenanceTrigger,
        preconditions: MaintenancePreconditions,
        source_basis: [u8; 32],
        not_before: u64,
    ) -> Result<Self, MaintenanceFailure> {
        if !matches!(scope, MaintenanceScope::Segment { .. })
            || (trigger == MaintenanceTrigger::Scheduled && not_before == 0)
            || (trigger != MaintenanceTrigger::Scheduled && not_before != 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut task = Self::with_contract_not_before(
            identity,
            MaintenanceTaskClass::IntegrityScrub,
            scope,
            trigger,
            preconditions,
            Vec::new(),
            Vec::new(),
            crate::catalog::integrity_scrub_resource_claim(),
            not_before,
        )?;
        task.integrity_scrub_source = Some(IntegrityScrubSourceBinding::new(source_basis)?);
        Ok(task)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn emergency_compaction_for_test(mut self) -> Result<Self, MaintenanceFailure> {
        if self.class != MaintenanceTaskClass::Compaction
            || self.trigger != MaintenanceTrigger::Event
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        self.emergency_compaction = true;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_contract_not_before(
        identity: MaintenanceTaskId,
        class: MaintenanceTaskClass,
        scope: MaintenanceScope,
        trigger: MaintenanceTrigger,
        preconditions: MaintenancePreconditions,
        mut inputs: Vec<MaintenanceObjectId>,
        mut outputs: Vec<MaintenanceObjectId>,
        reservations: ResourceAmounts,
        not_before: u64,
    ) -> Result<Self, MaintenanceFailure> {
        if inputs.len() > MAX_TASK_OBJECTS
            || outputs.len() > MAX_TASK_OBJECTS
            || ResourceDimension::ALL
                .iter()
                .all(|dimension| reservations.get(*dimension) == 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        inputs.sort_unstable();
        outputs.sort_unstable();
        if inputs.windows(2).any(|pair| pair[0] == pair[1])
            || outputs.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        if class == MaintenanceTaskClass::SnapshotLeaseExpiry
            && (!matches!(scope, MaintenanceScope::Segment { .. })
                || trigger != MaintenanceTrigger::Scheduled
                || preconditions.resource_generation != 1
                || inputs.len() != 1
                || !outputs.is_empty()
                || reservations != ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0])
                || not_before == 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            identity,
            class,
            scope,
            trigger,
            emergency_compaction: false,
            preconditions,
            inputs,
            outputs,
            integrity_scrub_source: None,
            reservations,
            not_before,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> MaintenanceTaskId {
        self.identity
    }

    #[must_use]
    pub const fn class(&self) -> MaintenanceTaskClass {
        self.class
    }

    /// Whether the task is optional work that an audited finite pause may
    /// defer. Emergency compaction remains eligible despite the ordinary
    /// Compaction class because it is protected Recovery Reserve work.
    #[must_use]
    pub const fn is_pause_deferrable(&self) -> bool {
        self.class.is_window_deferrable(self.emergency_compaction)
    }

    #[must_use]
    pub const fn scope(&self) -> MaintenanceScope {
        self.scope
    }
    #[must_use]
    pub const fn trigger(&self) -> MaintenanceTrigger {
        self.trigger
    }
    #[must_use]
    pub const fn priority(&self) -> MaintenancePriority {
        self.class.priority(self.trigger, self.emergency_compaction)
    }
    #[must_use]
    pub const fn preconditions(&self) -> MaintenancePreconditions {
        self.preconditions
    }
    #[must_use]
    pub fn inputs(&self) -> &[MaintenanceObjectId] {
        &self.inputs
    }
    #[must_use]
    pub fn outputs(&self) -> &[MaintenanceObjectId] {
        &self.outputs
    }
    /// Returns the catalog-derived source precondition for an integrity scrub.
    #[must_use]
    pub const fn source_binding(&self) -> Option<IntegrityScrubSourceBinding> {
        self.integrity_scrub_source
    }
    #[must_use]
    pub const fn reservations(&self) -> ResourceAmounts {
        self.reservations
    }
    #[must_use]
    pub const fn not_before(&self) -> u64 {
        self.not_before
    }
}
