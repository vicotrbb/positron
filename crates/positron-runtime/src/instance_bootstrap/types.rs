use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use positron_domain::identity::{ExternalTenantAlias, PrincipalId, Scope, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_domain::routing::SignalKind;
use positron_kernel::{
    AuditIntent, BootstrapKeyCustody, Catalog, CatalogFailureCode, CatalogProposal,
    CommittedLedgerReader, CrashRecordStore, ExportManifestSigner, FormatEpoch,
    InstanceBootstrapStorage, InstanceId, MaintenanceFailure, MaintenanceTaskId,
    MaintenanceTaskPhase, MountQualification, OwnedPrimaryDataVolume, ResourceAmounts,
    ResourceSnapshot, RetentionImpactPreview, RetentionReclamationEstimate, RetentionTimeAuthority,
    StorageKernelResourceAuthority, TransactionId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use positron_governance::{
    AdministrativeIdempotencyKey, ApiKeyAdministrationFailure, ApiKeyCreation, AuthorizedContext,
    CatalogFormatMigration, CatalogFormatMigrationAdministration, CatalogFormatMigrationFailure,
    DurableOperation, DurableOperationAdministration, DurableOperationFailure,
    DurableOperationRequest, DurableOperationStatus, DurableOperationTerminalError,
    ListenerTransportAdministration, ListenerTransportAdministrationFailure, ResourceGeneration,
    RetentionImpactConfirmation, TenantAliasAdministration, TenantAliasAdministrationFailure,
    TenantAliasBindRequest, TenantAliasBinding, TenantDisplayGenerationConflict,
    TenantDisplayNameUpdate, TenantDisplayNameUpdateRequest, TenantLifecycleAdministration,
    TenantLifecycleAdministrationFailure, TenantLifecycleTransition,
    TenantLifecycleTransitionRequest, TenantProfileAdministration,
    TenantProfileAdministrationFailure, TenantProfileAdministrationFailureCode,
    TenantRetentionAdministration, TenantRetentionAdministrationFailure, TenantRetentionUpdate,
    TenantRetentionUpdateRequest,
};
use positron_query::QueryCancellation;

/// Read-only diagnostic facts verified from the current bootstrap and Catalog
/// authorities. The values deliberately contain no key material, identifiers,
/// or repository coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRepositoryInspection {
    /// The current persisted Catalog has no Backup Repository binding owner.
    /// This is an explicit Release 1 state, never a guessed repository.
    NotConfigured,
}

impl BackupRepositoryInspection {
    /// Derives the Release-1 backup owner state from an authenticated Catalog
    /// snapshot. Release 1 has no Backup Repository binding object; opening
    /// the Governance owner proves that this is the persisted no-binding
    /// state rather than a guessed endpoint.
    pub(crate) fn from_authenticated_catalog(
        snapshot: &positron_kernel::CatalogSnapshot,
    ) -> Result<Self, ()> {
        snapshot.governance_object().map_err(|_| ())?;
        Ok(Self::NotConfigured)
    }
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
        }
    }
}

/// One authenticated, read-only support-bundle inspection. It owns only
/// opaque signing and sanitized diagnostic capabilities derived from the
/// durable bootstrap and Catalog view.
pub struct OfflineSupportBundleInspection {
    pub(in crate::instance_bootstrap) signer: ExportManifestSigner,
    pub(in crate::instance_bootstrap) catalog_generation: u64,
    pub(in crate::instance_bootstrap) backup_repository: BackupRepositoryInspection,
    pub(in crate::instance_bootstrap) resources: ResourceSnapshot,
    pub(in crate::instance_bootstrap) crash_records: CrashRecordStore,
}

impl OfflineSupportBundleInspection {
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ExportManifestSigner,
        u64,
        BackupRepositoryInspection,
        ResourceSnapshot,
        CrashRecordStore,
    ) {
        (
            self.signer,
            self.catalog_generation,
            self.backup_repository,
            self.resources,
            self.crash_records,
        )
    }
}

/// The read-only support-bundle boundary intentionally distinguishes a
/// rejected presented credential from unavailable local diagnostic state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineSupportBundleFailure {
    AuthenticationRejected,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoctorRuntimeFacts {
    key_custody_verified: bool,
    catalog_bootstrap_verified: bool,
    catalog_generation: u64,
    catalog_audit_frontier: u64,
    catalog_manifest_objects: u32,
    catalog_reachable_ledger_scopes: u32,
    catalog_quarantine_findings: u32,
    integrity_scrub_tasks: u32,
    integrity_scrub_checkpoints: u32,
    backup_repository: BackupRepositoryInspection,
    durable_operations: u32,
    active_durable_operations: u32,
    snapshot_leases: u32,
}

/// One authenticated snapshot of the public, non-secret facts Doctor reports.
/// Grouping these fields makes the inspection boundary explicit and prevents
/// positional argument mix-ups as the report grows.
pub(crate) struct VerifiedDoctorFacts {
    pub(crate) catalog_generation: u64,
    pub(crate) catalog_audit_frontier: u64,
    pub(crate) catalog_manifest_objects: u32,
    pub(crate) catalog_reachable_ledger_scopes: u32,
    pub(crate) catalog_quarantine_findings: u32,
    pub(crate) integrity_scrub_tasks: u32,
    pub(crate) integrity_scrub_checkpoints: u32,
    pub(crate) backup_repository: BackupRepositoryInspection,
    pub(crate) durable_operations: u32,
    pub(crate) active_durable_operations: u32,
    pub(crate) snapshot_leases: u32,
}

impl DoctorRuntimeFacts {
    pub(crate) const fn verified(facts: VerifiedDoctorFacts) -> Self {
        Self {
            key_custody_verified: true,
            catalog_bootstrap_verified: true,
            catalog_generation: facts.catalog_generation,
            catalog_audit_frontier: facts.catalog_audit_frontier,
            catalog_manifest_objects: facts.catalog_manifest_objects,
            catalog_reachable_ledger_scopes: facts.catalog_reachable_ledger_scopes,
            catalog_quarantine_findings: facts.catalog_quarantine_findings,
            integrity_scrub_tasks: facts.integrity_scrub_tasks,
            integrity_scrub_checkpoints: facts.integrity_scrub_checkpoints,
            backup_repository: facts.backup_repository,
            durable_operations: facts.durable_operations,
            active_durable_operations: facts.active_durable_operations,
            snapshot_leases: facts.snapshot_leases,
        }
    }

    #[must_use]
    pub const fn key_custody_verified(self) -> bool {
        self.key_custody_verified
    }

    #[must_use]
    pub const fn catalog_bootstrap_verified(self) -> bool {
        self.catalog_bootstrap_verified
    }

    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }

    /// The authenticated position of the retained Governance Audit chain.
    #[must_use]
    pub const fn catalog_audit_frontier(self) -> u64 {
        self.catalog_audit_frontier
    }

    /// The bounded number of immutable objects in the authenticated Catalog
    /// generation. Object identities and contents never cross this boundary.
    #[must_use]
    pub const fn catalog_manifest_objects(self) -> u32 {
        self.catalog_manifest_objects
    }

    /// The number of durable ledger scopes reachable from the authenticated
    /// Catalog manifests. Scope identifiers remain inside the Kernel.
    #[must_use]
    pub const fn catalog_reachable_ledger_scopes(self) -> u32 {
        self.catalog_reachable_ledger_scopes
    }

    /// The count of durable quarantine findings in the same authenticated
    /// Catalog view. Segment identities stay inside the Kernel.
    #[must_use]
    pub const fn catalog_quarantine_findings(self) -> u32 {
        self.catalog_quarantine_findings
    }

    /// The current durable inventory of bounded Integrity Scrub work.
    #[must_use]
    pub const fn integrity_scrub_tasks(self) -> u32 {
        self.integrity_scrub_tasks
    }

    /// The number of scrubs retaining a durable continuation checkpoint.
    #[must_use]
    pub const fn integrity_scrub_checkpoints(self) -> u32 {
        self.integrity_scrub_checkpoints
    }

    #[must_use]
    pub const fn backup_repository(self) -> BackupRepositoryInspection {
        self.backup_repository
    }

    #[must_use]
    pub const fn durable_operations(self) -> u32 {
        self.durable_operations
    }

    #[must_use]
    pub const fn active_durable_operations(self) -> u32 {
        self.active_durable_operations
    }

    #[must_use]
    pub const fn snapshot_leases(self) -> u32 {
        self.snapshot_leases
    }
}

/// A bounded, authorization-filtered Governance Audit history. When an audit
/// retention anchor is present, records before that signed position are no
/// longer claimed to be available by this response.
#[derive(Debug)]
pub struct GovernanceAuditHistory {
    records: Vec<positron_governance::GovernanceAuditEntry>,
    retention_anchor_position: Option<u64>,
}

impl GovernanceAuditHistory {
    #[must_use]
    pub fn records(&self) -> &[positron_governance::GovernanceAuditEntry] {
        &self.records
    }

    /// Returns the signed boundary preceding the retained suffix, if system
    /// policy has reclaimed an older audit prefix.
    #[must_use]
    pub const fn retention_anchor_position(&self) -> Option<u64> {
        self.retention_anchor_position
    }

    /// Returns the first position that this bounded response can contain.
    #[must_use]
    pub fn earliest_visible_position(&self) -> u64 {
        self.records
            .first()
            .map(positron_governance::GovernanceAuditEntry::position)
            .or_else(|| {
                self.retention_anchor_position
                    .and_then(|position| position.checked_add(1))
            })
            .unwrap_or(1)
    }
}

/// Read-only, generation-bound retention-reduction evidence for one tenant.
pub struct TenantRetentionImpactPreview {
    tenant: TenantId,
    retention_generation: ResourceGeneration,
    proposed_retention_seconds: NonZeroU64,
    catalog_identity: positron_kernel::CatalogGenerationId,
    catalog_generation: u64,
    evaluated_at: positron_domain::time::UnixNanoseconds,
    scopes: Vec<RetentionImpactPreview>,
}

/// The two values returned by a preview that must travel together to confirm
/// a retention reduction at its original trusted evaluation instant.
#[derive(Clone, Copy)]
pub(crate) struct TenantRetentionPreviewConfirmation {
    digest: [u8; 32],
    evaluation: positron_domain::time::UnixNanoseconds,
}

impl TenantRetentionPreviewConfirmation {
    #[must_use]
    pub(crate) const fn new(
        digest: [u8; 32],
        evaluation: positron_domain::time::UnixNanoseconds,
    ) -> Self {
        Self { digest, evaluation }
    }
}

impl TenantRetentionImpactPreview {
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn retention_generation(&self) -> ResourceGeneration {
        self.retention_generation
    }
    #[must_use]
    pub const fn proposed_retention_seconds(&self) -> NonZeroU64 {
        self.proposed_retention_seconds
    }
    #[must_use]
    pub const fn catalog_identity(&self) -> positron_kernel::CatalogGenerationId {
        self.catalog_identity
    }
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn evaluated_at(&self) -> positron_domain::time::UnixNanoseconds {
        self.evaluated_at
    }
    #[must_use]
    pub fn scopes(&self) -> &[RetentionImpactPreview] {
        &self.scopes
    }
    #[must_use]
    pub fn confirmation_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"positron.tenant-retention-impact.v1");
        hash.update(self.tenant.to_bytes());
        hash.update(self.retention_generation.get().to_be_bytes());
        hash.update(self.proposed_retention_seconds.get().to_be_bytes());
        hash.update(self.catalog_identity.to_bytes());
        hash.update(self.catalog_generation.to_be_bytes());
        for scope in &self.scopes {
            hash.update(scope.scope().tenant_id().to_bytes());
            hash.update([match scope.scope().signal_kind() {
                SignalKind::Logs => 1,
                SignalKind::Traces => 2,
            }]);
            hash.update(scope.scope().shard_id().value().to_be_bytes());
            hash.update(scope.catalog_identity().to_bytes());
            hash.update(scope.catalog_generation().to_be_bytes());
            hash.update(scope.evaluated_at().value().to_be_bytes());
            hash.update(scope.approximate_affected_bytes().to_be_bytes());
            hash.update(
                scope
                    .approximate_immediately_reclaimable_bytes()
                    .to_be_bytes(),
            );
            hash.update(scope.deferred_active_segment_bytes().to_be_bytes());
            hash.update(scope.deferred_mixed_sealed_segment_bytes().to_be_bytes());
            match scope.affected_time_range() {
                Some(range) => {
                    hash.update([1]);
                    hash.update(range.earliest().value().to_be_bytes());
                    hash.update(range.latest().value().to_be_bytes());
                },
                None => hash.update([0]),
            }
            match scope.earliest_reclamation() {
                RetentionReclamationEstimate::None => hash.update([0]),
                RetentionReclamationEstimate::At(time) => {
                    hash.update([1]);
                    hash.update(time.value().to_be_bytes());
                },
                RetentionReclamationEstimate::BlockedByDurableLease(time) => {
                    hash.update([2]);
                    hash.update(time.value().to_be_bytes());
                },
                RetentionReclamationEstimate::BlockedByInProcessSnapshot => hash.update([3]),
            }
        }
        hash.finalize().into()
    }

    /// A retained confirmation remains usable across ordinary clock movement
    /// only while no scope can reclaim or affect more data than it did in the
    /// preview. Catalog and generation bindings are checked separately.
    fn current_impact_does_not_exceed(&self, preview: &Self) -> bool {
        self.scopes.len() == preview.scopes.len()
            && self
                .scopes
                .iter()
                .zip(&preview.scopes)
                .all(|(current, prior)| {
                    current.scope() == prior.scope()
                        && current.catalog_identity() == prior.catalog_identity()
                        && current.catalog_generation() == prior.catalog_generation()
                        && current.approximate_affected_bytes()
                            <= prior.approximate_affected_bytes()
                        && current.approximate_immediately_reclaimable_bytes()
                            <= prior.approximate_immediately_reclaimable_bytes()
                        && current.deferred_active_segment_bytes()
                            <= prior.deferred_active_segment_bytes()
                        && current.deferred_mixed_sealed_segment_bytes()
                            <= prior.deferred_mixed_sealed_segment_bytes()
                })
    }
}

mod administration_inspection;
mod administration_keys;
mod administration_lifecycle;
mod administration_lifecycle_clock;
mod administration_retention;
mod administration_serving;
mod administration_tenants;
mod bootstrap_claim;
mod bootstrap_models;
mod failure_mappings;
use failure_mappings::*;
mod tenant_drain_gates;
mod tenant_drain_registry;

pub use bootstrap_claim::BootstrapClaim;
pub use bootstrap_models::{
    BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState, InitializationPlan,
    InitializedInstance,
};
pub(crate) use tenant_drain_gates::{IngestDrainPermit, QueryDrainPermit};
pub(in crate::instance_bootstrap) use tenant_drain_registry::TenantDrainRegistry;
