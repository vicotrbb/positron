use positron_kernel::{
    IntegrityQuarantineFinding, IntegrityVerificationOutcome, IntegrityVerificationReport,
};

/// Bounded, machine-renderable evidence from one offline verification pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineIntegrityVerification {
    reports: Vec<IntegrityVerificationReport>,
    findings: Vec<IntegrityQuarantineFinding>,
    facts: OfflineInspectionFacts,
    continuation: Option<OfflineIntegrityContinuation>,
    covered_scope_count: usize,
    all_covered_scopes_verified: bool,
    examined_segments: u64,
    examined_bytes: u64,
    omitted_segments: u64,
    aggregate_evidence: Vec<OfflineIntegrityEvidence>,
    localized_observations: Vec<OfflineLocalizedObservation>,
}

/// The only aggregate truth an offline verification may publish after it has
/// examined every reachable scope. A localized quarantine is degraded but
/// does not imply the instance-wide ambiguity represented by `Fenced`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineIntegrityAggregateOutcome {
    Verified,
    Incomplete,
    Quarantined,
    Fenced,
}

/// Terminal, secret-free evidence for one scope in an aggregate offline run.
///
/// The runtime bounds this vector before it is authenticated into a resume
/// token, so a complete result always has inspectable evidence for every
/// reachable scope rather than only the reports from its final invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineIntegrityEvidence {
    scope: positron_kernel::SegmentScope,
    catalog_generation: u64,
    outcome: IntegrityVerificationOutcome,
    checksum: [u8; 32],
}

impl OfflineIntegrityEvidence {
    pub(crate) fn from_report(report: IntegrityVerificationReport) -> Self {
        Self {
            scope: report.scope(),
            catalog_generation: report.catalog_generation(),
            outcome: report.outcome(),
            checksum: report.checksum(),
        }
    }
    pub(crate) const fn from_parts(
        scope: positron_kernel::SegmentScope,
        catalog_generation: u64,
        outcome: IntegrityVerificationOutcome,
        checksum: [u8; 32],
    ) -> Self {
        Self {
            scope,
            catalog_generation,
            outcome,
            checksum,
        }
    }
    #[must_use]
    pub const fn scope(self) -> positron_kernel::SegmentScope {
        self.scope
    }
    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn outcome(self) -> IntegrityVerificationOutcome {
        self.outcome
    }
    #[must_use]
    pub const fn checksum(self) -> [u8; 32] {
        self.checksum
    }
}

/// Read-only localization observed in an earlier bounded offline pass and
/// carried inside its authenticated continuation. It never claims a durable
/// Catalog quarantine publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineLocalizedObservation {
    pub(crate) scope: positron_kernel::SegmentScope,
    pub(crate) segment: positron_kernel::SegmentId,
    pub(crate) base_position: u64,
    pub(crate) sealed_frontier: u64,
    pub(crate) event_range: OfflineEventRange,
    pub(crate) ingest_range: OfflineIngestRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineEventRange {
    Known { earliest: i64, latest: i64 },
    MissingSourceTime,
    InvalidSourceTime,
    LegacyFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineIngestRange {
    Known { earliest: i64, latest: i64 },
    Unavailable,
}

impl From<IntegrityQuarantineFinding> for OfflineLocalizedObservation {
    fn from(finding: IntegrityQuarantineFinding) -> Self {
        let event_range = match finding.event_range() {
            positron_kernel::AuthenticatedEventRange::Known { earliest, latest } => {
                OfflineEventRange::Known {
                    earliest: earliest.value(),
                    latest: latest.value(),
                }
            },
            positron_kernel::AuthenticatedEventRange::Unavailable(
                positron_kernel::EventRangeUnavailable::MissingSourceTime,
            ) => OfflineEventRange::MissingSourceTime,
            positron_kernel::AuthenticatedEventRange::Unavailable(
                positron_kernel::EventRangeUnavailable::InvalidSourceTime,
            ) => OfflineEventRange::InvalidSourceTime,
            positron_kernel::AuthenticatedEventRange::Unavailable(
                positron_kernel::EventRangeUnavailable::LegacyFormat,
            ) => OfflineEventRange::LegacyFormat,
        };
        let ingest_range = match finding.ingest_range() {
            positron_kernel::AuthenticatedIngestRange::Known { earliest, latest } => {
                OfflineIngestRange::Known {
                    earliest: earliest.value(),
                    latest: latest.value(),
                }
            },
            positron_kernel::AuthenticatedIngestRange::Unavailable => {
                OfflineIngestRange::Unavailable
            },
        };
        Self {
            scope: finding.scope(),
            segment: finding.segment(),
            base_position: finding.base_position(),
            sealed_frontier: finding.sealed_frontier().value(),
            event_range,
            ingest_range,
        }
    }
}

impl OfflineLocalizedObservation {
    #[must_use]
    pub const fn scope(self) -> positron_kernel::SegmentScope {
        self.scope
    }
    #[must_use]
    pub const fn segment(self) -> positron_kernel::SegmentId {
        self.segment
    }
    #[must_use]
    pub const fn base_position(self) -> u64 {
        self.base_position
    }
    #[must_use]
    pub const fn sealed_frontier(self) -> u64 {
        self.sealed_frontier
    }
    #[must_use]
    pub const fn event_range(self) -> OfflineEventRange {
        self.event_range
    }
    #[must_use]
    pub const fn ingest_range(self) -> OfflineIngestRange {
        self.ingest_range
    }
}

/// Opaque, authenticated aggregate progress for an offline verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineIntegrityContinuation(pub(crate) Vec<u8>);

impl OfflineIntegrityContinuation {
    /// Maximum protected continuation bytes admitted by the canonical runtime
    /// format. The v4 format reserves enough room for all 1,024 terminal
    /// evidence records while remaining within the portable CLI argument cap
    /// once rendered as hexadecimal.
    pub const MAX_ENCODED_BYTES: usize = 65_536;

    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.0
    }
    pub fn from_encoded(encoded: Vec<u8>) -> Result<Self, OfflineIntegrityFailure> {
        (!encoded.is_empty() && encoded.len() <= Self::MAX_ENCODED_BYTES)
            .then_some(Self(encoded))
            .ok_or(OfflineIntegrityFailure::CorruptState)
    }
}

/// Facts captured while the caller holds the Primary Data Volume ownership
/// lock. They describe only authorities opened by the offline pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineInspectionFacts {
    catalog_generation: u64,
    registered_tenant_count: usize,
    reachable_scope_count: usize,
    verified_envelope_count: usize,
    quarantine_finding_count: usize,
    verified_scope_count: usize,
    fenced_scope_count: usize,
    incomplete_scope_count: usize,
    usable_disk_bytes: u64,
    disk_pressure: OfflineDiskPressure,
    backup_repository: crate::BackupRepositoryInspection,
}

/// Primary Data Volume pressure observed by the temporary offline governor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineDiskPressure {
    Healthy,
    Soft,
    Hard,
}

impl OfflineInspectionFacts {
    #[allow(clippy::too_many_arguments, reason = "one closed inspection snapshot")]
    pub(crate) const fn new(
        catalog_generation: u64,
        registered_tenant_count: usize,
        reachable_scope_count: usize,
        verified_envelope_count: usize,
        quarantine_finding_count: usize,
        verified_scope_count: usize,
        fenced_scope_count: usize,
        incomplete_scope_count: usize,
        usable_disk_bytes: u64,
        disk_pressure: OfflineDiskPressure,
        backup_repository: crate::BackupRepositoryInspection,
    ) -> Self {
        Self {
            catalog_generation,
            registered_tenant_count,
            reachable_scope_count,
            verified_envelope_count,
            quarantine_finding_count,
            verified_scope_count,
            fenced_scope_count,
            incomplete_scope_count,
            usable_disk_bytes,
            disk_pressure,
            backup_repository,
        }
    }
    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn registered_tenant_count(self) -> usize {
        self.registered_tenant_count
    }
    #[must_use]
    pub const fn reachable_scope_count(self) -> usize {
        self.reachable_scope_count
    }
    #[must_use]
    pub const fn verified_envelope_count(self) -> usize {
        self.verified_envelope_count
    }
    #[must_use]
    pub const fn quarantine_finding_count(self) -> usize {
        self.quarantine_finding_count
    }
    #[must_use]
    pub const fn verified_scope_count(self) -> usize {
        self.verified_scope_count
    }
    #[must_use]
    pub const fn fenced_scope_count(self) -> usize {
        self.fenced_scope_count
    }
    #[must_use]
    pub const fn incomplete_scope_count(self) -> usize {
        self.incomplete_scope_count
    }
    #[must_use]
    pub const fn usable_disk_bytes(self) -> u64 {
        self.usable_disk_bytes
    }
    #[must_use]
    pub const fn disk_pressure(self) -> OfflineDiskPressure {
        self.disk_pressure
    }
    #[must_use]
    pub const fn backup_repository(self) -> crate::BackupRepositoryInspection {
        self.backup_repository
    }
}

impl OfflineIntegrityVerification {
    #[allow(
        clippy::too_many_arguments,
        reason = "one immutable aggregate inspection result"
    )]
    pub(crate) fn new(
        reports: Vec<IntegrityVerificationReport>,
        findings: Vec<IntegrityQuarantineFinding>,
        facts: OfflineInspectionFacts,
        continuation: Option<OfflineIntegrityContinuation>,
        covered_scope_count: usize,
        all_covered_scopes_verified: bool,
        examined_segments: u64,
        examined_bytes: u64,
        omitted_segments: u64,
        aggregate_evidence: Vec<OfflineIntegrityEvidence>,
        localized_observations: Vec<OfflineLocalizedObservation>,
    ) -> Self {
        Self {
            reports,
            findings,
            facts,
            continuation,
            covered_scope_count,
            all_covered_scopes_verified,
            examined_segments,
            examined_bytes,
            omitted_segments,
            aggregate_evidence,
            localized_observations,
        }
    }

    /// Authenticated read-only localizations retained across bounded passes.
    #[must_use]
    pub fn localized_observations(&self) -> &[OfflineLocalizedObservation] {
        &self.localized_observations
    }

    #[must_use]
    pub fn reports(&self) -> &[IntegrityVerificationReport] {
        &self.reports
    }

    /// Durable quarantine evidence from the same read-only Catalog snapshot.
    #[must_use]
    pub fn findings(&self) -> &[IntegrityQuarantineFinding] {
        &self.findings
    }

    /// Authenticated terminal evidence accumulated across every resumed pass.
    #[must_use]
    pub fn aggregate_evidence(&self) -> &[OfflineIntegrityEvidence] {
        &self.aggregate_evidence
    }

    #[must_use]
    pub const fn facts(&self) -> OfflineInspectionFacts {
        self.facts
    }

    /// Authenticated aggregate progress for the next bounded invocation.
    #[must_use]
    pub fn continuation(&self) -> Option<&OfflineIntegrityContinuation> {
        self.continuation.as_ref()
    }

    /// An offline invocation is complete only when its evidence covers every
    /// reachable sealed scope and each reached a terminal result. A fenced
    /// result is terminal evidence, never a successful verification claim.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.covered_scope_count == self.facts.reachable_scope_count()
            && self.continuation.is_none()
            && self.aggregate_evidence.len() == self.facts.reachable_scope_count()
            && self
                .reports
                .iter()
                .all(|report| report.outcome() != IntegrityVerificationOutcome::Incomplete)
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.is_complete() && self.all_covered_scopes_verified
    }

    /// Derives one explicit aggregate outcome from authenticated terminal
    /// evidence. An actual fenced scope takes precedence because it signals
    /// instance-wide ambiguity even if another scope is already quarantined.
    #[must_use]
    pub fn aggregate_outcome(&self) -> OfflineIntegrityAggregateOutcome {
        if !self.is_complete() {
            return OfflineIntegrityAggregateOutcome::Incomplete;
        }
        if self
            .aggregate_evidence
            .iter()
            .any(|evidence| evidence.outcome() == IntegrityVerificationOutcome::Fenced)
        {
            return OfflineIntegrityAggregateOutcome::Fenced;
        }
        if self
            .aggregate_evidence
            .iter()
            .any(|evidence| evidence.outcome() == IntegrityVerificationOutcome::Quarantined)
        {
            return OfflineIntegrityAggregateOutcome::Quarantined;
        }
        if self.all_covered_scopes_verified {
            OfflineIntegrityAggregateOutcome::Verified
        } else {
            OfflineIntegrityAggregateOutcome::Incomplete
        }
    }

    #[must_use]
    pub const fn examined_segments(&self) -> u64 {
        self.examined_segments
    }
    #[must_use]
    pub const fn examined_bytes(&self) -> u64 {
        self.examined_bytes
    }
    #[must_use]
    pub const fn omitted_segments(&self) -> u64 {
        self.omitted_segments
    }
}

/// Typed offline-verification failure. It carries no storage, credential, or
/// decrypted-record detail because it is rendered by an operator report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineIntegrityFailure {
    OwnershipLocked,
    BootstrapUnavailable,
    KeyUnavailable,
    CatalogUnavailable,
    CorruptState,
    CapacityUnavailable,
    StorageUnavailable,
}
