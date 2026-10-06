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
}

/// Opaque, authenticated aggregate progress for an offline verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineIntegrityContinuation(pub(crate) Vec<u8>);

impl OfflineIntegrityContinuation {
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.0
    }
    pub fn from_encoded(encoded: Vec<u8>) -> Result<Self, OfflineIntegrityFailure> {
        (!encoded.is_empty() && encoded.len() <= 1024)
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
    pub(crate) fn new(
        reports: Vec<IntegrityVerificationReport>,
        findings: Vec<IntegrityQuarantineFinding>,
        facts: OfflineInspectionFacts,
        continuation: Option<OfflineIntegrityContinuation>,
        covered_scope_count: usize,
        all_covered_scopes_verified: bool,
    ) -> Self {
        Self {
            reports,
            findings,
            facts,
            continuation,
            covered_scope_count,
            all_covered_scopes_verified,
        }
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
            && self
                .reports
                .iter()
                .all(|report| report.outcome() != IntegrityVerificationOutcome::Incomplete)
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.is_complete() && self.all_covered_scopes_verified
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
