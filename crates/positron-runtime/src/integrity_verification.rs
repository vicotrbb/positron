use positron_kernel::{
    IntegrityQuarantineFinding, IntegrityVerificationOutcome, IntegrityVerificationReport,
    SegmentScope,
};

use crate::{BootstrapPaths, InstanceBootstrap};

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

/// Begins a bounded offline verification sequence without creating or
/// repairing bootstrap, Catalog, ledger, or quarantine state. Scope discovery
/// is bounded by the authenticated Catalog's 1,024-object limit; this
/// invocation processes one scope under the kernel's 128-segment, 16 MiB
/// scrub-pass budget and reports authenticated progress instead of continuing
/// internally.
pub fn verify_offline_integrity(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
) -> Result<OfflineIntegrityVerification, OfflineIntegrityFailure> {
    InstanceBootstrap::verify_offline_integrity(paths, max_registered_tenants, None, None)
}

/// Verifies one caller-selected offline scope without promoting it to an
/// aggregate verification claim.
pub fn verify_offline_integrity_scope(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    scope: SegmentScope,
) -> Result<OfflineIntegrityVerification, OfflineIntegrityFailure> {
    InstanceBootstrap::verify_offline_integrity(paths, max_registered_tenants, Some(scope), None)
}

/// Resumes exactly one bounded offline scrub pass from an authenticated
/// cursor. The caller names the scope so the cursor never selects source
/// bytes outside its reported result.
pub fn resume_offline_integrity(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    continuation: OfflineIntegrityContinuation,
) -> Result<OfflineIntegrityVerification, OfflineIntegrityFailure> {
    InstanceBootstrap::verify_offline_integrity(
        paths,
        max_registered_tenants,
        None,
        Some(continuation),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        OfflineIntegrityFailure, resume_offline_integrity, verify_offline_integrity,
        verify_offline_integrity_scope,
    };
    use crate::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
    use positron_kernel::{IntegrityCancellation, MountQualification, ResourceAmounts, WorkClaim};

    #[test]
    fn offline_verification_aggregates_healthy_reachable_scopes_without_changing_any_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let before = file_tree(&root)?;
        let report = verify_offline_integrity(&paths, 2)
            .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
        let after = file_tree(&root)?;

        assert!(report.is_complete());
        assert!(report.is_verified());
        let facts = report.facts();
        assert!(facts.catalog_generation() > 0);
        assert_eq!(facts.registered_tenant_count(), 1);
        assert_eq!(facts.verified_envelope_count(), 1);
        assert_eq!(facts.reachable_scope_count(), 2);
        assert_eq!(report.reports().len(), 2);
        assert_eq!(facts.verified_scope_count(), report.reports().len());
        assert_eq!(facts.fenced_scope_count(), 0);
        assert_eq!(facts.incomplete_scope_count(), 0);
        let retained = paths.retain_volume_for_test()?;
        drop(retained);
        assert_eq!(
            after, before,
            "offline verification must not create, repair, or publish"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn selected_terminal_scope_does_not_claim_whole_instance_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;

        let first = verify_offline_integrity(&paths, 2)
            .map_err(|failure| format!("first offline pass failed: {failure:?}"))?;
        let selected_scope = first.reports()[0].scope();
        let selected = verify_offline_integrity_scope(&paths, 2, selected_scope)
            .map_err(|failure| format!("selected scope failed: {failure:?}"))?;

        assert_eq!(
            selected.reports()[0].outcome(),
            positron_kernel::IntegrityVerificationOutcome::Verified
        );
        assert!(
            !selected.is_complete(),
            "a selected terminal scope must not claim other reachable scopes were verified"
        );
        assert!(!selected.is_verified());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_corruption_report_preserves_damaged_bytes_without_quarantine()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::routing::SignalKind;
        use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
        drop(catalog);
        drop(instance);

        let sealed = fs::read_dir(root.join("data/segments/sealed"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .next()
            .ok_or("sealed segment")?;
        fs::write(sealed, b"corrupt")?;
        let before = file_tree(&root)?;
        let report = verify_offline_integrity(&paths, 2)
            .map_err(|failure| format!("offline verification failed: {failure:?}"))?;
        assert!(!report.is_verified());
        assert!(
            report.reports().iter().any(|item| item.outcome()
                == positron_kernel::IntegrityVerificationOutcome::Fenced),
            "offline corruption is a non-mutating fenced fact, never a quarantine publication"
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn selected_scope_verification_returns_a_bound_cursor_and_resumes_without_global_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::routing::SignalKind;
        use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        // Initialization already leaves one reachable immutable segment in
        // this scope. Add 128 more so the production 128-segment budget
        // must return one authenticated omission.
        for _ in 0..128 {
            let key = crate::services::tenant_segment_key(&instance, &identity, scope)
                .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
            ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
        }
        drop(catalog);
        drop(instance);

        let before = file_tree(&root)?;
        let first = verify_offline_integrity_scope(&paths, 2, scope)
            .map_err(|failure| format!("first offline pass failed: {failure:?}"))?;
        assert!(!first.is_complete());
        assert!(!first.is_verified());
        assert_eq!(first.reports().len(), 1);
        let partial = first
            .reports()
            .iter()
            .copied()
            .find(|report| report.scope() == scope)
            .ok_or("missing requested scope report")?;
        assert_eq!(
            partial.outcome(),
            positron_kernel::IntegrityVerificationOutcome::Incomplete
        );
        assert_eq!(partial.examined_segments(), 128);
        assert_eq!(partial.omitted_segments(), 1);
        assert!(partial.continuation().is_some());
        let continuation = first
            .continuation()
            .cloned()
            .ok_or("missing aggregate continuation")?;
        let mut tampered = continuation.clone();
        tampered.0[0] ^= 0x80;
        assert_eq!(
            resume_offline_integrity(&paths, 2, tampered),
            Err(OfflineIntegrityFailure::CorruptState)
        );
        assert_eq!(file_tree(&root)?, before);

        let resumed = resume_offline_integrity(&paths, 2, continuation)
            .map_err(|failure| format!("resumed offline pass failed: {failure:?}"))?;
        assert!(!resumed.is_complete());
        assert!(!resumed.is_verified());
        assert!(resumed.continuation().is_none());
        assert_eq!(resumed.reports().len(), 1);
        assert_eq!(resumed.reports()[0].scope(), scope);
        assert_eq!(resumed.reports()[0].examined_segments(), 1);
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn aggregate_verification_bounds_valid_multi_scope_bytes_and_resumes_with_a_fresh_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::routing::{SignalKind, VirtualShardId};
        use positron_kernel::{
            ActiveSegmentLedger, Catalog, IntegrityScrubBudget, PreparedStoreBlock, SegmentScope,
            StoreBlockIdentity,
        };

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        drop(catalog);

        // Seventeen non-default Trace scopes each contain one normally sealed
        // segment with two valid 512 KiB Store Blocks. Every scope fits under
        // the claim independently, while their cumulative authenticated bytes
        // exceed it. Reopening the Catalog after each seal is the normal
        // next-segment path, so this is not an oversized or invalid fixture.
        for shard in 2_u16..=18 {
            let scope = SegmentScope::new(
                instance.tenant,
                SignalKind::Traces,
                VirtualShardId::new(shard.into())?,
            );
            let catalog = Catalog::open(
                &instance._authority,
                instance.instance,
                instance.key.catalog_secret(instance.instance)?,
            )?;
            let key = crate::services::tenant_segment_key(&instance, &identity, scope)
                .map_err(|failure| format!("trace segment key unavailable: {failure:?}"))?;
            let ledger = ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?;
            let identity_byte = u8::try_from(shard * 2)?;
            for block in 0_u8..2 {
                ledger.append(PreparedStoreBlock::new(
                    scope,
                    StoreBlockIdentity::new([identity_byte.saturating_add(block); 16])?,
                    vec![identity_byte.saturating_add(block); 524_288],
                )?)?;
            }
            ledger
                .seal()
                .map_err(|failure| format!("trace seal {shard} failed: {failure:?}"))?;
        }
        drop(instance);

        let before = file_tree(&root)?;
        let first = verify_offline_integrity(&paths, 2)
            .map_err(|failure| format!("aggregate offline pass failed: {failure:?}"))?;
        let examined_bytes = first
            .reports()
            .iter()
            .map(|report| report.examined_bytes())
            .sum::<u64>();
        assert!(
            examined_bytes <= IntegrityScrubBudget::MAX_BYTES,
            "the actual bytes examined by one aggregate invocation must fit its single 16 MiB resource claim"
        );
        let partial = first
            .reports()
            .iter()
            .copied()
            .find(|report| {
                report.outcome() == positron_kernel::IntegrityVerificationOutcome::Incomplete
            })
            .ok_or("missing truthful aggregate byte-bound partial report")?;
        assert!(partial.omitted_segments() > 0);
        assert!(!first.is_complete());
        assert!(!first.is_verified());
        let continuation = first
            .continuation()
            .cloned()
            .ok_or("missing aggregate byte-bound continuation")?;
        assert_eq!(file_tree(&root)?, before);

        let resumed = resume_offline_integrity(&paths, 2, continuation)
            .map_err(|failure| format!("fresh aggregate continuation failed: {failure:?}"))?;
        let resumed_bytes = resumed
            .reports()
            .iter()
            .map(|report| report.examined_bytes())
            .sum::<u64>();
        assert!(resumed_bytes <= IntegrityScrubBudget::MAX_BYTES);
        assert!(resumed.reports().iter().all(|report| {
            report.outcome() == positron_kernel::IntegrityVerificationOutcome::Verified
        }));
        assert!(resumed.is_complete());
        assert!(resumed.is_verified());
        assert!(resumed.continuation().is_none());
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn selected_nonfirst_scope_resumes_its_own_bound_cursor_without_claiming_instance_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::routing::{SignalKind, VirtualShardId};
        use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        // Traces sorts after the initialized Logs scope, so this proves that
        // an authenticated selected-scope continuation retains its target.
        let scope = SegmentScope::new(instance.tenant, SignalKind::Traces, VirtualShardId::new(2)?);
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        for _ in 0..129 {
            let key = crate::services::tenant_segment_key(&instance, &identity, scope)
                .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
            ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
        }
        drop(catalog);
        drop(instance);

        let before = file_tree(&root)?;
        let first = verify_offline_integrity_scope(&paths, 2, scope)
            .map_err(|failure| format!("selected offline pass failed: {failure:?}"))?;
        assert_eq!(first.reports().len(), 1);
        assert_eq!(
            first.reports()[0].outcome(),
            positron_kernel::IntegrityVerificationOutcome::Incomplete
        );
        assert_eq!(first.reports()[0].examined_segments(), 128);
        let continuation = first
            .continuation()
            .cloned()
            .ok_or("missing selected continuation")?;

        let resumed = resume_offline_integrity(&paths, 2, continuation)
            .map_err(|failure| format!("selected resume failed: {failure:?}"))?;
        assert_eq!(resumed.reports().len(), 1);
        assert_eq!(resumed.reports()[0].scope(), scope);
        assert_eq!(
            resumed.reports()[0].outcome(),
            positron_kernel::IntegrityVerificationOutcome::Verified
        );
        assert!(
            resumed.continuation().is_none(),
            "the selected terminal scope must not continue into aggregate scopes"
        );
        assert!(
            !resumed.is_complete(),
            "selected completion must not claim the whole instance was covered"
        );
        assert!(!resumed.is_verified());
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn protected_malformed_v2_continuation_fails_closed_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_kernel::BootstrapObjectPurpose;

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let malformed = crate::OfflineIntegrityContinuation(instance.key.protect(
            instance.instance,
            BootstrapObjectPurpose::Initialized,
            b"\x02malformed-v2",
        )?);
        drop(instance);
        let before = file_tree(&root)?;

        assert_eq!(
            resume_offline_integrity(&paths, 2, malformed),
            Err(OfflineIntegrityFailure::CorruptState)
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_authenticated_continuation_fails_closed_without_mutating_after_catalog_advance()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::{identity::Scope, routing::SignalKind};
        use positron_governance::{
            AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
            ResourceGeneration,
        };
        use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        for _ in 0..128 {
            let key = crate::services::tenant_segment_key(&instance, &identity, scope)
                .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
            ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
        }
        drop(catalog);
        drop(instance);
        let continuation = verify_offline_integrity_scope(&paths, 2, scope)
            .map_err(|failure| format!("selected pass failed: {failure:?}"))?
            .continuation()
            .cloned()
            .ok_or("missing continuation")?;

        let claim = InstanceBootstrap::claim(&paths)?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let administrator = instance.attribute(
            PresentedCredential::parse(claim.secret())?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        instance.create_api_key(
            administrator,
            Scope::Ingest,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x91; 16])?,
        )?;
        drop(instance);
        let before = file_tree(&root)?;

        assert_eq!(
            resume_offline_integrity(&paths, 2, continuation),
            Err(OfflineIntegrityFailure::CorruptState)
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_missing_key_reports_typed_failure_without_bootstrap_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        fs::remove_file(root.join("secrets/local-root-key.v1"))?;
        let before = file_tree(&root)?;
        assert_eq!(
            verify_offline_integrity(&paths, 2),
            Err(OfflineIntegrityFailure::KeyUnavailable)
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn key_unavailable_diagnostics_reserve_before_collection_and_release_after_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        fs::remove_file(root.join("secrets/local-root-key.v1"))?;
        let before = file_tree(&root)?;
        let claim = WorkClaim::system_diagnostics(ResourceAmounts::new([
            24_576, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0,
        ]))?;

        let collected =
            InstanceBootstrap::with_offline_key_unavailable_diagnostics(&paths, 2, claim, || {
                assert!(
                    paths.retain_volume_for_test().is_err(),
                    "the diagnostics reservation must hold exclusive ownership through collection"
                );
                file_tree(&root)
            })
            .map_err(|failure| format!("offline diagnostics failed: {failure:?}"))?;
        assert_eq!(collected?, before);
        let retained = paths.retain_volume_for_test()?;
        drop(retained);
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn key_unavailable_diagnostics_refuse_before_collection_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        fs::remove_file(root.join("secrets/local-root-key.v1"))?;
        let before = file_tree(&root)?;
        let entered = std::cell::Cell::new(false);
        let refusal = InstanceBootstrap::with_offline_key_unavailable_diagnostics(
            &paths,
            2,
            WorkClaim::system_diagnostics(ResourceAmounts::new([
                u64::MAX,
                0,
                1,
                0,
                0,
                0,
                0,
                1,
                1,
                1,
                0,
            ]))?,
            || entered.set(true),
        );
        assert_eq!(refusal, Err(OfflineIntegrityFailure::CapacityUnavailable));
        assert!(!entered.get(), "refused admission must precede collection");
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_verification_refuses_the_aggregate_reservation_before_collection_and_releases()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let before = file_tree(&root)?;
        let refusal = InstanceBootstrap::verify_offline_integrity_with_claim_for_test(
            &paths,
            2,
            WorkClaim::system_diagnostics(ResourceAmounts::new([
                u64::MAX,
                0,
                1,
                0,
                0,
                0,
                0,
                1,
                1,
                1,
                0,
            ]))?,
        );

        assert_eq!(refusal, Err(OfflineIntegrityFailure::CapacityUnavailable));
        let retained = paths.retain_volume_for_test()?;
        drop(retained);
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_verification_releases_its_reservation_after_a_cancelled_scrub()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::routing::SignalKind;
        use positron_kernel::{ActiveSegmentLedger, Catalog, SegmentScope};

        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
        let instance = InstanceBootstrap::reopen(&paths)?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
        let identity = positron_governance::Identity::open(&catalog.pin()?)?;
        let key = crate::services::tenant_segment_key(&instance, &identity, scope)
            .map_err(|failure| format!("segment key unavailable: {failure:?}"))?;
        ActiveSegmentLedger::open(&instance._authority, &catalog, scope, key)?.seal()?;
        drop(catalog);
        drop(instance);
        let before = file_tree(&root)?;
        let cancellation = IntegrityCancellation::new();
        cancellation.cancel();
        let cancelled =
            InstanceBootstrap::verify_offline_integrity_with_claim_and_cancellation_for_test(
                &paths,
                2,
                WorkClaim::system_diagnostics(ResourceAmounts::new([
                    16_000_000, 0, 1, 4_000_000, 128, 0, 0, 1, 1, 1, 0,
                ]))?,
                &cancellation,
            );

        let cancelled = cancelled
            .map_err(|failure| format!("cancelled scrub failed unexpectedly: {failure:?}"))?;
        assert!(!cancelled.is_complete());
        assert_eq!(
            cancelled.reports()[0].outcome(),
            positron_kernel::IntegrityVerificationOutcome::Incomplete
        );
        let retained = paths.retain_volume_for_test()?;
        drop(retained);
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn offline_verification_of_missing_root_never_creates_bootstrap_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root()?;
        let paths = BootstrapPaths::new(
            &root.join("data"),
            &root.join("secrets"),
            MountQualification::LocalHost,
        )?;
        let before = file_tree(&root)?;
        assert_eq!(
            verify_offline_integrity(&paths, 2),
            Err(OfflineIntegrityFailure::BootstrapUnavailable)
        );
        assert_eq!(file_tree(&root)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn temporary_root() -> Result<PathBuf, std::io::Error> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-offline-integrity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("data"))?;
        fs::create_dir_all(root.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(root)
    }

    fn file_tree(root: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>, std::io::Error> {
        let mut entries = Vec::new();
        collect_files(root, root, &mut entries)?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries)
    }

    fn collect_files(
        root: &Path,
        current: &Path,
        entries: &mut Vec<(PathBuf, Vec<u8>)>,
    ) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_files(root, &path, entries)?;
            } else {
                let relative = path
                    .strip_prefix(root)
                    .map_err(std::io::Error::other)?
                    .to_owned();
                // The volume acquisition lease is the only intentional
                // filesystem side effect of offline exclusivity.
                if relative != Path::new("data/.positron-volume.lock") {
                    entries.push((relative, fs::read(&path)?));
                }
            }
        }
        Ok(())
    }
}
