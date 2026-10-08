//! Bounded traversal for authenticated integrity verification.

use crate::{InstanceId, TransactionId};

use super::super::format::SegmentState;
use super::super::recovery::RecoveryMode;
use super::super::{
    ActiveSegmentLedger, LedgerStorage, SegmentId, SegmentProtectionKey, SegmentScope,
};
use super::{
    IntegrityCancellationProbe, IntegrityFailure, IntegrityFailureCode, IntegrityScrubBudget,
    IntegrityScrubContinuation, IntegrityVerificationMode, IntegrityVerificationOutcome,
    IntegrityVerificationReport, IntegrityVerificationScope, can_localize_quarantine,
    is_isolated_corruption, localized_finding, map_catalog_failure, map_ledger_failure,
    publish_quarantine, quarantined_segment_ids,
};

/// Inputs shared by every bounded integrity traversal. Keeping the scope,
/// protection, budget, cancellation, transaction, and cursor together makes
/// the immutable verification basis explicit at every entrypoint.
pub struct IntegrityVerificationRequest<'a> {
    scope: SegmentScope,
    protection: SegmentProtectionKey,
    budget: IntegrityScrubBudget,
    cancellation: &'a dyn IntegrityCancellationProbe,
    transaction: TransactionId,
    continuation: Option<IntegrityScrubContinuation>,
}

impl<'a> IntegrityVerificationRequest<'a> {
    #[must_use]
    pub fn new(
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        budget: IntegrityScrubBudget,
        cancellation: &'a dyn IntegrityCancellationProbe,
        transaction: TransactionId,
        continuation: Option<IntegrityScrubContinuation>,
    ) -> Self {
        Self {
            scope,
            protection,
            budget,
            cancellation,
            transaction,
            continuation,
        }
    }
}

/// Adds the catalog-mode and optional governance audit binding to one bounded
/// catalog traversal.
pub struct CatalogIntegrityVerificationRequest<'a> {
    verification: IntegrityVerificationRequest<'a>,
    mode: IntegrityVerificationMode,
    quarantine_audit: Option<crate::AuditIntent>,
}

impl<'a> CatalogIntegrityVerificationRequest<'a> {
    #[must_use]
    pub fn new(
        verification: IntegrityVerificationRequest<'a>,
        mode: IntegrityVerificationMode,
    ) -> Self {
        Self {
            verification,
            mode,
            quarantine_audit: None,
        }
    }

    #[must_use]
    pub fn with_quarantine_audit(mut self, quarantine_audit: crate::AuditIntent) -> Self {
        self.quarantine_audit = Some(quarantine_audit);
        self
    }
}

struct IntegrityVerificationTraversal<'a> {
    scope: SegmentScope,
    protection: &'a SegmentProtectionKey,
    budget: IntegrityScrubBudget,
    cancellation: &'a dyn IntegrityCancellationProbe,
    transaction: TransactionId,
    continuation: Option<IntegrityScrubContinuation>,
}

impl<'a> IntegrityVerificationTraversal<'a> {
    const fn from_request(request: &'a IntegrityVerificationRequest<'_>) -> Self {
        Self {
            scope: request.scope,
            protection: &request.protection,
            budget: request.budget,
            cancellation: request.cancellation,
            transaction: request.transaction,
            continuation: request.continuation,
        }
    }
}

struct IntegrityVerificationSnapshot<'a, 'kernel> {
    authority: &'kernel crate::StorageKernelResourceAuthority,
    storage: &'a LedgerStorage,
    basis: &'a crate::CatalogSnapshot,
    instance: InstanceId,
    catalog: Option<&'a crate::Catalog<'kernel>>,
}

/// The short, serialized publication boundary for a localized online finding.
/// The allowlist names only the authenticated durable task lineage permitted to
/// have advanced the catalog since the immutable scan began.
pub struct OnlineQuarantinePublication<'a> {
    report: IntegrityVerificationReport,
    transaction: TransactionId,
    maintenance_task: crate::MaintenanceTaskId,
    permitted_maintenance_tasks: &'a [crate::MaintenanceTaskId],
    audit: crate::AuditIntent,
}

impl<'a> OnlineQuarantinePublication<'a> {
    #[must_use]
    pub fn new(
        report: IntegrityVerificationReport,
        transaction: TransactionId,
        maintenance_task: crate::MaintenanceTaskId,
        permitted_maintenance_tasks: &'a [crate::MaintenanceTaskId],
        audit: crate::AuditIntent,
    ) -> Self {
        Self {
            report,
            transaction,
            maintenance_task,
            permitted_maintenance_tasks,
            audit,
        }
    }
}

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Authenticates a bounded immutable prefix of this scope. A sealed-object
    /// failure is atomically made visible as a catalog-authenticated quarantine;
    /// active-tail or catalog ambiguity is returned as a fenced outcome.
    pub fn verify_integrity(
        &self,
        mode: IntegrityVerificationMode,
        budget: IntegrityScrubBudget,
        cancellation: &dyn IntegrityCancellationProbe,
        transaction: TransactionId,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        verify_integrity_from(
            self.authority,
            &self.storage,
            self.catalog,
            IntegrityVerificationTraversal {
                scope: self.scope,
                protection: &self.protection,
                budget,
                cancellation,
                transaction,
                continuation: None,
            },
            mode,
            None,
        )
    }

    /// Resumes a previous bounded pass only when its exact authenticated
    /// Catalog generation and source segment are still reachable.
    pub fn resume_integrity(
        &self,
        mode: IntegrityVerificationMode,
        budget: IntegrityScrubBudget,
        cancellation: &dyn IntegrityCancellationProbe,
        transaction: TransactionId,
        continuation: IntegrityScrubContinuation,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        verify_integrity_from(
            self.authority,
            &self.storage,
            self.catalog,
            IntegrityVerificationTraversal {
                scope: self.scope,
                protection: &self.protection,
                budget,
                cancellation,
                transaction,
                continuation: Some(continuation),
            },
            mode,
            None,
        )
    }

    /// Verifies one catalog scope without reconstructing or repairing the
    /// ledger first. This is the runtime startup and maintenance entrypoint.
    pub fn verify_catalog_integrity(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        catalog: &'catalog crate::Catalog<'kernel>,
        request: CatalogIntegrityVerificationRequest<'_>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        Self::verify_catalog_integrity_with_audit(authority, catalog, request)
    }

    /// The runtime-only trusted publication path may bind one system-derived
    /// Governance Audit intent to a localized quarantine. Offline and startup
    /// callers retain the audit-free observation API above.
    pub fn verify_catalog_integrity_with_audit(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        catalog: &'catalog crate::Catalog<'kernel>,
        request: CatalogIntegrityVerificationRequest<'_>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open(volume).map_err(map_ledger_failure)?;
        verify_integrity_from(
            authority,
            &storage,
            catalog,
            IntegrityVerificationTraversal::from_request(&request.verification),
            request.mode,
            request.quarantine_audit,
        )
    }

    /// Verifies an exact caller-pinned online Catalog generation. Localized
    /// immutable corruption may publish only the canonical quarantine bound to
    /// that same generation; a concurrent successor therefore cannot become
    /// an implicit verification basis.
    pub fn verify_pinned_catalog_integrity(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        catalog: &'catalog crate::Catalog<'kernel>,
        snapshot: &crate::CatalogSnapshot,
        request: IntegrityVerificationRequest<'_>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open(volume).map_err(map_ledger_failure)?;
        verify_integrity_against_snapshot(
            IntegrityVerificationSnapshot {
                authority,
                storage: &storage,
                basis: snapshot,
                instance: catalog.instance(),
                catalog: Some(catalog),
            },
            IntegrityVerificationTraversal::from_request(&request),
            IntegrityVerificationMode::Online,
            None,
        )
    }

    /// Observes an already authenticated Catalog snapshot without acquiring a
    /// Catalog writer, creating storage directories, publishing a finding, or
    /// attempting recovery. Offline callers may only use Offline mode.
    pub fn verify_snapshot_integrity(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        snapshot: &crate::CatalogSnapshot,
        instance: InstanceId,
        request: IntegrityVerificationRequest<'_>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open_observed(volume).map_err(map_ledger_failure)?;
        verify_integrity_against_snapshot(
            IntegrityVerificationSnapshot {
                authority,
                storage: &storage,
                basis: snapshot,
                instance,
                catalog: None,
            },
            IntegrityVerificationTraversal::from_request(&request),
            IntegrityVerificationMode::Offline,
            None,
        )
    }

    /// Observes an exact authenticated online Catalog snapshot without a
    /// writer lease. A localized immutable failure is reported for the caller
    /// to publish through an exact-generation compare-and-swap; this method
    /// never substitutes a newer Catalog generation or mutates source bytes.
    pub fn verify_online_snapshot_integrity(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        snapshot: &crate::CatalogSnapshot,
        instance: InstanceId,
        request: IntegrityVerificationRequest<'_>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open_observed(volume).map_err(map_ledger_failure)?;
        verify_integrity_against_snapshot(
            IntegrityVerificationSnapshot {
                authority,
                storage: &storage,
                basis: snapshot,
                instance,
                catalog: None,
            },
            IntegrityVerificationTraversal::from_request(&request),
            IntegrityVerificationMode::Online,
            None,
        )
    }

    /// Publishes the localized result of `verify_online_snapshot_integrity`
    /// only when the current writer basis differs from the exact immutable
    /// scan basis solely by this request's durable maintenance record. The
    /// caller must serialize this short compare-and-swap with other Catalog
    /// writers; the immutable scan itself deliberately needs neither.
    pub fn publish_online_quarantine(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        catalog: &'catalog crate::Catalog<'kernel>,
        proof: &crate::CatalogSnapshot,
        current: &crate::CatalogSnapshot,
        publication: OnlineQuarantinePublication<'_>,
    ) -> Result<(), IntegrityFailure> {
        if publication.report.outcome() != IntegrityVerificationOutcome::Quarantined
            || publication.report.mode() != IntegrityVerificationMode::Online
            || publication.report.catalog_generation() != proof.number()
            || !publication
                .permitted_maintenance_tasks
                .contains(&publication.maintenance_task)
            || !proof
                .same_except_maintenance_tasks(current, publication.permitted_maintenance_tasks)
                .map_err(map_catalog_failure)?
        {
            return Err(IntegrityFailure(IntegrityFailureCode::InvalidInput));
        }
        let segment = publication
            .report
            .quarantined_segment()
            .ok_or(IntegrityFailure(IntegrityFailureCode::InvalidInput))?;
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open(volume).map_err(map_ledger_failure)?;
        let metadata = storage
            .catalog_segments_observed(proof, publication.report.scope())
            .map_err(map_ledger_failure)?;
        let metadata = metadata
            .into_iter()
            .find(|candidate| candidate.id == segment)
            .filter(|candidate| can_localize_quarantine(*candidate))
            .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
        publish_quarantine(
            catalog,
            publication.report.scope(),
            current,
            metadata,
            publication.transaction,
            Some(publication.audit),
        )
    }
}

fn verify_integrity_from(
    authority: &crate::StorageKernelResourceAuthority,
    storage: &LedgerStorage,
    catalog: &crate::Catalog<'_>,
    traversal: IntegrityVerificationTraversal<'_>,
    mode: IntegrityVerificationMode,
    quarantine_audit: Option<crate::AuditIntent>,
) -> Result<IntegrityVerificationReport, IntegrityFailure> {
    let basis = catalog.pin().map_err(map_catalog_failure)?;
    verify_integrity_against_snapshot(
        IntegrityVerificationSnapshot {
            authority,
            storage,
            basis: &basis,
            instance: catalog.instance(),
            catalog: Some(catalog),
        },
        traversal,
        mode,
        quarantine_audit,
    )
}

fn verify_integrity_against_snapshot(
    snapshot: IntegrityVerificationSnapshot<'_, '_>,
    traversal: IntegrityVerificationTraversal<'_>,
    mode: IntegrityVerificationMode,
    quarantine_audit: Option<crate::AuditIntent>,
) -> Result<IntegrityVerificationReport, IntegrityFailure> {
    let IntegrityVerificationSnapshot {
        authority,
        storage,
        basis,
        instance,
        catalog,
    } = snapshot;
    let IntegrityVerificationTraversal {
        scope,
        protection,
        budget,
        cancellation,
        transaction,
        continuation,
    } = traversal;
    let metadata = storage
        .catalog_segments_observed(basis, scope)
        .map_err(map_ledger_failure)?;
    let scans_sealed = !matches!(mode, IntegrityVerificationMode::Startup);
    let online_publication = matches!(mode, IntegrityVerificationMode::Online);
    let quarantined = quarantined_segment_ids(basis, scope)?;
    let retained_quarantine = scans_sealed.then(|| quarantined.first().copied()).flatten();
    let targets = metadata
        .iter()
        .filter(|candidate| match mode {
            IntegrityVerificationMode::Startup => candidate.state == SegmentState::Active,
            IntegrityVerificationMode::Online => candidate.state == SegmentState::Sealed,
            IntegrityVerificationMode::Offline => {
                matches!(candidate.state, SegmentState::Active | SegmentState::Sealed)
            },
        })
        .filter(|candidate| {
            candidate.state != SegmentState::Sealed || !quarantined.contains(&candidate.id)
        })
        .collect::<Vec<_>>();
    let target_count = targets.len();
    let _snapshot_protection = if online_publication {
        Some(
            super::super::SnapshotProtection::for_segments(
                authority.snapshot_protection(),
                authority.snapshot_barrier(),
                targets.iter().map(|candidate| candidate.id),
            )
            .map_err(map_ledger_failure)?,
        )
    } else {
        None
    };
    let source_identity = basis
        .integrity_scope_source_identity(scope)
        .map_err(map_ledger_failure)?;
    let start = match continuation {
        Some(continuation) if continuation.source_identity != source_identity => {
            return Ok(report(IntegrityReport {
                mode,
                scope,
                catalog_generation: basis.number(),
                examined_segments: 0,
                examined_bytes: 0,
                omitted_segments: target_count,
                outcome: IntegrityVerificationOutcome::Stale,
                quarantined_segment: None,
                continuation: None,
            }));
        },
        Some(continuation) => match targets
            .iter()
            .position(|candidate| candidate.id == continuation.last_segment)
        {
            Some(position) => position.saturating_add(1),
            None => {
                return Ok(report(IntegrityReport {
                    mode,
                    scope,
                    catalog_generation: basis.number(),
                    examined_segments: 0,
                    examined_bytes: 0,
                    omitted_segments: target_count,
                    outcome: IntegrityVerificationOutcome::Stale,
                    quarantined_segment: None,
                    continuation: None,
                }));
            },
        },
        None => 0,
    };
    let mut examined_segments = 0_usize;
    let mut examined_bytes = 0_u64;
    let mut last_segment = continuation.map(|cursor| cursor.last_segment);
    for candidate in targets.into_iter().skip(start).take(budget.0) {
        if cancellation.is_cancelled() {
            return Ok(report(IntegrityReport {
                mode,
                scope,
                catalog_generation: basis.number(),
                examined_segments,
                examined_bytes,
                omitted_segments: target_count
                    .saturating_sub(start.saturating_add(examined_segments)),
                outcome: IntegrityVerificationOutcome::Incomplete,
                quarantined_segment: None,
                continuation: continuation_for(source_identity, last_segment),
            }));
        }
        let physical = match if candidate.state == SegmentState::Sealed {
            storage.sealed_compaction_source_bound(*candidate, protection, instance)
        } else {
            Ok(None)
        } {
            Ok(Some((bytes, _))) => u64::try_from(bytes)
                .map_err(|_| IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?,
            Ok(None) => 0,
            Err(failure)
                if candidate.state == SegmentState::Sealed
                    && matches!(
                        mode,
                        IntegrityVerificationMode::Online | IntegrityVerificationMode::Offline
                    )
                    && is_isolated_corruption(failure.code()) =>
            {
                let Some(catalog) = online_publication.then_some(catalog).flatten() else {
                    if can_localize_quarantine(*candidate) {
                        return Ok(report(IntegrityReport {
                            mode,
                            scope,
                            catalog_generation: basis.number(),
                            examined_segments: examined_segments.saturating_add(1),
                            examined_bytes,
                            omitted_segments: target_count.saturating_sub(
                                start.saturating_add(examined_segments.saturating_add(1)),
                            ),
                            outcome: IntegrityVerificationOutcome::Quarantined,
                            quarantined_segment: Some(candidate.id),
                            continuation: continuation_for(source_identity, Some(candidate.id))
                                .filter(|_| {
                                    mode == IntegrityVerificationMode::Offline
                                        && target_count
                                            > start
                                                .saturating_add(examined_segments.saturating_add(1))
                                }),
                        })
                        .with_localized_finding(
                            localized_finding(scope, *candidate).ok_or(IntegrityFailure(
                                IntegrityFailureCode::AmbiguousIntegrity,
                            ))?,
                        ));
                    }
                    return Ok(report(IntegrityReport {
                        mode,
                        scope,
                        catalog_generation: basis.number(),
                        examined_segments,
                        examined_bytes,
                        omitted_segments: target_count
                            .saturating_sub(start.saturating_add(examined_segments)),
                        outcome: IntegrityVerificationOutcome::Fenced,
                        quarantined_segment: None,
                        continuation: None,
                    }));
                };
                if !can_localize_quarantine(*candidate) {
                    return Ok(report(IntegrityReport {
                        mode,
                        scope,
                        catalog_generation: basis.number(),
                        examined_segments,
                        examined_bytes,
                        omitted_segments: target_count
                            .saturating_sub(start.saturating_add(examined_segments)),
                        outcome: IntegrityVerificationOutcome::Fenced,
                        quarantined_segment: None,
                        continuation: None,
                    }));
                }
                publish_quarantine(
                    catalog,
                    scope,
                    basis,
                    *candidate,
                    transaction,
                    quarantine_audit.clone(),
                )?;
                return Ok(report(IntegrityReport {
                    mode,
                    scope,
                    catalog_generation: basis.number(),
                    examined_segments,
                    examined_bytes,
                    omitted_segments: target_count
                        .saturating_sub(start.saturating_add(examined_segments)),
                    outcome: IntegrityVerificationOutcome::Quarantined,
                    quarantined_segment: Some(candidate.id),
                    continuation: None,
                })
                .with_localized_finding(
                    localized_finding(scope, *candidate)
                        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?,
                ));
            },
            Err(_) => {
                return Ok(report(IntegrityReport {
                    mode,
                    scope,
                    catalog_generation: basis.number(),
                    examined_segments,
                    examined_bytes,
                    omitted_segments: target_count
                        .saturating_sub(start.saturating_add(examined_segments)),
                    outcome: IntegrityVerificationOutcome::Fenced,
                    quarantined_segment: None,
                    continuation: None,
                }));
            },
        };
        if physical > integrity_bytes_remaining(examined_bytes, budget.1) {
            return Ok(report(IntegrityReport {
                mode,
                scope,
                catalog_generation: basis.number(),
                examined_segments,
                examined_bytes,
                omitted_segments: target_count
                    .saturating_sub(start.saturating_add(examined_segments)),
                outcome: IntegrityVerificationOutcome::Incomplete,
                quarantined_segment: None,
                continuation: continuation_for(source_identity, last_segment),
            }));
        }
        match storage.recover_segment_with_mode(
            *candidate,
            protection,
            instance,
            RecoveryMode::Observe,
        ) {
            Ok((_key, _recovered)) => {
                examined_segments = examined_segments.saturating_add(1);
                examined_bytes = examined_bytes
                    .checked_add(physical)
                    .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
                last_segment = Some(candidate.id);
            },
            Err(failure)
                if candidate.state == SegmentState::Sealed
                    && matches!(
                        mode,
                        IntegrityVerificationMode::Online | IntegrityVerificationMode::Offline
                    )
                    && is_isolated_corruption(failure.code()) =>
            {
                let localized_examined_segments = examined_segments.saturating_add(1);
                let localized_examined_bytes = examined_bytes
                    .checked_add(physical)
                    .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
                let localized_omitted_segments =
                    target_count.saturating_sub(start.saturating_add(localized_examined_segments));
                let localized_continuation = continuation_for(source_identity, Some(candidate.id))
                    .filter(|_| {
                        mode == IntegrityVerificationMode::Offline
                            && localized_omitted_segments != 0
                    });
                let Some(catalog) = online_publication.then_some(catalog).flatten() else {
                    if can_localize_quarantine(*candidate) {
                        return Ok(report(IntegrityReport {
                            mode,
                            scope,
                            catalog_generation: basis.number(),
                            examined_segments: localized_examined_segments,
                            examined_bytes: localized_examined_bytes,
                            omitted_segments: localized_omitted_segments,
                            outcome: IntegrityVerificationOutcome::Quarantined,
                            quarantined_segment: Some(candidate.id),
                            continuation: localized_continuation,
                        })
                        .with_localized_finding(
                            localized_finding(scope, *candidate).ok_or(IntegrityFailure(
                                IntegrityFailureCode::AmbiguousIntegrity,
                            ))?,
                        ));
                    }
                    return Ok(report(IntegrityReport {
                        mode,
                        scope,
                        catalog_generation: basis.number(),
                        examined_segments,
                        examined_bytes,
                        omitted_segments: target_count
                            .saturating_sub(start.saturating_add(examined_segments)),
                        outcome: IntegrityVerificationOutcome::Fenced,
                        quarantined_segment: None,
                        continuation: None,
                    }));
                };
                if !can_localize_quarantine(*candidate) {
                    return Ok(report(IntegrityReport {
                        mode,
                        scope,
                        catalog_generation: basis.number(),
                        examined_segments,
                        examined_bytes,
                        omitted_segments: target_count
                            .saturating_sub(start.saturating_add(examined_segments)),
                        outcome: IntegrityVerificationOutcome::Fenced,
                        quarantined_segment: None,
                        continuation: None,
                    }));
                }
                publish_quarantine(
                    catalog,
                    scope,
                    basis,
                    *candidate,
                    transaction,
                    quarantine_audit.clone(),
                )?;
                return Ok(report(IntegrityReport {
                    mode,
                    scope,
                    catalog_generation: basis.number(),
                    examined_segments,
                    examined_bytes,
                    omitted_segments: target_count
                        .saturating_sub(start.saturating_add(examined_segments)),
                    outcome: IntegrityVerificationOutcome::Quarantined,
                    quarantined_segment: Some(candidate.id),
                    continuation: None,
                })
                .with_localized_finding(
                    localized_finding(scope, *candidate)
                        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?,
                ));
            },
            Err(_) => {
                return Ok(report(IntegrityReport {
                    mode,
                    scope,
                    catalog_generation: basis.number(),
                    examined_segments,
                    examined_bytes,
                    omitted_segments: target_count
                        .saturating_sub(start.saturating_add(examined_segments)),
                    outcome: IntegrityVerificationOutcome::Fenced,
                    quarantined_segment: None,
                    continuation: None,
                }));
            },
        }
    }
    let omitted = target_count.saturating_sub(start.saturating_add(examined_segments));
    Ok(report(IntegrityReport {
        mode,
        scope,
        catalog_generation: basis.number(),
        examined_segments,
        examined_bytes,
        omitted_segments: omitted,
        outcome: if omitted != 0 {
            IntegrityVerificationOutcome::Incomplete
        } else if retained_quarantine.is_some() {
            IntegrityVerificationOutcome::Quarantined
        } else {
            IntegrityVerificationOutcome::Verified
        },
        quarantined_segment: retained_quarantine,
        continuation: continuation_for(source_identity, last_segment).filter(|_| omitted != 0),
    }))
}

fn integrity_bytes_remaining(examined: u64, budget: u64) -> u64 {
    budget.saturating_sub(examined)
}

struct IntegrityReport {
    mode: IntegrityVerificationMode,
    scope: SegmentScope,
    catalog_generation: u64,
    examined_segments: usize,
    examined_bytes: u64,
    omitted_segments: usize,
    outcome: IntegrityVerificationOutcome,
    quarantined_segment: Option<SegmentId>,
    continuation: Option<IntegrityScrubContinuation>,
}

fn report(parts: IntegrityReport) -> IntegrityVerificationReport {
    let IntegrityReport {
        mode,
        scope,
        catalog_generation,
        examined_segments,
        examined_bytes,
        omitted_segments,
        outcome,
        quarantined_segment,
        continuation,
    } = parts;
    IntegrityVerificationReport {
        mode,
        verification_scope: match mode {
            IntegrityVerificationMode::Startup => IntegrityVerificationScope::StartupFrontiers,
            IntegrityVerificationMode::Online => {
                IntegrityVerificationScope::ReachableImmutableSegments
            },
            IntegrityVerificationMode::Offline => {
                IntegrityVerificationScope::ReachableDurableSegments
            },
        },
        scope,
        catalog_generation,
        examined_segments,
        examined_bytes,
        omitted_segments,
        outcome,
        quarantined_segment,
        localized_finding: None,
        continuation,
    }
}

fn continuation_for(
    source_identity: [u8; 32],
    last_segment: Option<SegmentId>,
) -> Option<IntegrityScrubContinuation> {
    last_segment.map(|last_segment| IntegrityScrubContinuation {
        source_identity,
        last_segment,
    })
}
