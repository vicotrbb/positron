//! Bounded traversal for authenticated integrity verification.

use crate::{InstanceId, TransactionId};

use super::super::format::SegmentState;
use super::super::recovery::RecoveryMode;
use super::super::{
    ActiveSegmentLedger, LedgerStorage, SegmentId, SegmentProtectionKey, SegmentScope,
};
use super::{
    IntegrityCancellation, IntegrityFailure, IntegrityFailureCode, IntegrityScrubBudget,
    IntegrityScrubContinuation, IntegrityVerificationMode, IntegrityVerificationOutcome,
    IntegrityVerificationReport, IntegrityVerificationScope, can_localize_quarantine,
    is_isolated_corruption, map_catalog_failure, map_ledger_failure, publish_quarantine,
    quarantined_segment_ids,
};

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Authenticates a bounded immutable prefix of this scope. A sealed-object
    /// failure is atomically made visible as a catalog-authenticated quarantine;
    /// active-tail or catalog ambiguity is returned as a fenced outcome.
    pub fn verify_integrity(
        &self,
        mode: IntegrityVerificationMode,
        budget: IntegrityScrubBudget,
        cancellation: &IntegrityCancellation,
        transaction: TransactionId,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        verify_integrity_from(
            &self.storage,
            self.catalog,
            self.scope,
            &self.protection,
            mode,
            budget,
            cancellation,
            transaction,
            None,
        )
    }

    /// Resumes a previous bounded pass only when its exact authenticated
    /// Catalog generation and source segment are still reachable.
    pub fn resume_integrity(
        &self,
        mode: IntegrityVerificationMode,
        budget: IntegrityScrubBudget,
        cancellation: &IntegrityCancellation,
        transaction: TransactionId,
        continuation: IntegrityScrubContinuation,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        verify_integrity_from(
            &self.storage,
            self.catalog,
            self.scope,
            &self.protection,
            mode,
            budget,
            cancellation,
            transaction,
            Some(continuation),
        )
    }

    /// Verifies one catalog scope without reconstructing or repairing the
    /// ledger first. This is the runtime startup and maintenance entrypoint.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_catalog_integrity(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        catalog: &'catalog crate::Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        mode: IntegrityVerificationMode,
        budget: IntegrityScrubBudget,
        cancellation: &IntegrityCancellation,
        transaction: TransactionId,
        continuation: Option<IntegrityScrubContinuation>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open(volume).map_err(map_ledger_failure)?;
        verify_integrity_from(
            &storage,
            catalog,
            scope,
            &protection,
            mode,
            budget,
            cancellation,
            transaction,
            continuation,
        )
    }

    /// Verifies an exact caller-pinned online Catalog generation. Localized
    /// immutable corruption may publish only the canonical quarantine bound to
    /// that same generation; a concurrent successor therefore cannot become
    /// an implicit verification basis.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_pinned_catalog_integrity(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        catalog: &'catalog crate::Catalog<'kernel>,
        snapshot: &crate::CatalogSnapshot,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        budget: IntegrityScrubBudget,
        cancellation: &IntegrityCancellation,
        transaction: TransactionId,
        continuation: Option<IntegrityScrubContinuation>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open(volume).map_err(map_ledger_failure)?;
        verify_integrity_against_snapshot(
            &storage,
            snapshot,
            catalog.instance(),
            Some(catalog),
            scope,
            &protection,
            IntegrityVerificationMode::Online,
            budget,
            cancellation,
            transaction,
            continuation,
        )
    }

    /// Observes an already authenticated Catalog snapshot without acquiring a
    /// Catalog writer, creating storage directories, publishing a finding, or
    /// attempting recovery. Offline callers may only use Offline mode.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_snapshot_integrity(
        authority: &'kernel crate::StorageKernelResourceAuthority,
        snapshot: &crate::CatalogSnapshot,
        instance: InstanceId,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        mode: IntegrityVerificationMode,
        budget: IntegrityScrubBudget,
        cancellation: &IntegrityCancellation,
        transaction: TransactionId,
        continuation: Option<IntegrityScrubContinuation>,
    ) -> Result<IntegrityVerificationReport, IntegrityFailure> {
        if mode != IntegrityVerificationMode::Offline {
            return Err(IntegrityFailure(IntegrityFailureCode::InvalidInput));
        }
        let volume = authority
            .primary_data_volume()
            .ok_or(IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?;
        let storage = LedgerStorage::open_observed(volume).map_err(map_ledger_failure)?;
        verify_integrity_against_snapshot(
            &storage,
            snapshot,
            instance,
            None,
            scope,
            &protection,
            mode,
            budget,
            cancellation,
            transaction,
            continuation,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_integrity_from(
    storage: &LedgerStorage,
    catalog: &crate::Catalog<'_>,
    scope: SegmentScope,
    protection: &SegmentProtectionKey,
    mode: IntegrityVerificationMode,
    budget: IntegrityScrubBudget,
    cancellation: &IntegrityCancellation,
    transaction: TransactionId,
    continuation: Option<IntegrityScrubContinuation>,
) -> Result<IntegrityVerificationReport, IntegrityFailure> {
    let basis = catalog.pin().map_err(map_catalog_failure)?;
    verify_integrity_against_snapshot(
        storage,
        &basis,
        catalog.instance(),
        Some(catalog),
        scope,
        protection,
        mode,
        budget,
        cancellation,
        transaction,
        continuation,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_integrity_against_snapshot(
    storage: &LedgerStorage,
    basis: &crate::CatalogSnapshot,
    instance: InstanceId,
    catalog: Option<&crate::Catalog<'_>>,
    scope: SegmentScope,
    protection: &SegmentProtectionKey,
    mode: IntegrityVerificationMode,
    budget: IntegrityScrubBudget,
    cancellation: &IntegrityCancellation,
    transaction: TransactionId,
    continuation: Option<IntegrityScrubContinuation>,
) -> Result<IntegrityVerificationReport, IntegrityFailure> {
    let metadata = storage
        .catalog_segments_observed(basis, scope)
        .map_err(map_ledger_failure)?;
    let immutable_scope = !matches!(mode, IntegrityVerificationMode::Startup);
    let targets = metadata
        .iter()
        .filter(|candidate| {
            candidate.state
                == if immutable_scope {
                    SegmentState::Sealed
                } else {
                    SegmentState::Active
                }
        })
        .collect::<Vec<_>>();
    let target_count = targets.len();
    let quarantined = quarantined_segment_ids(basis, scope)?;
    if let Some(segment) = targets
        .iter()
        .find(|candidate| quarantined.contains(&candidate.id))
        .map(|candidate| candidate.id)
    {
        return Ok(report(
            mode,
            scope,
            basis.number(),
            0,
            0,
            target_count,
            IntegrityVerificationOutcome::Quarantined,
            Some(segment),
            None,
        ));
    }
    let source_identity = basis
        .integrity_scope_source_identity(scope)
        .map_err(map_ledger_failure)?;
    let start = match continuation {
        Some(continuation) if continuation.source_identity != source_identity => {
            return Ok(report(
                mode,
                scope,
                basis.number(),
                0,
                0,
                target_count,
                IntegrityVerificationOutcome::Stale,
                None,
                None,
            ));
        },
        Some(continuation) => match targets
            .iter()
            .position(|candidate| candidate.id == continuation.last_segment)
        {
            Some(position) => position.saturating_add(1),
            None => {
                return Ok(report(
                    mode,
                    scope,
                    basis.number(),
                    0,
                    0,
                    target_count,
                    IntegrityVerificationOutcome::Stale,
                    None,
                    None,
                ));
            },
        },
        None => 0,
    };
    let mut examined_segments = 0_usize;
    let mut examined_bytes = 0_u64;
    let mut last_segment = continuation.map(|cursor| cursor.last_segment);
    for candidate in targets.into_iter().skip(start).take(budget.0) {
        if cancellation.is_cancelled() {
            return Ok(report(
                mode,
                scope,
                basis.number(),
                examined_segments,
                examined_bytes,
                target_count.saturating_sub(start.saturating_add(examined_segments)),
                IntegrityVerificationOutcome::Incomplete,
                None,
                continuation_for(source_identity, last_segment),
            ));
        }
        let physical = match if immutable_scope {
            storage.sealed_compaction_source_bound(*candidate, protection, instance)
        } else {
            Ok(None)
        } {
            Ok(Some((bytes, _))) => u64::try_from(bytes)
                .map_err(|_| IntegrityFailure(IntegrityFailureCode::StorageUnavailable))?,
            Ok(None) => 0,
            Err(failure)
                if mode == IntegrityVerificationMode::Online
                    && immutable_scope
                    && is_isolated_corruption(failure.code()) =>
            {
                let Some(catalog) = catalog else {
                    return Ok(report(
                        mode,
                        scope,
                        basis.number(),
                        examined_segments,
                        examined_bytes,
                        target_count.saturating_sub(start.saturating_add(examined_segments)),
                        IntegrityVerificationOutcome::Fenced,
                        None,
                        None,
                    ));
                };
                if !can_localize_quarantine(*candidate) {
                    return Ok(report(
                        mode,
                        scope,
                        basis.number(),
                        examined_segments,
                        examined_bytes,
                        target_count.saturating_sub(start.saturating_add(examined_segments)),
                        IntegrityVerificationOutcome::Fenced,
                        None,
                        None,
                    ));
                }
                publish_quarantine(catalog, scope, basis, *candidate, transaction)?;
                return Ok(report(
                    mode,
                    scope,
                    basis.number(),
                    examined_segments,
                    examined_bytes,
                    target_count.saturating_sub(start.saturating_add(examined_segments)),
                    IntegrityVerificationOutcome::Quarantined,
                    Some(candidate.id),
                    None,
                ));
            },
            Err(_) => {
                return Ok(report(
                    mode,
                    scope,
                    basis.number(),
                    examined_segments,
                    examined_bytes,
                    target_count.saturating_sub(start.saturating_add(examined_segments)),
                    IntegrityVerificationOutcome::Fenced,
                    None,
                    None,
                ));
            },
        };
        if physical > integrity_bytes_remaining(examined_bytes) {
            return Ok(report(
                mode,
                scope,
                basis.number(),
                examined_segments,
                examined_bytes,
                target_count.saturating_sub(start.saturating_add(examined_segments)),
                IntegrityVerificationOutcome::Incomplete,
                None,
                continuation_for(source_identity, last_segment),
            ));
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
                if mode == IntegrityVerificationMode::Online
                    && immutable_scope
                    && is_isolated_corruption(failure.code()) =>
            {
                let Some(catalog) = catalog else {
                    return Ok(report(
                        mode,
                        scope,
                        basis.number(),
                        examined_segments,
                        examined_bytes,
                        target_count.saturating_sub(start.saturating_add(examined_segments)),
                        IntegrityVerificationOutcome::Fenced,
                        None,
                        None,
                    ));
                };
                if !can_localize_quarantine(*candidate) {
                    return Ok(report(
                        mode,
                        scope,
                        basis.number(),
                        examined_segments,
                        examined_bytes,
                        target_count.saturating_sub(start.saturating_add(examined_segments)),
                        IntegrityVerificationOutcome::Fenced,
                        None,
                        None,
                    ));
                }
                publish_quarantine(catalog, scope, basis, *candidate, transaction)?;
                return Ok(report(
                    mode,
                    scope,
                    basis.number(),
                    examined_segments,
                    examined_bytes,
                    target_count.saturating_sub(start.saturating_add(examined_segments)),
                    IntegrityVerificationOutcome::Quarantined,
                    Some(candidate.id),
                    None,
                ));
            },
            Err(_) => {
                return Ok(report(
                    mode,
                    scope,
                    basis.number(),
                    examined_segments,
                    examined_bytes,
                    target_count.saturating_sub(start.saturating_add(examined_segments)),
                    IntegrityVerificationOutcome::Fenced,
                    None,
                    None,
                ));
            },
        }
    }
    let omitted = target_count.saturating_sub(start.saturating_add(examined_segments));
    Ok(report(
        mode,
        scope,
        basis.number(),
        examined_segments,
        examined_bytes,
        omitted,
        if omitted == 0 {
            IntegrityVerificationOutcome::Verified
        } else {
            IntegrityVerificationOutcome::Incomplete
        },
        None,
        continuation_for(source_identity, last_segment).filter(|_| omitted != 0),
    ))
}

fn integrity_bytes_remaining(examined: u64) -> u64 {
    IntegrityScrubBudget::MAX_BYTES.saturating_sub(examined)
}

#[allow(clippy::too_many_arguments)]
fn report(
    mode: IntegrityVerificationMode,
    scope: SegmentScope,
    catalog_generation: u64,
    examined_segments: usize,
    examined_bytes: u64,
    omitted_segments: usize,
    outcome: IntegrityVerificationOutcome,
    quarantined_segment: Option<SegmentId>,
    continuation: Option<IntegrityScrubContinuation>,
) -> IntegrityVerificationReport {
    IntegrityVerificationReport {
        mode,
        verification_scope: match mode {
            IntegrityVerificationMode::Startup => IntegrityVerificationScope::StartupFrontiers,
            IntegrityVerificationMode::Online | IntegrityVerificationMode::Offline => {
                IntegrityVerificationScope::ReachableImmutableSegments
            },
        },
        scope,
        catalog_generation,
        examined_segments,
        examined_bytes,
        omitted_segments,
        outcome,
        quarantined_segment,
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
