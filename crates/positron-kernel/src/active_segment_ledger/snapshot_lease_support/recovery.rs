use super::*;

pub(crate) fn snapshot_from_record<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    state: &super::super::super::state::LedgerState<'kernel>,
    lease_basis: &crate::CatalogSnapshot,
    record: &LeaseRecord,
) -> Result<LedgerSnapshot<'kernel>, LedgerFailure> {
    if record.scope != ledger.scope || record.frontier > state.frontier {
        return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
    }
    let maximum_bytes = record.blocks.iter().try_fold(0_usize, |total, expected| {
        let bytes = state
            .blocks
            .iter()
            .find(|actual| {
                actual.identity == expected.identity
                    && actual.position == expected.position
                    && actual.segment == expected.segment
            })
            .map_or(super::super::super::MAX_STORE_BLOCK_BYTES, |block| {
                block.payload.len()
            });
        total
            .checked_add(bytes)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
    })?;
    // The current Catalog generation authenticates the lease/expiry pair.
    // Pin the generation recorded by that pair before admitting recovery, so
    // a later publication cannot substitute a lease segment identity.
    let original_basis = ledger
        .catalog
        .pin_historical_generation(
            lease_basis,
            record.catalog_identity,
            record.catalog_generation,
        )
        .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
    let recovery = resume_recovery_plan(ledger, state, &original_basis, lease_basis, record)?;
    let admitted = if recovery.segments.is_empty() {
        // Creating a lease clones only already-retained blocks. The caller's
        // admitted query task covers construction work, while this claim must
        // precede and cover the retained clone allocation itself.
        super::super::super::capacity::snapshot_retained_claim(maximum_bytes, record.blocks.len())?
    } else {
        let recovery_working_bytes = recovery
            .encoded_bytes
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(maximum_bytes))
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let recovery_items = recovery
            .segments
            .len()
            .checked_mul(super::super::super::MAX_RETAINED_BLOCKS)
            .and_then(|items| items.checked_add(record.blocks.len()))
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        super::super::super::capacity::snapshot_resume_claim(
            recovery_working_bytes,
            recovery.encoded_bytes,
            recovery_items,
            recovery.segments.len(),
        )?
    };
    let maximum_claim = crate::WorkClaim::tenant(
        record.scope.tenant,
        crate::WorkKind::InteractiveQueryTail,
        admitted,
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut capacity = ledger
        .authority
        .governor()
        .reserve(maximum_claim)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    // The recorded basis binds cursor identity. A current authenticated
    // quarantine is a safety overlay: a cursor must never resume and hand a
    // newly quarantined leased segment to query execution.
    let mut quarantined_holes =
        super::super::super::integrity::integrity_quarantine_findings(&original_basis)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            .into_iter()
            .filter(|finding| finding.scope() == record.scope)
            .collect::<Vec<_>>();
    let leased_segments = record
        .blocks
        .iter()
        .map(|block| block.segment)
        .collect::<BTreeSet<_>>();
    for finding in super::super::super::integrity::integrity_quarantine_findings(lease_basis)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
        .into_iter()
        .filter(|finding| {
            finding.scope() == record.scope && leased_segments.contains(&finding.segment())
        })
    {
        if !quarantined_holes
            .iter()
            .any(|existing| existing.segment() == finding.segment())
        {
            quarantined_holes
                .try_reserve(1)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            quarantined_holes.push(finding);
        }
    }
    quarantined_holes.sort_unstable_by_key(|finding| finding.base_position());
    let empty_frontier_is_quarantined = record.blocks.is_empty()
        && quarantined_holes
            .iter()
            .any(|finding| finding.sealed_frontier() >= record.frontier);
    let blocks = blocks_for_record(
        ledger,
        state,
        record,
        &recovery.segments,
        empty_frontier_is_quarantined,
    )?;
    let bytes = blocks
        .iter()
        .try_fold(0_usize, |total, block| {
            total.checked_add(block.payload.len())
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    capacity
        .try_resize_preserving_capacity(super::super::super::capacity::snapshot_retained_claim(
            bytes,
            blocks.len(),
        )?)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    Ok(LedgerSnapshot {
        _capacity: capacity,
        _protection: super::super::super::snapshot_protection::SnapshotProtection::for_blocks(
            ledger.authority.snapshot_protection(),
            ledger.authority.snapshot_barrier(),
            &blocks,
        )?,
        scope: record.scope,
        frontier: record.frontier,
        catalog_generation: record.catalog_generation,
        catalog_identity: record.catalog_identity,
        blocks,
        quarantined_holes,
    })
}

struct ResumeRecoveryPlan {
    segments: Vec<super::super::super::format::SegmentMetadata>,
    encoded_bytes: usize,
}

fn resume_recovery_plan(
    ledger: &ActiveSegmentLedger<'_, '_>,
    state: &super::super::super::state::LedgerState<'_>,
    original_basis: &crate::CatalogSnapshot,
    current_basis: &crate::CatalogSnapshot,
    record: &LeaseRecord,
) -> Result<ResumeRecoveryPlan, LedgerFailure> {
    let mut missing = BTreeSet::new();
    for expected in &record.blocks {
        let exact = state.blocks.iter().any(|actual| {
            actual.identity == expected.identity
                && actual.position == expected.position
                && actual.segment == expected.segment
        });
        if exact {
            continue;
        }
        if state.blocks.iter().any(|actual| {
            actual.position == expected.position && actual.segment == expected.segment
        }) || state
            .blocks
            .iter()
            .any(|actual| actual.segment == expected.segment)
        {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        missing.insert(expected.segment);
    }
    if missing.is_empty() {
        return Ok(ResumeRecoveryPlan {
            segments: Vec::new(),
            encoded_bytes: 0,
        });
    }
    let original_metadata = ledger
        .storage
        .catalog_segments_historical(original_basis, record.scope)?;
    let current_metadata = ledger
        .storage
        .catalog_segments_observed(current_basis, record.scope)?;
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(missing.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut encoded_bytes = 0_usize;
    for identity in missing {
        if !original_metadata
            .iter()
            .any(|candidate| candidate.id == identity)
        {
            return Err(LedgerFailure::new(LedgerFailureCode::SnapshotExpired));
        }
        let segment = current_metadata
            .iter()
            .find(|candidate| {
                candidate.id == identity
                    && matches!(
                        candidate.state,
                        SegmentState::Sealed | SegmentState::Retired
                    )
            })
            .copied()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::SnapshotExpired))?;
        encoded_bytes = encoded_bytes
            .checked_add(ledger.storage.snapshot_recovery_encoded_bytes(segment)?)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        segments.push(segment);
    }
    Ok(ResumeRecoveryPlan {
        segments,
        encoded_bytes,
    })
}

fn blocks_for_record<'kernel>(
    ledger: &ActiveSegmentLedger<'kernel, '_>,
    state: &super::super::super::state::LedgerState<'kernel>,
    record: &LeaseRecord,
    missing_metadata: &[super::super::super::format::SegmentMetadata],
    empty_frontier_is_quarantined: bool,
) -> Result<Vec<CommittedBlock>, LedgerFailure> {
    let mut missing_segments = BTreeSet::new();
    for expected in &record.blocks {
        let exact = state.blocks.iter().any(|actual| {
            actual.identity == expected.identity
                && actual.position == expected.position
                && actual.segment == expected.segment
        });
        if exact {
            continue;
        }
        missing_segments.insert(expected.segment);
    }

    let mut recovered = Vec::new();
    recovered
        .try_reserve_exact(record.blocks.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if !missing_segments.is_empty() {
        for metadata in missing_metadata.iter().copied() {
            let (_key, recovered_segment) = ledger.storage.recover_segment_with_mode(
                metadata,
                &ledger.protection,
                ledger.catalog.instance(),
                RecoveryMode::Observe,
            )?;
            recovered.extend(recovered_segment.blocks);
        }
    }

    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(record.blocks.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for expected in &record.blocks {
        let block = state
            .blocks
            .iter()
            .find(|actual| {
                actual.identity == expected.identity
                    && actual.position == expected.position
                    && actual.segment == expected.segment
            })
            .or_else(|| {
                recovered.iter().find(|actual| {
                    actual.identity == expected.identity
                        && actual.position == expected.position
                        && actual.segment == expected.segment
                })
            })
            .ok_or_else(|| {
                if recovered
                    .iter()
                    .any(|actual| actual.segment == expected.segment)
                {
                    LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)
                } else {
                    LedgerFailure::new(LedgerFailureCode::SnapshotExpired)
                }
            })?;
        blocks.push(block.clone());
    }
    let mut previous_position = None;
    for block in &blocks {
        if previous_position.is_some_and(|previous| block.position <= previous) {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        previous_position = Some(block.position);
    }
    if !(blocks.is_empty() && empty_frontier_is_quarantined)
        && blocks
            .last()
            .map_or(CommitPosition::origin(), |block| block.position)
            != record.frontier
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    Ok(blocks)
}
