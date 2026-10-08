use std::collections::BTreeSet;

use positron_domain::routing::CommitPosition;

use crate::catalog::{
    CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch, TransactionId,
};
use crate::data_protection::DataProtection;

use super::super::format::SegmentState;
use super::super::recovery::RecoveryMode;
use super::super::snapshot_lease_codec::decode;
use super::super::snapshot_lease_record::{LeaseRecord, SnapshotLeaseId};
use super::super::{
    ActiveSegmentLedger, CommittedBlock, FORMAT_EPOCH, LedgerFailure, LedgerFailureCode,
    LedgerSnapshot, SegmentScope, map_frame_failure,
};

#[path = "snapshot_lease_support/publication.rs"]
mod publication;
#[path = "snapshot_lease_support/recovery.rs"]
mod recovery;

pub(crate) use publication::{
    map_catalog_failure, publish_lease_and_task_removals,
    publish_lease_release_with_task_replacement, publish_lease_replacement_with_task_replacements,
    publish_many, publish_many_with_catalog_objects, publish_many_with_expected_catalog,
    publish_many_with_expected_catalog_snapshot,
};
pub(crate) use recovery::snapshot_from_record;

fn rollback_lease_reservation(
    state: &mut super::super::state::LedgerState<'_>,
    identity: SnapshotLeaseId,
    previous_amounts: crate::ResourceAmounts,
) -> Result<(), LedgerFailure> {
    let reservation = state
        .lease_reservations
        .get_mut(&identity)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    if reservation.granted() != previous_amounts {
        reservation
            .try_resize(previous_amounts)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
    }
    Ok(())
}

pub(crate) struct LeaseReservationTransaction {
    identity: SnapshotLeaseId,
    original: crate::ResourceAmounts,
}

impl LeaseReservationTransaction {
    pub(crate) fn begin(
        state: &mut super::super::state::LedgerState<'_>,
        identity: SnapshotLeaseId,
    ) -> Result<Self, LedgerFailure> {
        let original = state
            .lease_reservation_baselines
            .get(&identity)
            .copied()
            .or_else(|| {
                state
                    .lease_reservations
                    .get(&identity)
                    .map(|value| value.granted())
            })
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        state.lease_reservation_baselines.insert(identity, original);
        Ok(Self { identity, original })
    }

    pub(crate) fn resize(
        &self,
        state: &mut super::super::state::LedgerState<'_>,
        amounts: crate::ResourceAmounts,
    ) -> Result<(), LedgerFailure> {
        let reservation = state
            .lease_reservations
            .get_mut(&self.identity)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        if reservation.granted() != amounts {
            reservation
                .try_resize_preserving_capacity(amounts)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        }
        Ok(())
    }

    pub(crate) fn commit(self, state: &mut super::super::state::LedgerState<'_>) {
        state.lease_reservation_baselines.remove(&self.identity);
    }

    pub(crate) fn cancel(self, state: &mut super::super::state::LedgerState<'_>) {
        state.lease_reservation_baselines.remove(&self.identity);
    }

    pub(crate) fn rollback(
        self,
        state: &mut super::super::state::LedgerState<'_>,
    ) -> Result<(), LedgerFailure> {
        rollback_lease_reservation(state, self.identity, self.original)?;
        state.lease_reservation_baselines.remove(&self.identity);
        Ok(())
    }
}

pub(crate) fn active_segments(
    snapshot: &crate::CatalogSnapshot,
    scope: SegmentScope,
    now: u64,
) -> Result<BTreeSet<super::super::SegmentId>, LedgerFailure> {
    let mut segments = BTreeSet::new();
    for record in records(snapshot)? {
        if record.scope == scope && now < record.expiry {
            for block in record.blocks {
                segments.insert(block.segment);
            }
        }
    }
    Ok(segments)
}

/// Returns the latest durable lease expiry that still protects one segment.
pub(crate) fn reclamation_lease_expiry(
    snapshot: &crate::CatalogSnapshot,
    scope: SegmentScope,
    segment: super::super::SegmentId,
    now: u64,
) -> Result<Option<u64>, LedgerFailure> {
    records(snapshot)?
        .into_iter()
        .try_fold(None, |latest, record| {
            if record.scope != scope
                || now >= record.expiry
                || !record.blocks.iter().any(|block| block.segment == segment)
            {
                return Ok(latest);
            }
            Ok(Some(latest.map_or(record.expiry, |previous: u64| {
                previous.max(record.expiry)
            })))
        })
}

pub(super) fn publish(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Option<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    publish_many(catalog, basis, remove, add.into_iter().collect())
}

pub(crate) fn expired_in_scope(
    records: &[LeaseRecord],
    scope: SegmentScope,
    now: u64,
) -> BTreeSet<SnapshotLeaseId> {
    records
        .iter()
        .filter(|record| record.scope == scope && now >= record.expiry)
        .map(|record| record.identity)
        .collect()
}

pub(super) fn reject_time_regression(
    state: &super::super::state::LedgerState<'_>,
    now: u64,
) -> Result<(), LedgerFailure> {
    if now < state.last_snapshot_lease_time {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    Ok(())
}

pub(super) fn remove_reservations(
    state: &mut super::super::state::LedgerState<'_>,
    identities: &BTreeSet<SnapshotLeaseId>,
) {
    for identity in identities {
        state.lease_reservations.remove(identity);
        state.lease_reservation_baselines.remove(identity);
        state.lease_resume_markers.remove(identity);
        state.pending_lease_releases.remove(*identity);
    }
}

pub(crate) fn records(
    snapshot: &crate::CatalogSnapshot,
) -> Result<Vec<LeaseRecord>, LedgerFailure> {
    let mut records = Vec::new();
    records
        .try_reserve_exact(snapshot.plaintext_objects().count())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in snapshot.plaintext_objects() {
        if let Some(record) = decode(bytes)? {
            records.push(record);
        }
    }
    Ok(records)
}

pub(crate) fn fresh_identity() -> Result<SnapshotLeaseId, LedgerFailure> {
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let bytes = random
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
    SnapshotLeaseId::new(bytes)
}
