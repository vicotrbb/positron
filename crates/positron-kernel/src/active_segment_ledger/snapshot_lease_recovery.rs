use std::collections::{BTreeMap, BTreeSet};

use crate::{
    MaintenanceCoordinator, MaintenanceFailure, MaintenanceTaskClass, MaintenanceTaskId,
    MaintenanceTaskPhase, ResourceReservation, WorkClaim, WorkKind,
};

use super::capacity::lease_claim;
use super::snapshot_lease::{MAX_SNAPSHOT_LEASES, expired_in_scope, publish_many, records};
use super::snapshot_lease_codec::encode;
use super::snapshot_lease_record::{LeaseResumeMarker, SnapshotLeaseId, validate_active_lease};
use super::{LedgerFailure, LedgerFailureCode, SegmentScope};

pub(super) struct RecoveredLeases<'kernel> {
    pub(super) reservations: BTreeMap<SnapshotLeaseId, ResourceReservation<'kernel>>,
    pub(super) resume_markers: BTreeMap<SnapshotLeaseId, LeaseResumeMarker>,
    pub(super) last_observed: u64,
}

#[derive(Clone, Copy)]
enum LeaseRecoveryObservation {
    Unavailable,
    Current(u64),
    ConservativeFloor,
}

pub(super) enum LeaseRecoveryClock {
    Conservative,
    Strict(Option<u64>),
}

impl LeaseRecoveryObservation {
    fn from_durable(now: Option<u64>, persisted_floor: u64) -> Self {
        match now {
            Some(now) if now < persisted_floor => Self::ConservativeFloor,
            Some(now) => Self::Current(now),
            None if persisted_floor != 0 => Self::ConservativeFloor,
            None => Self::Unavailable,
        }
    }

    const fn expiry_time(self) -> Option<u64> {
        match self {
            Self::Current(now) => Some(now),
            Self::Unavailable | Self::ConservativeFloor => None,
        }
    }
}

fn protected_coupled_leases(
    catalog: &crate::Catalog<'_>,
    leases: &BTreeSet<SnapshotLeaseId>,
) -> Result<BTreeSet<SnapshotLeaseId>, LedgerFailure> {
    if leases.is_empty() {
        return Ok(BTreeSet::new());
    }
    let coordinator = MaintenanceCoordinator::restore_from_catalog(catalog)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
    let mut protected = BTreeSet::new();
    for lease in leases {
        let task = MaintenanceTaskId::new(lease.to_bytes())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        match coordinator.status(task) {
            Ok(status) => {
                if status.task().class() != MaintenanceTaskClass::SnapshotLeaseExpiry {
                    return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                }
                if matches!(
                    status.phase(),
                    MaintenanceTaskPhase::Queued
                        | MaintenanceTaskPhase::Running
                        | MaintenanceTaskPhase::Deferred
                ) {
                    protected.insert(*lease);
                }
            },
            Err(MaintenanceFailure::UnknownTask) => {},
            Err(_) => return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired)),
        }
    }
    Ok(protected)
}

pub(super) fn recover_reservations<'kernel>(
    ledger_authority: &'kernel crate::StorageKernelResourceAuthority,
    catalog: &crate::Catalog<'_>,
    scope: SegmentScope,
    snapshot: &crate::CatalogSnapshot,
    clock: LeaseRecoveryClock,
) -> Result<RecoveredLeases<'kernel>, LedgerFailure> {
    let scoped = records(snapshot)?
        .into_iter()
        .filter(|record| record.scope == scope)
        .collect::<Vec<_>>();
    let persisted_last_observed = scoped
        .iter()
        .map(|record| record.observed_at)
        .max()
        .unwrap_or(0);
    let observation = match clock {
        // A retention-time opener is not the expiry handler. It may recover a
        // scope after the lease becomes due, but must leave the coupled lease
        // and its durable expiry descriptor for the coordinator to terminalize
        // together. Removing only the lease would make the Running task
        // unrecoverable after a crash or a competing Catalog publication.
        LeaseRecoveryClock::Conservative => LeaseRecoveryObservation::ConservativeFloor,
        LeaseRecoveryClock::Strict(now) => {
            if now.is_some_and(|now| now < persisted_last_observed) {
                return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
            }
            LeaseRecoveryObservation::from_durable(now, persisted_last_observed)
        },
    };
    let expiry_time = observation.expiry_time();
    let expired =
        expiry_time.map_or_else(BTreeSet::new, |now| expired_in_scope(&scoped, scope, now));
    // A recovered lease can predate a task handler. Retain every nonterminal
    // paired lease unchanged until that handler can atomically replace both
    // durable records. Rewriting only `observed_at` also changes the task's
    // immutable binding, so it is just as invalid as removing only a due
    // lease. Legacy unpaired leases still reclaim through this path.
    let leases = scoped
        .iter()
        .map(|record| record.identity)
        .collect::<BTreeSet<_>>();
    let protected = protected_coupled_leases(catalog, &leases)?;
    let removable = expired
        .difference(&protected)
        .copied()
        .collect::<BTreeSet<_>>();
    let mut active = scoped
        .into_iter()
        .filter(|record| !removable.contains(&record.identity))
        .collect::<Vec<_>>();
    for record in &active {
        let validation_time = if protected.contains(&record.identity) {
            record.observed_at
        } else {
            expiry_time.unwrap_or(record.observed_at)
        };
        validate_active_lease(record, validation_time)?;
    }
    if active.len() > MAX_SNAPSHOT_LEASES {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    if let Some(now) = expiry_time.filter(|now| {
        !removable.is_empty()
            || active
                .iter()
                .any(|record| !protected.contains(&record.identity) && record.observed_at != *now)
    }) {
        let remove = active
            .iter()
            .filter(|record| !protected.contains(&record.identity))
            .map(|record| record.identity)
            .chain(removable.iter().copied())
            .collect::<BTreeSet<_>>();
        for record in &mut active {
            if !protected.contains(&record.identity) {
                record.observed_at = now;
            }
        }
        let additions = active
            .iter()
            .filter(|record| !protected.contains(&record.identity))
            .map(encode)
            .collect::<Result<Vec<_>, _>>()?;
        publish_many(catalog, snapshot, &remove, additions)?;
    }
    let mut retained = BTreeMap::new();
    let mut resume_markers = BTreeMap::new();
    for record in active {
        if record.resume_count > 0 {
            resume_markers.insert(
                record.identity,
                LeaseResumeMarker {
                    sequence: record.last_resume_sequence.unwrap_or_default(),
                    prior_digest: record.last_resume_prior_digest,
                    attempts: record.resume_count,
                    repeats: record.repeated_batch_count,
                    usage: record.usage,
                },
            );
        }
        let encoded = encode(&record)?;
        let claim = WorkClaim::tenant(
            scope.tenant,
            WorkKind::InteractiveQueryTail,
            lease_claim(encoded.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let reservation = ledger_authority
            .governor()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        if retained.insert(record.identity, reservation).is_some() {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
    }
    Ok(RecoveredLeases {
        reservations: retained,
        resume_markers,
        last_observed: if persisted_last_observed == 0 {
            0
        } else {
            expiry_time.unwrap_or(persisted_last_observed)
        },
    })
}
