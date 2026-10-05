use std::collections::BTreeSet;

use positron_domain::routing::CommitPosition;

use crate::IngestTime;
use crate::catalog::{
    Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, FormatEpoch, MAX_CATALOG_OBJECTS,
    MAX_CATALOG_TOTAL_BYTES, TransactionId,
};
use crate::data_protection::DataProtection;

use super::format::{SegmentMetadata, SegmentState};
use super::storage::LedgerStorage;
use super::{
    FORMAT_EPOCH, LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope, map_frame_failure,
};

struct PublicationOptions<'clock> {
    frontier: Option<IngestTime>,
    anchor: Option<IngestTime>,
    lifecycle_clock: Option<&'clock crate::retention_time::StagedCatalogAnchor<'clock>>,
    exact_scope: bool,
    additional: Vec<CatalogObject>,
    replaced_tasks: BTreeSet<crate::MaintenanceTaskId>,
}

pub(super) struct RetentionPublication<'clock, 'authority, 'metadata> {
    pub(super) lifecycle_clock: &'clock crate::retention_time::StagedCatalogAnchor<'authority>,
    pub(super) scope: SegmentScope,
    pub(super) metadata: &'metadata [SegmentMetadata],
    pub(super) frontier: IngestTime,
    pub(super) anchor: IngestTime,
    pub(super) additional: Vec<CatalogObject>,
    pub(super) replaced_tasks: BTreeSet<crate::MaintenanceTaskId>,
}

pub(super) fn fresh_metadata(
    scope: SegmentScope,
    base_position: CommitPosition,
) -> Result<SegmentMetadata, LedgerFailure> {
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        random
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
    );
    Ok(SegmentMetadata {
        scope,
        id: SegmentId::new(bytes)?,
        state: SegmentState::Active,
        base_position,
    })
}

pub(super) fn publish_segments(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(
        catalog,
        basis,
        storage,
        scope,
        metadata,
        PublicationOptions {
            frontier: None,
            anchor: None,
            lifecycle_clock: None,
            exact_scope: false,
            additional: Vec::new(),
            replaced_tasks: BTreeSet::new(),
        },
    )
}

pub(super) fn publish_exact_scope_segments(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(
        catalog,
        basis,
        storage,
        scope,
        metadata,
        PublicationOptions {
            frontier: None,
            anchor: None,
            lifecycle_clock: None,
            exact_scope: true,
            additional: Vec::new(),
            replaced_tasks: BTreeSet::new(),
        },
    )
}

pub(super) fn publish_exact_scope_segments_with_task_replacement(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    replacement: crate::MaintenanceTaskId,
    terminal: CatalogObject,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    let mut replaced_tasks = BTreeSet::new();
    replaced_tasks.insert(replacement);
    publish_scope(
        catalog,
        basis,
        storage,
        scope,
        metadata,
        PublicationOptions {
            frontier: None,
            anchor: None,
            lifecycle_clock: None,
            exact_scope: true,
            additional: vec![terminal],
            replaced_tasks,
        },
    )
}

pub(super) fn publish_segments_with_frontier(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    lifecycle_clock: &crate::retention_time::StagedCatalogAnchor<'_>,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    frontier: IngestTime,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(
        catalog,
        basis,
        storage,
        scope,
        metadata,
        PublicationOptions {
            frontier: Some(frontier),
            anchor: Some(frontier),
            lifecycle_clock: Some(lifecycle_clock),
            exact_scope: false,
            additional: Vec::new(),
            replaced_tasks: BTreeSet::new(),
        },
    )
}

pub(super) fn publish_retention_with_tasks(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    publication: RetentionPublication<'_, '_, '_>,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_scope(
        catalog,
        basis,
        storage,
        publication.scope,
        publication.metadata,
        PublicationOptions {
            frontier: Some(publication.frontier),
            anchor: Some(publication.anchor),
            lifecycle_clock: Some(publication.lifecycle_clock),
            exact_scope: false,
            additional: publication.additional,
            replaced_tasks: publication.replaced_tasks,
        },
    )
}

fn publish_scope(
    catalog: &Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    options: PublicationOptions<'_>,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    let (object_capacity, total_bytes) =
        publication_preflight(basis, storage, scope, metadata, &options)?;
    if object_capacity > MAX_CATALOG_OBJECTS || total_bytes > MAX_CATALOG_TOTAL_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(object_capacity)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let mut lifecycle_anchor_seen = false;
    for bytes in basis.plaintext_objects() {
        if !retains_basis_object(storage, scope, &options, bytes, &mut lifecycle_anchor_seen)? {
            continue;
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        retained.extend_from_slice(bytes);
        objects.push(CatalogObject::new(retained)?);
    }
    let PublicationOptions {
        frontier,
        anchor,
        lifecycle_clock,
        exact_scope,
        additional,
        replaced_tasks: _,
    } = options;
    for segment in metadata {
        objects.push(CatalogObject::new(storage.metadata_object(*segment))?);
    }
    if let Some(frontier) = frontier {
        objects.push(CatalogObject::new(super::retention_frontier::encode(
            scope, frontier,
        ))?);
    }
    if let (Some(clock), Some(anchor)) = (lifecycle_clock, anchor) {
        objects.push(CatalogObject::new(
            clock
                .catalog_anchor_record(anchor)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
        )?);
    }
    let additional_ids = additional
        .iter()
        .map(CatalogObject::identity)
        .collect::<Vec<_>>();
    objects.extend(additional);
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(
        random
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
    );
    let publication = catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            basis
                .format_epoch()
                .unwrap_or(FormatEpoch::new(FORMAT_EPOCH)?),
            objects,
        )?,
        None,
    );
    match publication {
        Ok(commit) => Ok(commit.snapshot().clone()),
        Err(failure) => {
            // A generation marker rename may have made the proposal durable
            // before its directory synchronization reported failure. Reconcile
            // the catalog authority before exposing an ordinary rejection to
            // callers whose live ledger still reflects the prior generation.
            if failure.code() != CatalogFailureCode::StorageUnavailable {
                return Err(failure.into());
            }
            catalog
                .refresh_state()
                .map_err(|failure| LedgerFailure::ambiguous(LedgerFailure::from(failure).code()))?;
            let snapshot = catalog
                .pin()
                .map_err(|failure| LedgerFailure::ambiguous(LedgerFailure::from(failure).code()))?;
            if snapshot.identity() == basis.identity() {
                return Err(failure.into());
            }
            let segments = storage.catalog_segments(&snapshot, scope)?;
            let segments_subsume = metadata.iter().all(|expected| segments.contains(expected))
                && (!exact_scope || segments.len() == metadata.len());
            let frontier_subsumed = match frontier {
                Some(expected) => super::retention_frontier::recover(&snapshot, scope)?
                    .is_some_and(|published| published >= expected),
                None => true,
            };
            let anchor_subsumed = lifecycle_clock.map_or(Ok(true), |clock| {
                clock
                    .catalog_anchor_subsumed(&snapshot)
                    .map_err(|_| LedgerFailure::ambiguous(LedgerFailureCode::StorageUnavailable))
            })?;
            let tasks_subsumed = additional_ids.iter().try_fold(true, |visible, identity| {
                Ok::<_, LedgerFailure>(visible && snapshot.object(*identity)?.is_some())
            })?;
            if snapshot.number() > basis.number()
                && segments_subsume
                && frontier_subsumed
                && anchor_subsumed
                && tasks_subsumed
            {
                Ok(snapshot)
            } else {
                Err(LedgerFailure::ambiguous(LedgerFailureCode::StaleGeneration))
            }
        },
    }
}

fn publication_preflight(
    basis: &crate::CatalogSnapshot,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
    options: &PublicationOptions<'_>,
) -> Result<(usize, usize), LedgerFailure> {
    let mut count = 0_usize;
    let mut total_bytes = 0_usize;
    let mut lifecycle_anchor_seen = false;
    for candidate in basis.plaintext_objects() {
        if !retains_basis_object(
            storage,
            scope,
            options,
            candidate,
            &mut lifecycle_anchor_seen,
        )? {
            continue;
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        total_bytes = total_bytes
            .checked_add(candidate.len())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    }
    let metadata_bytes = metadata
        .len()
        .checked_mul(super::format::METADATA_BYTES)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    count = count
        .checked_add(metadata.len())
        .and_then(|value| value.checked_add(usize::from(options.frontier.is_some())))
        .and_then(|value| value.checked_add(usize::from(options.lifecycle_clock.is_some())))
        .and_then(|value| value.checked_add(options.additional.len()))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    total_bytes = total_bytes
        .checked_add(metadata_bytes)
        .and_then(|value| {
            value.checked_add(if options.frontier.is_some() {
                super::retention_frontier::RECORD_BYTES
            } else {
                0
            })
        })
        .and_then(|value| {
            value.checked_add(if options.lifecycle_clock.is_some() {
                crate::retention_time::CATALOG_ANCHOR_RECORD_BYTES
            } else {
                0
            })
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for object in &options.additional {
        total_bytes = total_bytes
            .checked_add(object.plaintext_len())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    }
    Ok((count, total_bytes))
}

fn retains_basis_object(
    storage: &LedgerStorage,
    scope: SegmentScope,
    options: &PublicationOptions<'_>,
    candidate: &[u8],
    lifecycle_anchor_seen: &mut bool,
) -> Result<bool, LedgerFailure> {
    if storage.is_scope_metadata(candidate, scope) {
        return Ok(false);
    }
    if crate::maintenance::durable_task_record_identity(candidate)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
        .is_some_and(|identity| options.replaced_tasks.contains(&identity))
    {
        return Ok(false);
    }
    if options.frontier.is_some()
        && super::retention_frontier::decode(candidate)?
            .is_some_and(|(candidate_scope, _)| candidate_scope == scope)
    {
        return Ok(false);
    }
    let lifecycle_anchor =
        crate::retention_time::validate_catalog_anchor_singleton(candidate, lifecycle_anchor_seen)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    Ok(options.lifecycle_clock.is_none() || !lifecycle_anchor)
}
