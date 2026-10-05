//! Catalog publication and discovery for bounded integrity quarantine evidence.

use crate::{CatalogObject, CatalogProposal, TransactionId};

use super::super::{SegmentId, SegmentScope};
use super::{
    IntegrityFailure, IntegrityFailureCode, IntegrityQuarantineFinding, MAX_QUARANTINE_FINDINGS,
    decode_quarantine, encode_quarantine, map_catalog_failure,
};

pub fn publish_quarantine(
    catalog: &crate::Catalog<'_>,
    scope: SegmentScope,
    basis: &crate::CatalogSnapshot,
    metadata: super::super::format::SegmentMetadata,
    transaction: TransactionId,
) -> Result<(), IntegrityFailure> {
    let existing = quarantined_segment_ids(basis, scope)?;
    if existing.contains(&metadata.id) {
        return Ok(());
    }
    if quarantine_finding_count(basis)? >= MAX_QUARANTINE_FINDINGS {
        return Err(IntegrityFailure(IntegrityFailureCode::FindingCapacity));
    }
    let capacity = basis
        .object_count()
        .checked_add(1)
        .ok_or(IntegrityFailure(IntegrityFailureCode::FindingCapacity))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(capacity)
        .map_err(|_| IntegrityFailure(IntegrityFailureCode::FindingCapacity))?;
    for identity in basis.object_identities() {
        let object = basis
            .object(identity)
            .map_err(map_catalog_failure)?
            .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
        objects.push(CatalogObject::new(object.to_vec()).map_err(map_catalog_failure)?);
    }
    objects.push(CatalogObject::new(encode_quarantine(metadata)?).map_err(map_catalog_failure)?);
    let epoch = basis
        .format_epoch()
        .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
    let proposal =
        CatalogProposal::new(transaction, epoch, objects).map_err(map_catalog_failure)?;
    catalog
        .commit(basis.identity(), proposal, None)
        .map_err(map_catalog_failure)?;
    Ok(())
}

pub fn integrity_quarantine_findings(
    snapshot: &crate::CatalogSnapshot,
) -> Result<Vec<IntegrityQuarantineFinding>, IntegrityFailure> {
    let mut findings = Vec::new();
    for identity in snapshot.object_identities() {
        let object = snapshot
            .object(identity)
            .map_err(map_catalog_failure)?
            .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
        let Some((scope, segment, base_position, sealed_frontier, event_range, ingest_range)) =
            decode_quarantine(object)?
        else {
            continue;
        };
        findings
            .try_reserve(1)
            .map_err(|_| IntegrityFailure(IntegrityFailureCode::FindingCapacity))?;
        findings.push(IntegrityQuarantineFinding {
            scope,
            segment,
            base_position,
            sealed_frontier,
            event_range,
            ingest_range,
        });
        if findings.len() > MAX_QUARANTINE_FINDINGS {
            return Err(IntegrityFailure(IntegrityFailureCode::FindingCapacity));
        }
    }
    Ok(findings)
}

pub fn quarantined_segment_ids(
    snapshot: &crate::CatalogSnapshot,
    scope: SegmentScope,
) -> Result<Vec<SegmentId>, IntegrityFailure> {
    integrity_quarantine_findings(snapshot).map(|findings| {
        findings
            .into_iter()
            .filter(|finding| finding.scope == scope)
            .map(|finding| finding.segment)
            .collect()
    })
}

fn quarantine_finding_count(snapshot: &crate::CatalogSnapshot) -> Result<usize, IntegrityFailure> {
    let mut findings = 0_usize;
    for identity in snapshot.object_identities() {
        let object = snapshot
            .object(identity)
            .map_err(map_catalog_failure)?
            .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
        if decode_quarantine(object)?.is_some() {
            findings = findings
                .checked_add(1)
                .filter(|count| *count <= MAX_QUARANTINE_FINDINGS)
                .ok_or(IntegrityFailure(IntegrityFailureCode::FindingCapacity))?;
        }
    }
    Ok(findings)
}

#[cfg(fuzzing)]
pub(super) fn fuzz_quarantine_record(data: &[u8]) {
    // The record is catalog-authenticated in production; fuzzing still proves
    // malformed retained evidence cannot panic or manufacture a valid scope.
    let _ = decode_quarantine(data);
}
