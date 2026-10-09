//! Explicit data-loss confirmation and immutable abandonment evidence.

use sha2::{Digest, Sha256};

use super::format::{SegmentState, decode_metadata};
use super::integrity::{decode_quarantine, integrity_quarantine_findings};
use super::{
    IntegrityFailure, IntegrityFailureCode, IntegrityQuarantineFinding, SegmentId, SegmentScope,
};
use crate::{CatalogObject, CatalogSnapshot};

pub(super) const ABANDONMENT_MAGIC: &[u8; 8] = b"PABAND01";

/// A read-only, generation-bound preview of the exact acknowledged data lost.
/// Confirming returns a proposal, never writes files or fabricates valid bytes.
pub struct SegmentAbandonmentPlan {
    finding: IntegrityQuarantineFinding,
    confirmation: [u8; 32],
    objects: Vec<CatalogObject>,
}

impl SegmentAbandonmentPlan {
    pub fn preflight(
        snapshot: &CatalogSnapshot,
        scope: SegmentScope,
        segment: SegmentId,
    ) -> Result<Self, IntegrityFailure> {
        let finding = integrity_quarantine_findings(snapshot)?
            .into_iter()
            .find(|finding| {
                finding.scope() == scope && finding.segment() == segment && !finding.is_abandoned()
            })
            .ok_or(IntegrityFailure(IntegrityFailureCode::InvalidInput))?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| IntegrityFailure(IntegrityFailureCode::FindingCapacity))?;
        let mut removed = false;
        let mut evidence = false;
        let mut digest = Sha256::new();
        digest.update(b"positron.segment-abandonment.confirmation.v1\0");
        digest.update(snapshot.identity().to_bytes());
        digest.update(snapshot.number().to_be_bytes());
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(super::integrity::map_catalog_failure)?
                .ok_or(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?;
            if let Some(metadata) = decode_metadata(bytes)
                .map_err(|_| IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity))?
                && metadata.scope == scope
                && metadata.id == segment
            {
                if removed
                    || metadata.state != SegmentState::Sealed
                    || metadata.base_position.value() != finding.base_position()
                    || metadata.sealed_frontier != Some(finding.sealed_frontier())
                    || metadata.event_range != finding.event_range()
                    || metadata.ingest_range != finding.ingest_range()
                {
                    return Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity));
                }
                removed = true;
                continue;
            }
            let bytes = if let Some((record_scope, record_segment, ..)) = decode_quarantine(bytes)?
                && record_scope == scope
                && record_segment == segment
            {
                if evidence {
                    return Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity));
                }
                evidence = true;
                digest.update(bytes);
                [ABANDONMENT_MAGIC.as_slice(), bytes].concat()
            } else {
                bytes.to_vec()
            };
            objects.push(CatalogObject::new(bytes).map_err(super::integrity::map_catalog_failure)?);
        }
        if !removed || !evidence {
            return Err(IntegrityFailure(IntegrityFailureCode::AmbiguousIntegrity));
        }
        Ok(Self {
            finding,
            confirmation: digest.finalize().into(),
            objects,
        })
    }

    #[must_use]
    pub const fn finding(&self) -> IntegrityQuarantineFinding {
        self.finding
    }
    #[must_use]
    pub const fn confirmation_digest(&self) -> [u8; 32] {
        self.confirmation
    }

    /// Requires the complete preview commitment. Administration must jointly
    /// publish these objects with its durable operation and governance audit.
    pub fn confirm(self, confirmation: [u8; 32]) -> Result<Vec<CatalogObject>, IntegrityFailure> {
        if confirmation != self.confirmation {
            return Err(IntegrityFailure(IntegrityFailureCode::InvalidInput));
        }
        Ok(self.objects)
    }
}

pub fn integrity_abandonment_findings(
    snapshot: &CatalogSnapshot,
) -> Result<Vec<IntegrityQuarantineFinding>, IntegrityFailure> {
    Ok(integrity_quarantine_findings(snapshot)?
        .into_iter()
        .filter(|finding| finding.is_abandoned())
        .collect())
}
