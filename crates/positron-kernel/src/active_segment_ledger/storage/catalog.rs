use crate::catalog::CatalogSnapshot;
use rustix::fs::{self as unix_fs, AtFlags, Dir};

use super::super::format::{SegmentMetadata, SegmentState, decode_metadata};
use super::super::io::{map_errno, synchronize};
use super::super::recovery::{frontier_name, frontier_temporary_name, segment_name};
use super::super::{LedgerFailure, LedgerFailureCode, SegmentScope};
use super::{LedgerStorage, MAX_SEGMENTS};

impl LedgerStorage {
    pub(crate) fn catalog_segments(
        &self,
        snapshot: &CatalogSnapshot,
        scope: SegmentScope,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        self.catalog_segments_mode(snapshot, scope, true)
    }

    pub(crate) fn catalog_segments_observed(
        &self,
        snapshot: &CatalogSnapshot,
        scope: SegmentScope,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        self.catalog_segments_mode(snapshot, scope, false)
    }

    /// Returns metadata named by an authenticated historical Catalog snapshot.
    ///
    /// A historical snapshot intentionally predates later copy-on-write
    /// publications, so its closed-world view does not describe every current
    /// directory entry. Callers must recover only the returned, named artifacts
    /// through the normal authenticated recovery path.
    pub(crate) fn catalog_segments_historical(
        &self,
        snapshot: &CatalogSnapshot,
        scope: SegmentScope,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        self.catalog_segments_from_snapshot(snapshot, scope)
    }

    fn catalog_segments_mode(
        &self,
        snapshot: &CatalogSnapshot,
        scope: SegmentScope,
        repair: bool,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        let all_segments = self.decode_catalog_segments(snapshot)?;
        self.reject_unpublished_entries(&all_segments, snapshot, repair)?;
        Self::segments_for_scope(all_segments, scope)
    }

    fn catalog_segments_from_snapshot(
        &self,
        snapshot: &CatalogSnapshot,
        scope: SegmentScope,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        Self::segments_for_scope(self.decode_catalog_segments(snapshot)?, scope)
    }

    fn decode_catalog_segments(
        &self,
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        let mut all_segments = Vec::new();
        all_segments
            .try_reserve_exact(snapshot.plaintext_object_count())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        for plaintext in snapshot.plaintext_objects() {
            if let Some(metadata) = decode_metadata(plaintext)? {
                all_segments.push(metadata);
            }
        }
        Ok(all_segments)
    }

    fn segments_for_scope(
        all_segments: Vec<SegmentMetadata>,
        scope: SegmentScope,
    ) -> Result<Vec<SegmentMetadata>, LedgerFailure> {
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(all_segments.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        for metadata in all_segments {
            if metadata.scope == scope {
                segments.push(metadata);
            }
        }
        if segments
            .iter()
            .filter(|metadata| metadata.state == SegmentState::Active)
            .count()
            > 1
        {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
        segments.sort_by_key(|metadata| {
            (
                metadata.base_position,
                (metadata.state != SegmentState::Retired) as u8,
            )
        });
        Ok(segments)
    }

    fn reject_unpublished_entries(
        &self,
        metadata: &[SegmentMetadata],
        snapshot: &CatalogSnapshot,
        repair: bool,
    ) -> Result<(), LedgerFailure> {
        let abandoned = crate::integrity_abandonment_findings(snapshot)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        for (directory, active_namespace) in [(&self.active, true), (&self.sealed, false)] {
            let mut entries = Dir::read_from(directory).map_err(map_errno)?;
            let mut count = 0_usize;
            let mut removed = false;
            while let Some(entry) = entries.read() {
                let entry = entry.map_err(map_errno)?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                count = count
                    .checked_add(1)
                    .filter(|count| *count <= MAX_SEGMENTS * 2)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
                let published = metadata.iter().any(|segment| {
                    name == segment_name(segment.id).as_bytes()
                        || name == frontier_name(segment.id).as_bytes()
                        || (active_namespace
                            && segment.state == SegmentState::Active
                            && name == frontier_temporary_name(segment.id).as_bytes())
                });
                let retained_evidence = !active_namespace
                    && abandoned.iter().any(|finding| {
                        name == segment_name(finding.segment()).as_bytes()
                            || name == frontier_name(finding.segment()).as_bytes()
                    });
                if !published && !retained_evidence {
                    if active_namespace && recognized_ledger_name(name) {
                        if repair {
                            unix_fs::unlinkat(directory, name, AtFlags::empty())
                                .map_err(map_errno)?;
                            removed = true;
                        }
                    } else {
                        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                    }
                }
            }
            if removed {
                synchronize(directory)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn recognized_ledger_name(name: &[u8]) -> bool {
    [b".segment".as_slice(), b".frontier", b".frontier.tmp"]
        .iter()
        .filter_map(|suffix| name.strip_suffix(*suffix))
        .any(|prefix| prefix.len() == 32 && prefix.iter().all(u8::is_ascii_hexdigit))
}
