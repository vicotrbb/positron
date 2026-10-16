//! Incremental authentication of captured Catalog metadata, without publication.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Holds bounded authenticated metadata while an asynchronous caller streams
/// and checks every ciphertext file against `files()`. No live state is changed.
pub struct BackupCaptureVerification {
    instance: InstanceId,
    generation: u64,
    catalog: [u8; 32],
    epoch: FormatEpoch,
    audit: u64,
    files: Vec<BackupCaptureFile>,
    accepted: BTreeSet<[u8; 32]>,
    objects: BTreeMap<CatalogObjectId, Arc<[u8]>>,
    records: Vec<GovernanceAuditRecord>,
    checkpoint: Option<GovernanceAuditCheckpoint>,
    object_bytes: usize,
    audit_bytes: usize,
}

impl Catalog<'_> {
    /// Authenticates one bounded index using its signed manifest capture binding.
    pub fn begin_backup_capture_verification(
        &self,
        operation: [u8; 16],
        request: [u8; 32],
        index: &[u8],
    ) -> Result<BackupCaptureVerification, CatalogFailure> {
        if operation == [0; 16] || request == [0; 32] {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        if index.len() > MAX_CAPTURE_INDEX_BYTES {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        if index.get(..8) != Some(b"POSBCI01") {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let epoch = FormatEpoch::new(u32::from_be_bytes(
            index
                .get(8..12)
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?,
        ))?;
        if !epoch.is_catalog_readable() {
            return Err(fail(CatalogFailureCode::UnsupportedFormat));
        }
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let plaintext = storage::artifact::open_backup_capture(
            &secret,
            self.instance,
            codec::index_identity(operation, request),
            epoch,
            index
                .get(12..)
                .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?,
        )?;
        let (generation, catalog, audit, files) =
            BackupCapture::decode_inventory(&plaintext, operation, request, epoch)?;
        Ok(BackupCaptureVerification {
            instance: self.instance,
            generation,
            catalog,
            epoch,
            audit,
            files,
            accepted: BTreeSet::new(),
            objects: BTreeMap::new(),
            records: Vec::new(),
            checkpoint: None,
            object_bytes: 0,
            audit_bytes: 0,
        })
    }
}

fn array(bytes: usize, count: usize) -> Result<usize, CatalogFailure> {
    bytes
        .checked_mul(count)
        .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
}
// A B-tree node holds eleven entries and twelve child pointers. Charge
// one full node per entry, including allocation/control overhead, which
// bounds both the root and partially occupied internal nodes.
fn nodes(entry: usize, count: usize) -> Result<usize, CatalogFailure> {
    let bytes = array(entry, 12)?
        .checked_add(array(std::mem::size_of::<usize>(), 16)?)
        .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
    array(bytes, count)
}

impl BackupCaptureVerification {
    /// Admission ceiling derived from capture format limits before reading an
    /// index. Includes retained state, index decoding, one metadata decode, and
    /// finish-time sorting and native inventory checks.
    pub fn required_memory_bytes() -> Result<u64, CatalogFailure> {
        let arc = 2 * std::mem::size_of::<usize>();
        let records = MAX_CAPTURE_FILES.next_power_of_two();
        let charges = [
            std::mem::size_of::<Self>(),
            array(std::mem::size_of::<BackupCaptureFile>(), MAX_CAPTURE_FILES)?,
            nodes(std::mem::size_of::<[u8; 32]>(), MAX_CAPTURE_FILES)?,
            nodes(
                std::mem::size_of::<(CatalogObjectId, Arc<[u8]>)>(),
                MAX_CATALOG_OBJECTS,
            )?,
            MAX_CATALOG_TOTAL_BYTES,
            array(arc, MAX_CATALOG_OBJECTS)?,
            array(std::mem::size_of::<GovernanceAuditRecord>(), records)?,
            MAX_RECOVERED_AUDIT_BYTES,
            array(arc, MAX_CAPTURE_FILES)?,
            // Incoming ciphertext, opened index, and AEAD working copy.
            array(MAX_CAPTURE_INDEX_BYTES, 3)?,
            // One metadata ciphertext/plaintext and codec-owned temporary data.
            array(types::MAX_CATALOG_OBJECT_BYTES + 315, 6)?,
            // Stable audit sorting may allocate half the record vector.
            array(std::mem::size_of::<GovernanceAuditRecord>(), records / 2)?,
            // Native inventory tracks seen, required, and present segment IDs.
            array(
                nodes(std::mem::size_of::<[u8; 32]>(), MAX_CATALOG_OBJECTS)?,
                3,
            )?,
        ];
        let bytes = charges.into_iter().try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        u64::try_from(bytes).map_err(|_| fail(CatalogFailureCode::LimitExceeded))
    }

    /// Peak charge derived from this authenticated inventory before accepting
    /// metadata. Caller-owned index and remote streaming buffers are separate.
    pub fn prospective_memory_bytes(&self) -> Result<u64, CatalogFailure> {
        let mut object_count = 0usize;
        let mut object_bytes = 0usize;
        let mut audit_count = 0usize;
        let mut audit_bytes = 0usize;
        let mut checkpoint_count = 0usize;
        let mut largest_metadata = 0usize;
        for file in &self.files {
            let (count, total, fixed, limit) = match file.kind {
                BackupCaptureFileKind::CatalogObject => (
                    &mut object_count,
                    &mut object_bytes,
                    315usize,
                    types::MAX_CATALOG_OBJECT_BYTES + 315,
                ),
                BackupCaptureFileKind::GovernanceAudit => (
                    &mut audit_count,
                    &mut audit_bytes,
                    315 + super::super::codec::MAX_AUDIT_RECORD_BYTES
                        - types::MAX_AUDIT_INTENT_BYTES,
                    super::super::codec::MAX_AUDIT_RECORD_BYTES + 315,
                ),
                BackupCaptureFileKind::AuditCheckpoint => {
                    checkpoint_count = checkpoint_count
                        .checked_add(1)
                        .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
                    if checkpoint_count > 1 || file.size > 1024 {
                        return Err(fail(CatalogFailureCode::IntegrityCorruption));
                    }
                    largest_metadata = largest_metadata.max(
                        usize::try_from(file.size)
                            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?,
                    );
                    continue;
                },
                _ => continue,
            };
            let bytes =
                usize::try_from(file.size).map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
            if bytes > limit {
                return Err(fail(CatalogFailureCode::LimitExceeded));
            }
            let plaintext = bytes
                .checked_sub(fixed)
                .filter(|bytes| *bytes > 0)
                .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
            *total = total
                .checked_add(plaintext)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
            largest_metadata = largest_metadata.max(bytes);
        }
        if object_count == 0
            || object_count > MAX_CATALOG_OBJECTS
            || object_bytes > MAX_CATALOG_TOTAL_BYTES
            || audit_bytes > MAX_RECOVERED_AUDIT_BYTES
        {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let records = if audit_count == 0 {
            0
        } else {
            audit_count
                .checked_next_power_of_two()
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?
                .max(4)
        };
        let metadata_count = object_count
            .checked_add(audit_count)
            .and_then(|count| count.checked_add(checkpoint_count))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let charges = [
            std::mem::size_of::<Self>(),
            array(
                std::mem::size_of::<BackupCaptureFile>(),
                self.files.capacity(),
            )?,
            nodes(std::mem::size_of::<[u8; 32]>(), metadata_count)?,
            nodes(
                std::mem::size_of::<(CatalogObjectId, Arc<[u8]>)>(),
                object_count,
            )?,
            object_bytes,
            array(2 * std::mem::size_of::<usize>(), object_count)?,
            array(std::mem::size_of::<GovernanceAuditRecord>(), records)?,
            audit_bytes,
            array(2 * std::mem::size_of::<usize>(), audit_count)?,
            array(largest_metadata, 6)?,
            array(std::mem::size_of::<GovernanceAuditRecord>(), records / 2)?,
            array(nodes(std::mem::size_of::<[u8; 32]>(), object_count)?, 3)?,
        ];
        let bytes = charges.into_iter().try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        u64::try_from(bytes).map_err(|_| fail(CatalogFailureCode::LimitExceeded))
    }

    /// Conservative retained allocation charge, including collection node slack
    /// and Arc control blocks. Transient index/file buffers are charged by callers.
    pub fn retained_memory_bytes(&self) -> Result<u64, CatalogFailure> {
        let charges = [
            std::mem::size_of::<Self>(),
            array(
                std::mem::size_of::<BackupCaptureFile>(),
                self.files.capacity(),
            )?,
            nodes(std::mem::size_of::<[u8; 32]>(), self.accepted.len())?,
            nodes(
                std::mem::size_of::<(CatalogObjectId, Arc<[u8]>)>(),
                self.objects.len(),
            )?,
            self.object_bytes,
            array(2 * std::mem::size_of::<usize>(), self.objects.len())?,
            array(
                std::mem::size_of::<GovernanceAuditRecord>(),
                self.records.capacity(),
            )?,
            self.audit_bytes,
            array(2 * std::mem::size_of::<usize>(), self.records.len())?,
        ];
        let bytes = charges.into_iter().try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        u64::try_from(bytes).map_err(|_| fail(CatalogFailureCode::LimitExceeded))
    }

    pub fn files(&self) -> &[BackupCaptureFile] {
        &self.files
    }

    /// Accepts one complete bounded metadata ciphertext after remote streaming.
    /// Segment bytes are checked by the caller against the authenticated inventory.
    pub fn verify_file(
        &mut self,
        catalog: &Catalog<'_>,
        identity: [u8; 32],
        encoded: &[u8],
    ) -> Result<(), CatalogFailure> {
        let file = self
            .files
            .binary_search_by_key(&identity, |file| file.identity)
            .ok()
            .and_then(|position| self.files.get(position))
            .copied()
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
        let limit = match file.kind {
            BackupCaptureFileKind::CatalogObject => types::MAX_CATALOG_OBJECT_BYTES + 315,
            BackupCaptureFileKind::GovernanceAudit => {
                super::super::codec::MAX_AUDIT_RECORD_BYTES + 315
            },
            BackupCaptureFileKind::AuditCheckpoint => 1024,
            _ => return Err(fail(CatalogFailureCode::InvalidInput)),
        };
        if encoded.len() > limit {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        if catalog.instance != self.instance
            || self.accepted.contains(&identity)
            || encoded.len() as u64 != file.size
            || <[u8; 32]>::from(Sha256::digest(encoded)) != file.checksum
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let secret = catalog
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let plaintext = storage::artifact::open_backup_capture(
            &secret,
            self.instance,
            file.address,
            self.epoch,
            encoded,
        )?;
        match file.kind {
            BackupCaptureFileKind::CatalogObject => {
                CatalogObject::new(plaintext.clone())?;
                let total = self
                    .object_bytes
                    .checked_add(plaintext.len())
                    .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
                if total > MAX_CATALOG_TOTAL_BYTES || self.objects.len() >= MAX_CATALOG_OBJECTS {
                    return Err(fail(CatalogFailureCode::LimitExceeded));
                }
                self.objects
                    .insert(CatalogObjectId(file.address), Arc::from(plaintext));
                self.object_bytes = total;
            },
            BackupCaptureFileKind::GovernanceAudit => {
                let record = super::super::codec::decode_audit(&plaintext)?;
                let total = self
                    .audit_bytes
                    .checked_add(record.intent().len())
                    .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
                if record.record_hash() != file.address || total > MAX_RECOVERED_AUDIT_BYTES {
                    return Err(fail(CatalogFailureCode::IntegrityCorruption));
                }
                self.records.push(record);
                self.audit_bytes = total;
            },
            BackupCaptureFileKind::AuditCheckpoint => {
                let checkpoint = GovernanceAuditCheckpoint::decode(&plaintext)?;
                if self.checkpoint.is_some()
                    || checkpoint.instance() != self.instance
                    || checkpoint.record_hash() != file.address
                {
                    return Err(fail(CatalogFailureCode::IntegrityCorruption));
                }
                self.checkpoint = Some(checkpoint);
            },
            _ => return Err(fail(CatalogFailureCode::InvalidInput)),
        }
        self.accepted.insert(identity);
        Ok(())
    }

    /// Validates cross-object consistency and returns an unpublished read view.
    /// The caller must separately verify every ciphertext checksum before using it.
    pub fn finish(mut self) -> Result<CatalogSnapshot, CatalogFailure> {
        if self.objects.is_empty()
            || self.files.iter().any(|file| {
                matches!(
                    file.kind,
                    BackupCaptureFileKind::CatalogObject
                        | BackupCaptureFileKind::GovernanceAudit
                        | BackupCaptureFileKind::AuditCheckpoint
                ) && !self.accepted.contains(&file.identity)
            })
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        self.records.sort_by_key(GovernanceAuditRecord::position);
        let mut snapshot = CatalogSnapshot(Arc::new(types::SnapshotData {
            identity: CatalogGenerationId(self.catalog),
            number: self.generation,
            format_epoch: Some(self.epoch),
            objects: self.objects,
            audit_frontier: types::AuditFrontier {
                position: self.audit,
                hash: self
                    .records
                    .last()
                    .map_or([0; 32], GovernanceAuditRecord::record_hash),
            },
        }));
        let anchor = super::super::audit_checkpoint::retention_anchor(&snapshot)?;
        let last_position = self.records.last().map_or_else(
            || anchor.as_ref().map_or(0, AuditRetentionAnchor::position),
            GovernanceAuditRecord::position,
        );
        if last_position != self.audit {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        if self
            .records
            .first()
            .is_some_and(|record| record.position() == 1)
            || anchor.is_none()
        {
            let trust = if self.checkpoint.is_some() {
                snapshot.governance_object()?.1.integrity_public_key()
            } else {
                [0; 32]
            };
            super::super::audit_checkpoint::verify_chain(
                &self.records,
                trust,
                self.checkpoint.as_ref(),
            )?;
            if let Some(anchor) = &anchor {
                anchor.verify(super::super::audit_checkpoint::retention_trust(
                    &snapshot,
                    self.instance,
                )?)?;
                if !self.records.iter().any(|record| {
                    record.position() == anchor.position()
                        && record.record_hash() == anchor.record_hash()
                }) {
                    return Err(fail(CatalogFailureCode::IntegrityCorruption));
                }
            }
        } else {
            AuditRetentionAnchor::verify_retained_suffix(
                &self.records,
                anchor.as_ref(),
                super::super::audit_checkpoint::retention_trust(&snapshot, self.instance)?,
            )?;
            if self.checkpoint.is_some() {
                return Err(fail(CatalogFailureCode::IntegrityCorruption));
            }
        }
        if self.records.is_empty() {
            Arc::get_mut(&mut snapshot.0)
                .ok_or_else(|| fail(CatalogFailureCode::ConcurrentWriter))?
                .audit_frontier
                .hash = anchor
                .as_ref()
                .map_or([0; 32], AuditRetentionAnchor::record_hash);
        }
        crate::active_segment_ledger::verify_backup_capture_inventory(&snapshot, &self.files)?;
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(
        audit: u64,
        records: Vec<GovernanceAuditRecord>,
    ) -> Result<BackupCaptureVerification, CatalogFailure> {
        Ok(BackupCaptureVerification {
            instance: InstanceId::new([1; 16])?,
            generation: 1,
            catalog: [1; 32],
            epoch: FormatEpoch::CATALOG_V2,
            audit,
            files: Vec::new(),
            accepted: BTreeSet::new(),
            objects: BTreeMap::from([(
                CatalogObjectId([2; 32]),
                Arc::from(b"opaque metadata".as_slice()),
            )]),
            records,
            checkpoint: None,
            object_bytes: 15,
            audit_bytes: 0,
        })
    }

    #[test]
    fn captured_catalog_requires_complete_audit_frontier_and_chain() -> Result<(), CatalogFailure> {
        let (first, _) = super::super::super::codec::prepare_audit(
            types::AuditFrontier::ORIGIN,
            TransactionId::new([1; 16])?,
            b"first",
        )?;
        let (second, _) = super::super::super::codec::prepare_audit(
            types::AuditFrontier {
                position: first.position(),
                hash: first.record_hash(),
            },
            TransactionId::new([2; 16])?,
            b"second",
        )?;
        assert!(metadata(2, vec![first.clone()])?.finish().is_err());
        assert!(metadata(2, vec![second.clone()])?.finish().is_err());
        assert!(
            metadata(2, vec![first.clone(), first.clone(), second.clone()])?
                .finish()
                .is_err()
        );
        let snapshot = metadata(2, vec![second, first])?.finish()?;
        assert_eq!(snapshot.governance_audit_frontier(), 2);
        Ok(())
    }
}
