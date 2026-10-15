//! Immutable source handles and captured-byte AEAD/frontier verification.
use super::{
    format::{SegmentMetadata, SegmentState, decode_metadata},
    io::{open_existing_directory, open_regular},
    recovery::{RecoveryMode, frontier_name, segment_name},
    storage::LedgerStorage,
};
use crate::{
    BackupCaptureFile, BackupCaptureFileKind, CatalogFailure, CatalogFailureCode, CatalogSnapshot,
    InstanceId, OwnedPrimaryDataVolume, SegmentProtectionKey, SegmentScope,
};
use rustix::fs::{self as unix_fs, AtFlags};
use std::fs::File;
fn corrupt() -> CatalogFailure {
    CatalogFailure::new(CatalogFailureCode::IntegrityCorruption)
}
fn storage() -> CatalogFailure {
    CatalogFailure::new(CatalogFailureCode::StorageUnavailable)
}
/// Discovery retains at most one source handle, before a capture grant exists.
/// The admitted Catalog reader owns the fixed directory inspection peak.
pub(crate) fn backup_source_estimate(
    volume: &OwnedPrimaryDataVolume,
    basis: &CatalogSnapshot,
) -> Result<(usize, u64), CatalogFailure> {
    let mut count = 0usize;
    let mut bytes = 0u64;
    for object in basis.plaintext_objects() {
        let Some(segment) = decode_metadata(object).map_err(|_| corrupt())? else {
            continue;
        };
        if segment.state == SegmentState::Retired {
            continue;
        }
        let directory =
            open_existing_directory(&volume._root, "segments").map_err(|_| storage())?;
        let source = open_existing_directory(
            &directory,
            if segment.state == SegmentState::Active {
                "active"
            } else {
                "sealed"
            },
        )
        .map_err(|_| storage())?;
        for name in [segment_name(segment.id), frontier_name(segment.id)] {
            match unix_fs::statat(&source, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) if name.ends_with(".frontier") => continue,
                Err(_) => return Err(storage()),
                Ok(_) => {},
            }
            let file = open_regular(&source, &name, false).map_err(|_| storage())?;
            let length = file.metadata().map_err(|_| storage())?.len();
            if length > 64 * 1024 * 1024 {
                return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
            }
            count = count.checked_add(1).ok_or_else(corrupt)?;
            bytes = bytes.checked_add(length).ok_or_else(corrupt)?;
        }
    }
    Ok((count, bytes))
}
pub(crate) struct BackupSegmentVerification {
    basis: CatalogSnapshot,
    instance: InstanceId,
    metadata: Vec<SegmentMetadata>,
    keys: Vec<(SegmentScope, SegmentProtectionKey)>,
}
impl BackupSegmentVerification {
    pub(crate) const fn instance(&self) -> InstanceId {
        self.instance
    }
    /// Reuses the Kernel's AEAD/header/acknowledged-frontier recovery on the
    /// private captured files, never on a later live filename or generation.
    pub(crate) fn verify_next(&mut self, directory: &File) -> Result<bool, CatalogFailure> {
        let Some(metadata) = self.metadata.last().copied() else {
            return Ok(true);
        };
        let key = self
            .keys
            .iter()
            .find(|(scope, _)| *scope == metadata.scope)
            .map(|(_, key)| key)
            .ok_or_else(corrupt)?;
        let storage = LedgerStorage::captured_for_backup(directory).map_err(|_| storage())?;
        storage
            .verification_source_bound(metadata, key, self.instance, Some(&self.basis))
            .map_err(|_| corrupt())?
            .ok_or_else(corrupt)?;
        let (_, recovered) = storage
            .recover_segment_with_mode(
                metadata,
                key,
                self.instance,
                RecoveryMode::Observe,
                Some(&self.basis),
            )
            .map_err(|_| corrupt())?;
        if metadata.sealed_frontier != Some(recovered.frontier) {
            return Err(corrupt());
        }
        self.metadata.pop();
        Ok(self.metadata.is_empty())
    }
}
pub(crate) fn backup_segment_sources(
    volume: &OwnedPrimaryDataVolume,
    basis: &CatalogSnapshot,
    instance: InstanceId,
    keys: Vec<(SegmentScope, SegmentProtectionKey)>,
    available_handles: u64,
) -> Result<(Vec<(BackupCaptureFile, File)>, BackupSegmentVerification), CatalogFailure> {
    if !crate::integrity_quarantine_findings(basis)
        .map_err(|_| corrupt())?
        .is_empty()
    {
        return Err(corrupt());
    }
    let mut metadata = Vec::new();
    for bytes in basis.plaintext_objects() {
        if let Some(segment) = decode_metadata(bytes).map_err(|_| corrupt())? {
            match segment.state {
                SegmentState::Active => {
                    return Err(CatalogFailure::new(CatalogFailureCode::StaleGeneration));
                },
                SegmentState::Sealed => metadata.push(segment),
                SegmentState::Retired => {},
            }
        }
    }
    metadata.sort_by_key(|segment| segment.id);
    if metadata.windows(2).any(|pair| {
        pair.first()
            .zip(pair.get(1))
            .is_some_and(|(left, right)| left.id == right.id)
    }) {
        return Err(corrupt());
    }
    if metadata.len() as u64 * 2 > available_handles
        || metadata
            .iter()
            .any(|metadata| !keys.iter().any(|(scope, _)| *scope == metadata.scope))
    {
        return Err(CatalogFailure::new(
            CatalogFailureCode::ResourceAdmissionRefused,
        ));
    }
    let verification = BackupSegmentVerification {
        basis: basis.clone(),
        instance,
        metadata: metadata.clone(),
        keys,
    };
    if metadata.is_empty() {
        return Ok((Vec::new(), verification));
    }
    let directory = open_existing_directory(&volume._root, "segments").map_err(|_| storage())?;
    let sealed = open_existing_directory(&directory, "sealed").map_err(|_| storage())?;
    let mut files = Vec::new();
    files
        .try_reserve_exact(metadata.len() * 2)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
    for segment in metadata {
        let mut address = [0; 32];
        address
            .get_mut(..16)
            .ok_or_else(corrupt)?
            .copy_from_slice(&segment.id.to_bytes());
        for (kind, name) in [
            (BackupCaptureFileKind::Segment, segment_name(segment.id)),
            (
                BackupCaptureFileKind::SegmentFrontier,
                frontier_name(segment.id),
            ),
        ] {
            match unix_fs::statat(&sealed, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => {},
                Err(rustix::io::Errno::NOENT) if kind == BackupCaptureFileKind::SegmentFrontier => {
                    continue;
                },
                Err(_) => return Err(storage()),
            }
            let file = open_regular(&sealed, &name, false).map_err(|_| storage())?;
            let length = file.metadata().map_err(|_| storage())?.len();
            if length > 64 * 1024 * 1024 {
                return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
            }
            files.push((BackupCaptureFile::new(kind, address, length)?, file));
        }
    }
    Ok((files, verification))
}
