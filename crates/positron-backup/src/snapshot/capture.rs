use super::*;
use positron_kernel::{BackupCapture, BackupCaptureFile, BackupCaptureFileKind};
use sha2::{Digest, Sha256};

/// Bounded validation of the bytes named by the authenticated Kernel index.
/// A manifest is available only after every captured file matches that index.
pub struct BackupManifestBuilder {
    manifest: BackupManifest,
    files: Vec<(usize, BackupCaptureFile)>,
    next: usize,
    offset: u64,
    hash: Sha256,
    failed: bool,
}
impl BackupManifestBuilder {
    pub fn new(
        capture: &BackupCapture,
        snapshot: [u8; 16],
        repository: RepositoryIdentity,
        retention: BackupRetention,
        key_context: [u8; 32],
    ) -> Result<Self, RepositoryFailure> {
        if capture.files().is_empty() || capture.files().len() > MAX_BACKUP_OBJECTS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let index = capture
            .files()
            .iter()
            .find(|file| file.kind() == BackupCaptureFileKind::Index)
            .ok_or(RepositoryFailure::CorruptState)?;
        let catalog = BackupCatalogIdentity::new(
            capture.catalog_generation(),
            capture.catalog_identity(),
            capture.format_epoch().value(),
            capture.audit_frontier(),
            index.identity(),
        )?;
        let mut files = Vec::new();
        files
            .try_reserve_exact(capture.files().len())
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        files.extend(capture.files().iter().copied().enumerate());
        files.sort_unstable_by_key(|(_, file)| file.identity());
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(files.len())
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for (_, file) in &files {
            objects.push(BackupObject::new(
                file.identity(),
                file.size(),
                0,
                file.checksum(),
                file.size(),
            )?);
        }
        Ok(Self {
            manifest: BackupManifest::new(
                snapshot,
                repository,
                catalog,
                retention,
                key_context,
                objects,
            )?,
            files,
            next: 0,
            offset: 0,
            hash: Sha256::new(),
            failed: false,
        })
    }
    /// Admits private candidate metadata before reading captured bytes. The
    /// Publisher's external amount excludes this builder; nothing is signed or
    /// exposed until `step` has verified every authenticated index checksum.
    pub fn preflight(
        &self,
        publisher: &BackupPublisher<'_>,
        keys: &[BackupKeyEnvelope],
    ) -> Result<(), RepositoryFailure> {
        let files = u64::try_from(self.files.capacity())
            .ok()
            .and_then(|count| {
                count.checked_mul(std::mem::size_of::<(usize, BackupCaptureFile)>() as u64)
            })
            .ok_or(RepositoryFailure::LimitExceeded)?;
        publisher.capture_memory(&self.manifest, keys, files)
    }
    /// Heap retained while ancestry verification runs before byte validation.
    pub fn retained_memory_bytes(&self) -> Result<u64, RepositoryFailure> {
        u64::try_from(self.files.capacity())
            .ok()
            .and_then(|count| {
                count.checked_mul(std::mem::size_of::<(usize, BackupCaptureFile)>() as u64)
            })
            .and_then(|files| {
                self.manifest
                    .retained_memory_bytes()
                    .ok()
                    .and_then(|manifest| files.checked_add(manifest))
            })
            .ok_or(RepositoryFailure::LimitExceeded)
    }
    /// Reads at most `budget` bytes and completes at most 32 files per call.
    pub fn step(
        &mut self,
        capture: &BackupCapture,
        budget: u64,
    ) -> Result<Option<BackupManifest>, RepositoryFailure> {
        if self.failed || budget == 0 || budget > crate::MAX_RANGE_BYTES {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.failed = true;
        if capture.catalog_generation() != self.manifest.catalog_generation
            || capture.catalog_identity() != self.manifest.catalog_identity
            || capture.format_epoch().value() != self.manifest.format_epoch
            || capture.audit_frontier() != self.manifest.audit_frontier
            || capture.files().len() != self.files.len()
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let mut remaining = budget;
        let mut completed = 0;
        while remaining > 0 && completed < 32 {
            let Some((position, file)) = self.files.get(self.next) else {
                break;
            };
            if capture.files().get(*position) != Some(file) {
                return Err(RepositoryFailure::CorruptState);
            }
            let length = (file.size() - self.offset).min(remaining);
            let bytes = capture
                .read(file.identity(), self.offset, length)
                .map_err(|_| RepositoryFailure::CorruptState)?;
            if bytes.len() as u64 != length {
                return Err(RepositoryFailure::CorruptState);
            }
            self.hash.update(bytes);
            self.offset += length;
            remaining -= length;
            if self.offset == file.size() {
                if <[u8; 32]>::from(std::mem::take(&mut self.hash).finalize()) != file.checksum() {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                self.next += 1;
                self.offset = 0;
                completed += 1;
            }
        }
        self.failed = false;
        Ok((self.next == self.files.len()).then(|| self.manifest.clone()))
    }
}
impl BackupSource for BackupCapture {
    fn read(&self, file: [u8; 32], offset: u64, length: u64) -> Result<Vec<u8>, RepositoryFailure> {
        BackupCapture::read(self, file, offset, length)
            .map_err(|_| RepositoryFailure::SourceIntegrityCorruption)
    }
}
