//! Bounded, idempotent native ciphertext staging under the offline restore origin.
use super::*;
use std::io::Write;
use std::os::unix::fs::MetadataExt;

impl Catalog<'_> {
    /// Creates the native empty ledger directories even when every captured
    /// tenant was excluded. It never creates an active segment or a tenant key.
    pub fn prepare_restore_segments(&self) -> Result<(), CatalogFailure> {
        if self.restore_origin_intent()?.is_none() {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            crate::ResourceAmounts::new([1024, 1, 1, 0, 0, 0, 0, 1, 1, 3, 0]),
        )
        .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        let _grant = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let volume = self
            .authority
            .primary_data_volume()
            .ok_or_else(|| fail(CatalogFailureCode::ResourceAdmissionRefused))?;
        let segments = io::directory(&volume._root, "segments", true)?;
        drop(io::directory(&segments, "active", true)?);
        drop(io::directory(&segments, "sealed", true)?);
        Ok(())
    }
    /// Returns true once the whole signed file is checksummed and durably named.
    /// Runtime keeps the target offline until native AEAD/frontier verification.
    pub fn restore_segment_range(
        &self,
        file: BackupCaptureFile,
        offset: u64,
        bytes: &[u8],
    ) -> Result<bool, CatalogFailure> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        if bytes.is_empty()
            || bytes.len() > 4 * 1024 * 1024
            || end > file.size()
            || file.size() > 64 * 1024 * 1024
            || file.checksum() == [0; 32]
        {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        if self.restore_origin_intent()?.is_none()
            || !crate::active_segment_ledger::restore_file_is_reachable(&self.pin()?, file)?
        {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let claim = RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            crate::ResourceAmounts::new([131_072, 1, 1, 0, 3, 0, 0, 1, 1, 3, file.size()]),
        )
        .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        let _grant = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(CatalogFailure::admission)?;
        let volume = self
            .authority
            .primary_data_volume()
            .ok_or_else(|| fail(CatalogFailureCode::ResourceAdmissionRefused))?;
        let segments = io::directory(&volume._root, "segments", true)?;
        let sealed = io::directory(&segments, "sealed", true)?;
        drop(io::directory(&segments, "active", true)?);
        let name = file.storage_name();
        if io::exists(&sealed, &name)? {
            let mut existing = io::open(&sealed, &name)?;
            verify_file(&mut existing, file)?;
            compare_range(&mut existing, offset, bytes)?;
            return Ok(true);
        }
        let stage = format!(".restore-{name}");
        let mut output = unix_fs::openat(
            &sealed,
            &stage,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|_| fail(CatalogFailureCode::StorageUnavailable))?;
        let metadata = output.metadata().map_err(io::error)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > file.size()
            || metadata.len() < offset
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let overlap = metadata
            .len()
            .saturating_sub(offset)
            .min(bytes.len() as u64) as usize;
        compare_range(
            &mut output,
            offset,
            bytes
                .get(..overlap)
                .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?,
        )?;
        output
            .seek(SeekFrom::Start(offset + overlap as u64))
            .map_err(io::error)?;
        output
            .write_all(
                bytes
                    .get(overlap..)
                    .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?,
            )
            .map_err(io::error)?;
        output.sync_all().map_err(io::error)?;
        sealed.sync_all().map_err(io::error)?;
        if output.metadata().map_err(io::error)?.len() != file.size() {
            return Ok(false);
        }
        verify_file(&mut output, file)?;
        unix_fs::renameat_with(
            &sealed,
            &stage,
            &sealed,
            &name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| fail(CatalogFailureCode::StorageUnavailable))?;
        sealed.sync_all().map_err(io::error)?;
        Ok(true)
    }
}
fn compare_range(file: &mut File, offset: u64, expected: &[u8]) -> Result<(), CatalogFailure> {
    file.seek(SeekFrom::Start(offset)).map_err(io::error)?;
    let mut buffer = [0; 65_536];
    for chunk in expected.chunks(buffer.len()) {
        let actual = buffer
            .get_mut(..chunk.len())
            .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?;
        file.read_exact(actual).map_err(io::error)?;
        if actual != chunk {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
    }
    Ok(())
}
fn verify_file(file: &mut File, expected: BackupCaptureFile) -> Result<(), CatalogFailure> {
    if file.metadata().map_err(io::error)?.len() != expected.size() {
        return Err(fail(CatalogFailureCode::IntegrityCorruption));
    }
    file.seek(SeekFrom::Start(0)).map_err(io::error)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65_536];
    loop {
        let length = file.read(&mut buffer).map_err(io::error)?;
        if length == 0 {
            break;
        }
        hash.update(
            buffer
                .get(..length)
                .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?,
        );
    }
    if <[u8; 32]>::from(hash.finalize()) != expected.checksum() {
        return Err(fail(CatalogFailureCode::IntegrityCorruption));
    }
    Ok(())
}
