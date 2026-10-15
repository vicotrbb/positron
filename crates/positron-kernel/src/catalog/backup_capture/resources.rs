//! Allocation-free sizing precedes owned metadata and immutable-handle staging.
use super::*;
/// Capture phase peaks share retained metadata; the copy buffer is released
/// before Repository control work begins.
#[derive(Clone, Copy, Debug)]
pub struct BackupCaptureResourceEstimate {
    resources: crate::ResourceAmounts,
    retained_memory_bytes: u64,
}
impl BackupCaptureResourceEstimate {
    pub fn resources(&self) -> crate::ResourceAmounts {
        self.resources
    }
    pub fn retained_memory_bytes(&self) -> u64 {
        self.retained_memory_bytes
    }
    pub fn copy_buffer_bytes(&self) -> u64 {
        COPY_BUFFER_BYTES
    }
}
const COPY_BUFFER_BYTES: u64 = 4 * 1024 * 1024;
impl Catalog<'_> {
    pub fn backup_capture_resource_estimate(
        &self,
        registry_bytes: usize,
    ) -> Result<BackupCaptureResourceEstimate, CatalogFailure> {
        if registry_bytes > 4 * 1024 * 1024 {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let basis = &state.current;
        let volume = self
            .authority
            .primary_data_volume()
            .ok_or_else(|| fail(CatalogFailureCode::ResourceAdmissionRefused))?;
        let (sources, source_bytes) =
            crate::active_segment_ledger::backup_source_estimate(volume, basis)?;
        let metadata_bytes = basis.plaintext_objects().try_fold(0u64, |total, object| {
            total
                .checked_add(object.len() as u64)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        let audit_bytes = state.audit.iter().try_fold(0u64, |total, record| {
            total
                .checked_add(record.intent().len() as u64 + 102)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        let checkpoint_bytes = state
            .audit_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.encode().len() as u64);
        // Acceptance, task dispatch and the four phase receipts may add bounded
        // Catalog/audit records before preparation. Concurrent source growth is
        // rechecked by preparation and cannot consume an undersized grant.
        let metadata_count = basis
            .object_count()
            .checked_add(state.audit.len())
            .and_then(|count| count.checked_add(17))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let plaintext = metadata_bytes
            .checked_add(audit_bytes)
            .and_then(|bytes| bytes.checked_add(checkpoint_bytes))
            .and_then(|bytes| bytes.checked_add(registry_bytes as u64 + 48 + 65_536))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let estimated_files = metadata_count
            .checked_add(
                basis
                    .object_count()
                    .checked_add(8)
                    .and_then(|count| count.checked_mul(2))
                    .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?,
            )
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let index = 439u64
            .checked_add(estimated_files as u64 * 105)
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        if metadata_count
            .checked_add(sources)
            .is_none_or(|count| count > MAX_CAPTURE_FILES)
            || index > MAX_CAPTURE_INDEX_BYTES as u64
        {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let retained_memory_bytes = plaintext
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(index * 6))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let memory = retained_memory_bytes
            .checked_add(COPY_BUFFER_BYTES)
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let disk = plaintext
            .checked_add((metadata_count as u64 + 1) * 315)
            .and_then(|bytes| bytes.checked_add(index))
            .and_then(|bytes| bytes.checked_add(source_bytes))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        Ok(BackupCaptureResourceEstimate {
            retained_memory_bytes,
            resources: crate::ResourceAmounts::new([
                memory,
                1,
                1,
                0,
                1,
                0,
                1,
                1,
                1,
                sources as u64 + 8,
                disk,
            ]),
        })
    }
}
