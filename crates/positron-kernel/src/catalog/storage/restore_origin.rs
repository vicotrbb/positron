//! Atomic descriptor-only import boundary in the ordinary encrypted Catalog.
use super::super::restore_origin::{MAX_ORIGIN_BYTES, StoredOrigin};
use super::*;
const NAME: &str = "restore-origin.v1";
fn identity(instance: InstanceId) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"positron-catalog-restore-origin-v1\0");
    hash.update(instance.to_bytes());
    hash.finalize().into()
}
impl CatalogStorage {
    pub(in crate::catalog) fn publish_restore_origin(
        &self,
        secret: &CatalogSecret,
        origin: &StoredOrigin,
    ) -> Result<(), CatalogFailure> {
        let plaintext = origin.encode()?;
        if entry_exists(&self._catalog, NAME)? {
            let existing = self
                .read_restore_origin(secret, origin.instance)?
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
            if existing.encode()? != plaintext {
                return Err(CatalogFailure::new(CatalogFailureCode::IdempotencyConflict));
            }
            return synchronize(&self._catalog);
        }
        let encoded = protect_artifact(
            secret,
            origin.instance,
            ArtifactKind::RestoreOrigin,
            identity(origin.instance),
            FormatEpoch::CATALOG_V2,
            &plaintext,
        )?;
        write_transaction_file(
            &self.staging,
            NAME,
            &encoded,
            CatalogFileEvent::PartialObjectWrite,
        )?;
        synchronize_named_file(&self.staging, NAME)?;
        synchronize(&self.staging)?;
        unix_fs::renameat_with(
            &self.staging,
            NAME,
            &self._catalog,
            NAME,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
        synchronize(&self._catalog)
    }
    pub(in crate::catalog) fn read_restore_origin(
        &self,
        secret: &CatalogSecret,
        instance: InstanceId,
    ) -> Result<Option<StoredOrigin>, CatalogFailure> {
        if !entry_exists(&self._catalog, NAME)? {
            return Ok(None);
        }
        let encoded = read_exact_file(
            &self._catalog,
            NAME,
            MAX_ORIGIN_BYTES + FRAME_OVERHEAD_BYTES,
        )?;
        let plaintext = open_artifact(
            secret,
            instance,
            ArtifactKind::RestoreOrigin,
            identity(instance),
            FormatEpoch::CATALOG_V2,
            &encoded,
        )?;
        StoredOrigin::decode(self, secret, instance, &plaintext).map(Some)
    }
    pub(in crate::catalog) fn rewrap_restore_origin(
        &self,
        current: &CatalogWrappingKey,
        replacement: &CatalogWrappingKey,
        instance: InstanceId,
    ) -> Result<(), CatalogFailure> {
        if entry_exists(&self._catalog, NAME)? {
            self.rewrap_named(
                &self._catalog,
                NAME,
                MAX_ORIGIN_BYTES + FRAME_OVERHEAD_BYTES,
                current,
                replacement,
                instance,
                ArtifactKind::RestoreOrigin,
                identity(instance),
                FormatEpoch::CATALOG_V2,
            )?;
        }
        Ok(())
    }
}
