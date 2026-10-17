use super::tenant_purge::{corrupt, object_identity, unavailable};
use super::*;
use crate::catalog::tenant_purge::KeyLocation;

/// Open directory handles retain iteration position only for this worker's life.
/// An unpublished scan is intentionally restarted after cold recovery.
pub(in crate::catalog) struct KeyInventory {
    objects: File,
    staging: File,
    entries: Dir,
    nested: Option<(File, Dir, [u8; 16])>,
    stage: u8,
    count: usize,
    bytes: usize,
    selected: std::collections::BTreeSet<KeyLocation>,
    visited: u64,
}
impl CatalogStorage {
    pub(in crate::catalog) fn begin_key_inventory(&self) -> Result<KeyInventory, CatalogFailure> {
        Ok(KeyInventory {
            objects: self.objects.try_clone().map_err(|_| unavailable())?,
            staging: self.staging.try_clone().map_err(|_| unavailable())?,
            entries: Dir::read_from(&self.objects).map_err(|_| unavailable())?,
            nested: None,
            stage: 0,
            count: 0,
            bytes: 0,
            selected: std::collections::BTreeSet::new(),
            visited: 0,
        })
    }
    pub(in crate::catalog) fn reclaim_key_location(
        &self,
        location: &KeyLocation,
    ) -> Result<(), CatalogFailure> {
        let nested;
        let directory = match location.kind {
            0 => &self.objects,
            1 => &self.staging,
            2 => {
                let name = hex(&location.transaction);
                if !entry_exists(&self.staging, name.as_str())? {
                    return Ok(());
                }
                nested = open_existing_directory(&self.staging, &name)?;
                &nested
            },
            _ => return Err(corrupt()),
        };
        let base = object_name(FormatEpoch(location.epoch), location.id);
        let name = if location.kind == 1 {
            format!("rewrap-1-{base}")
        } else {
            base
        };
        if entry_exists(directory, name.as_str())? {
            emit_event(CatalogFileEvent::ReclaimKeyObject)?;
            unix_fs::unlinkat(directory, name.as_str(), rustix::fs::AtFlags::empty())
                .map_err(|_| unavailable())?;
        }
        // Also synchronize a repeated removal after an interrupted first fsync.
        emit_event(CatalogFileEvent::SynchronizeReclaimedKeyDirectory)?;
        synchronize(directory)
    }
}
impl KeyInventory {
    pub(in crate::catalog) fn step(
        &mut self,
        secret: &CatalogSecret,
        instance: InstanceId,
        selector: &impl Fn(&[u8]) -> Result<bool, CatalogFailure>,
    ) -> Result<Option<Vec<KeyLocation>>, CatalogFailure> {
        for _ in 0..64 {
            let entry = if let Some((_, entries, _)) = &mut self.nested {
                entries.read()
            } else {
                self.entries.read()
            };
            let Some(entry) = entry else {
                if self.nested.take().is_some() {
                    continue;
                }
                if self.stage == 0 {
                    self.stage = 1;
                    self.entries = Dir::read_from(&self.staging).map_err(|_| unavailable())?;
                    self.count = 0;
                    self.bytes = 0;
                    continue;
                }
                return Ok(Some(self.selected.iter().copied().collect()));
            };
            let entry = entry.map_err(|_| unavailable())?;
            self.visited = self.visited.checked_add(1).ok_or_else(corrupt)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            reserve_directory_entry(&mut self.count, &mut self.bytes, name.len())?;
            if self.nested.is_none() && self.stage == 1 && is_transaction_directory_name(name) {
                let file = open_existing_directory(
                    &self.staging,
                    std::str::from_utf8(name).map_err(|_| corrupt())?,
                )?;
                let mut tx = [0; 16];
                for (i, byte) in tx.iter_mut().enumerate() {
                    *byte = hex_value(name.get(i * 2).copied()).ok_or_else(corrupt)? * 16
                        + hex_value(name.get(i * 2 + 1).copied()).ok_or_else(corrupt)?;
                }
                let entries = Dir::read_from(&file).map_err(|_| unavailable())?;
                self.nested = Some((file, entries, tx));
                continue;
            }
            let Some((epoch, id)) = object_identity(name)? else {
                continue;
            };
            let (directory, kind, transaction) = if let Some((file, _, tx)) = &self.nested {
                (file, 2, *tx)
            } else if self.stage == 0 {
                (&self.objects, 0, [0; 16])
            } else {
                (&self.staging, 1, [0; 16])
            };
            // The descriptor reconstructs exactly this name; accepting an
            // alternative prefix in another directory could leave key bytes
            // behind while incorrectly issuing completion.
            let canonical = object_name(epoch, id);
            let canonical = if kind == 1 {
                format!("rewrap-1-{canonical}")
            } else {
                canonical
            };
            if name != canonical.as_bytes() {
                return Err(corrupt());
            }
            let encoded = read_exact_file(
                directory,
                entry.file_name(),
                MAX_CATALOG_OBJECT_BYTES + FRAME_OVERHEAD_BYTES,
            )?;
            let plaintext = open_artifact(
                secret,
                instance,
                ArtifactKind::Object,
                id.0,
                epoch,
                &encoded,
            )?;
            if DataProtection::hash(&plaintext).map_err(|_| unavailable())? != id.0 {
                return Err(corrupt());
            }
            if selector(&plaintext)? {
                if self.selected.len() >= crate::catalog::tenant_purge::MAX_KEYS
                    || u64::try_from(self.selected.len()).map_err(|_| corrupt())?
                        >= crate::catalog::MAX_RECOVERY_ITEMS
                {
                    return Err(CatalogFailure::new(CatalogFailureCode::LimitExceeded));
                }
                self.selected.insert(KeyLocation {
                    kind,
                    transaction,
                    epoch: epoch.0,
                    id,
                });
            }
            // One authenticated file per turn, independent of its size.
            return Ok(None);
        }
        Ok(None)
    }
    pub(in crate::catalog) fn visited(&self) -> u64 {
        self.visited
    }
}
