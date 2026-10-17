use super::super::tenant_purge;
use super::*;

impl CatalogStorage {
    /// Resolve exclusions from the newest marker-authenticated Catalog. Reads
    /// here are raw, so a missing current object never authorizes itself.
    pub(in crate::catalog) fn reclaimed_key_ids(
        &self,
        secret: &CatalogSecret,
        instance: InstanceId,
    ) -> Result<Vec<CatalogObjectId>, CatalogFailure> {
        let markers = self.markers(secret)?;
        if markers.authentication_failures != 0 {
            return Err(corrupt());
        }
        let Some((generation, _)) = markers.verified.iter().max_by_key(|(_, n)| **n) else {
            return Ok(Vec::new());
        };
        let record = super::super::codec::decode_commit(
            *generation,
            &self.read_commit(secret, instance, *generation)?,
        )?;
        let mut objects = BTreeMap::new();
        for id in &record.objects {
            objects.insert(
                *id,
                self.read_object_raw(secret, instance, *id, record.format_epoch)?,
            );
        }
        tenant_purge::reclaimed_ids(&super::super::codec::snapshot_from_record(&record, objects))
    }
}
pub(super) fn object_identity(
    name: &[u8],
) -> Result<Option<(FormatEpoch, CatalogObjectId)>, CatalogFailure> {
    let name = name.strip_prefix(b"rewrap-1-").unwrap_or(name);
    if name.len() != 81 || name.get(10) != Some(&b'-') || name.get(75..) != Some(b".frame") {
        return Ok(None);
    }
    let epoch = std::str::from_utf8(name.get(..10).ok_or_else(corrupt)?)
        .map_err(|_| corrupt())?
        .parse::<u32>()
        .map_err(|_| corrupt())?;
    let mut id = [0; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        let high = hex_value(name.get(11 + 2 * i).copied()).ok_or_else(corrupt)?;
        let low = hex_value(name.get(12 + 2 * i).copied()).ok_or_else(corrupt)?;
        *byte = high * 16 + low;
    }
    Ok(Some((FormatEpoch(epoch), CatalogObjectId(id))))
}
pub(super) fn corrupt() -> CatalogFailure {
    CatalogFailure::new(CatalogFailureCode::IntegrityCorruption)
}
pub(super) fn unavailable() -> CatalogFailure {
    CatalogFailure::new(CatalogFailureCode::StorageUnavailable)
}
