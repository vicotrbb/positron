//! Only bounded, non-secret Backup progress enters Maintenance persistence.
use super::*;
const MAGIC: &[u8; 8] = b"POSBRP02";
pub(super) fn encode(
    transfer: BackupTransfer,
    next_key: u32,
    verification: &[u8],
) -> Result<Vec<u8>, ServiceFailure> {
    if verification.len() > 512 {
        return Err(ServiceFailure::CorruptState);
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&transfer.encode());
    bytes.extend_from_slice(&next_key.to_be_bytes());
    bytes.extend_from_slice(&(verification.len() as u16).to_be_bytes());
    bytes.extend_from_slice(verification);
    Ok(bytes)
}
pub(super) fn decode(bytes: &[u8]) -> Result<(&[u8], u32, &[u8]), ServiceFailure> {
    if bytes.is_empty() {
        return Ok((&[], 0, &[]));
    }
    if bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(ServiceFailure::CorruptState);
    }
    let transfer = bytes.get(8..72).ok_or(ServiceFailure::CorruptState)?;
    let next_key = u32::from_be_bytes(
        bytes
            .get(72..76)
            .ok_or(ServiceFailure::CorruptState)?
            .try_into()
            .map_err(|_| ServiceFailure::CorruptState)?,
    );
    let length = usize::from(u16::from_be_bytes(
        bytes
            .get(76..78)
            .ok_or(ServiceFailure::CorruptState)?
            .try_into()
            .map_err(|_| ServiceFailure::CorruptState)?,
    ));
    if length > 512 || bytes.len() != 78 + length {
        return Err(ServiceFailure::CorruptState);
    }
    Ok((
        transfer,
        next_key,
        bytes.get(78..).ok_or(ServiceFailure::CorruptState)?,
    ))
}

const OWNER_MAGIC: &[u8; 8] = b"POSBOW01";
pub(in crate::services::backup_administration) const MAX_OWNER_FIELD: usize = 1024;
pub(in crate::services::backup_administration) fn unpack(
    bytes: &[u8],
) -> Result<(&[u8], &[u8]), ServiceFailure> {
    if bytes.is_empty() {
        return Ok((&[], &[]));
    }
    if bytes.get(..8) != Some(OWNER_MAGIC.as_slice()) {
        return Err(ServiceFailure::CorruptState);
    }
    let registry = usize::from(u16::from_be_bytes(
        bytes
            .get(8..10)
            .ok_or(ServiceFailure::CorruptState)?
            .try_into()
            .map_err(|_| ServiceFailure::CorruptState)?,
    ));
    let progress = usize::from(u16::from_be_bytes(
        bytes
            .get(10..12)
            .ok_or(ServiceFailure::CorruptState)?
            .try_into()
            .map_err(|_| ServiceFailure::CorruptState)?,
    ));
    if registry > MAX_OWNER_FIELD
        || progress > MAX_OWNER_FIELD
        || bytes.len() != 12 + registry + progress
    {
        return Err(ServiceFailure::CorruptState);
    }
    Ok((
        bytes
            .get(12..12 + registry)
            .ok_or(ServiceFailure::CorruptState)?,
        bytes
            .get(12 + registry..)
            .ok_or(ServiceFailure::CorruptState)?,
    ))
}
pub(super) fn pack(registry: &[u8], progress: &[u8]) -> Result<Vec<u8>, ServiceFailure> {
    if registry.len() > MAX_OWNER_FIELD || progress.len() > MAX_OWNER_FIELD {
        return Err(ServiceFailure::CorruptState);
    }
    let mut bytes = Vec::with_capacity(12 + registry.len() + progress.len());
    bytes.extend_from_slice(OWNER_MAGIC);
    bytes.extend_from_slice(&(registry.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&(progress.len() as u16).to_be_bytes());
    bytes.extend_from_slice(registry);
    bytes.extend_from_slice(progress);
    Ok(bytes)
}
pub(in crate::services::backup_administration) fn current(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    binding: RepositoryOperationBinding,
) -> Result<(u64, Vec<u8>), ServiceFailure> {
    binding
        .current_backup_progress(services.instance.maintenance_coordinator(), execution)
        .map_err(super::super::super::maintenance::map_failure)
}
/// Replaces only the supplied owner field, retaining the other field from the
/// current exact dispatch. A failed publication preserves both prior fields.
pub(in crate::services::backup_administration) fn persist(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    binding: RepositoryOperationBinding,
    registry: Option<&[u8]>,
    progress: Option<&[u8]>,
) -> Result<(), ServiceFailure> {
    let _gate = services.catalog_operation()?;
    let (sequence, current) = current(services, execution, binding)?;
    let (old_registry, old_progress) = unpack(&current)?;
    let registry = registry.unwrap_or(old_registry);
    let progress = progress.unwrap_or(old_progress);
    if registry == old_registry && progress == old_progress {
        return Ok(());
    }
    let payload = pack(registry, progress)?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let now = services
        .maintenance_status_now()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    execution
        .checkpoint_and_persist_at(
            services.instance.maintenance_coordinator(),
            &catalog,
            binding
                .backup_checkpoint(
                    sequence
                        .checked_add(1)
                        .ok_or(ServiceFailure::CorruptState)?,
                    &payload,
                )
                .map_err(super::super::super::maintenance::map_failure)?,
            now,
        )
        .map_err(super::super::super::maintenance::map_failure)?;
    #[cfg(test)]
    if registry != old_registry && !progress.is_empty() {
        test_stops::hit(test_stops::StopPoint::RegistryCursorPersisted, None)?;
    }
    Ok(())
}
