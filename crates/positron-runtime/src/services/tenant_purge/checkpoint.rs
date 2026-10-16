//! Non-secret cursors use the existing exact maintenance dispatch checkpoint.
use super::*;
use positron_kernel::MaintenanceExecution;

#[derive(Default)]
pub(super) struct Progress {
    pub inventory: [u8; 32],
    pub after: [u8; 16],
    pub repository: [u8; 16],
    pub verification: Vec<u8>,
    pub purge: Vec<u8>,
    pub reclamation: Vec<u8>,
    pub descriptor: bool,
}
impl Progress {
    fn encode(&self) -> Result<Vec<u8>, ServiceFailure> {
        let mut bytes = b"POSTPC01".to_vec();
        bytes.extend_from_slice(&self.inventory);
        bytes.extend_from_slice(&self.after);
        bytes.extend_from_slice(&self.repository);
        bytes.push(u8::from(self.descriptor));
        for field in [&self.verification, &self.purge, &self.reclamation] {
            if field.len() > 1024 {
                return Err(ServiceFailure::CorruptState);
            }
            bytes.extend_from_slice(&(field.len() as u16).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, ServiceFailure> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        if bytes.get(..8) != Some(b"POSTPC01") {
            return Err(ServiceFailure::CorruptState);
        }
        let mut at = 8;
        fn take<'a>(
            bytes: &'a [u8],
            at: &mut usize,
            length: usize,
        ) -> Result<&'a [u8], ServiceFailure> {
            let end = at.checked_add(length).ok_or(ServiceFailure::CorruptState)?;
            let value = bytes.get(*at..end).ok_or(ServiceFailure::CorruptState)?;
            *at = end;
            Ok(value)
        }
        let inventory = take(bytes, &mut at, 32)?
            .try_into()
            .map_err(|_| ServiceFailure::CorruptState)?;
        let after = take(bytes, &mut at, 16)?
            .try_into()
            .map_err(|_| ServiceFailure::CorruptState)?;
        let repository = take(bytes, &mut at, 16)?
            .try_into()
            .map_err(|_| ServiceFailure::CorruptState)?;
        let descriptor = match take(bytes, &mut at, 1)? {
            [0] => false,
            [1] => true,
            _ => return Err(ServiceFailure::CorruptState),
        };
        let mut field = || -> Result<Vec<u8>, ServiceFailure> {
            let length = usize::from(u16::from_be_bytes(
                take(bytes, &mut at, 2)?
                    .try_into()
                    .map_err(|_| ServiceFailure::CorruptState)?,
            ));
            if length > 1024 {
                return Err(ServiceFailure::CorruptState);
            }
            Ok(take(bytes, &mut at, length)?.to_vec())
        };
        let verification = field()?;
        let purge = field()?;
        let reclamation = field()?;
        if at != bytes.len() {
            return Err(ServiceFailure::CorruptState);
        }
        Ok(Self {
            inventory,
            after,
            repository,
            verification,
            purge,
            reclamation,
            descriptor,
        })
    }
}
pub(super) fn current(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    binding: RepositoryOperationBinding,
) -> Result<Progress, ServiceFailure> {
    let (_, bytes) = binding
        .current_backup_progress(services.instance.maintenance_coordinator(), execution)
        .map_err(super::super::maintenance::map_failure)?;
    Progress::decode(&bytes)
}
/// Caller holds the Catalog mutation gate, including when publishing progress.
pub(super) fn persist(
    services: &ServiceHandle,
    catalog: &positron_kernel::Catalog<'_>,
    execution: &MaintenanceExecution<'_>,
    binding: RepositoryOperationBinding,
    progress: &Progress,
) -> Result<(), ServiceFailure> {
    let (sequence, prior) = binding
        .current_backup_progress(services.instance.maintenance_coordinator(), execution)
        .map_err(super::super::maintenance::map_failure)?;
    let bytes = progress.encode()?;
    if bytes == prior {
        return Ok(());
    }
    execution
        .checkpoint_and_persist_at(
            services.instance.maintenance_coordinator(),
            catalog,
            binding
                .backup_checkpoint(
                    sequence
                        .checked_add(1)
                        .ok_or(ServiceFailure::CorruptState)?,
                    &bytes,
                )
                .map_err(super::super::maintenance::map_failure)?,
            services
                .maintenance_status_now()
                .map_err(|_| ServiceFailure::StorageUnavailable)?,
        )
        .map_err(super::super::maintenance::map_failure)?;
    Ok(())
}
