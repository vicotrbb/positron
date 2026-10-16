//! Atomic authenticated ownership precedes every restore staging write.
use super::*;
use rustix::fs::Dir;
const PREFIX: &str = ".positron-restore-owner.";

pub(super) fn is_claim_name(name: &[u8]) -> bool {
    name.strip_prefix(PREFIX.as_bytes())
        .is_some_and(|suffix| suffix.len() == 64 && suffix.iter().all(u8::is_ascii_hexdigit))
}
impl BootstrapArtifactAccess {
    /// An empty directory's authenticated name is published atomically: there
    /// is no partial payload which could strand the first ownership write.
    /// Only a proven empty target can create a claim; retries verify it instead.
    pub fn claim_restore_target(
        &self,
        instance: InstanceId,
        secret: &CatalogSecret,
        intent: [u8; 32],
    ) -> Result<(), BootstrapStorageFailure> {
        let layout = self.layout()?;
        if layout.is_empty_instance() {
            let name = self.restore_claim_name(instance, secret, intent)?;
            unix_fs::mkdirat(&self.data, name.as_str(), Mode::RWXU)
                .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        }
        let directory = self.restore_claim_directory(instance, secret, intent)?;
        synchronize(&directory)?;
        synchronize(&self.data)
    }
    /// Verifies exact instance, intent and held physical roots before resuming
    /// incomplete Catalog staging. No missing claim is created by inspection.
    pub fn verify_restore_target(
        &self,
        instance: InstanceId,
        secret: &CatalogSecret,
        intent: [u8; 32],
    ) -> Result<(), BootstrapStorageFailure> {
        self.restore_claim_directory(instance, secret, intent)
            .map(|_| ())
    }
    fn restore_claim_directory(
        &self,
        instance: InstanceId,
        secret: &CatalogSecret,
        intent: [u8; 32],
    ) -> Result<File, BootstrapStorageFailure> {
        let layout = self.layout()?;
        if layout.unknown_or_unsafe()
            || layout
                .data
                .iter()
                .filter(|entry| **entry == BootstrapEntry::RestoreOwnership)
                .count()
                != 1
        {
            return Err(BootstrapStorageFailure::BoundIdentityMismatch);
        }
        let name = self.restore_claim_name(instance, secret, intent)?;
        let directory = unix_fs::openat(
            &self.data,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| BootstrapStorageFailure::BoundIdentityMismatch)?;
        let metadata = directory
            .metadata()
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        let entry = unix_fs::statat(&self.data, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.dev() != entry.st_dev as u64
            || metadata.ino() != entry.st_ino
        {
            return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
        }
        let mut entries =
            Dir::read_from(&directory).map_err(|_| BootstrapStorageFailure::Unavailable)?;
        while let Some(entry) = entries.read() {
            let entry = entry.map_err(|_| BootstrapStorageFailure::Unavailable)?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
            }
        }
        Ok(directory)
    }
    fn restore_claim_name(
        &self,
        instance: InstanceId,
        secret: &CatalogSecret,
        intent: [u8; 32],
    ) -> Result<String, BootstrapStorageFailure> {
        if intent == [0; 32] {
            return Err(BootstrapStorageFailure::BoundIdentityMismatch);
        }
        let mut payload = instance.to_bytes().to_vec();
        payload.extend_from_slice(&intent);
        payload.extend_from_slice(&self.restore_target_commitment()?);
        let digest = secret
            .opaque_digest(b"positron-restore-target-ownership-v1", &payload)
            .map_err(|_| BootstrapStorageFailure::UnsafeOrCorrupt)?;
        Ok(format!(
            "{PREFIX}{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }
}
