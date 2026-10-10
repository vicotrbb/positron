//! Exact predecessor custody removal relative to the held secrets directory.
use super::*;

impl BootstrapArtifactAccess {
    pub(crate) fn retire_predecessor_key(
        &self,
        identity: crate::BootstrapKeyIdentity,
        epoch: u64,
        absence_authorized: bool,
    ) -> Result<(), BootstrapKeyFailure> {
        let name = match epoch {
            0 => return Err(BootstrapKeyFailure::InvalidInput),
            1 => "local-root-key.v1".to_owned(),
            _ => format!("local-root-key.epoch-{epoch}.v1"),
        };
        match unix_fs::statat(&self.secrets, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) if absence_authorized => {
                return BootstrapKeyCustody::synchronize_root_envelope_directory(&self.secrets);
            },
            Err(_) => return Err(BootstrapKeyFailure::Custody),
            Ok(_) => {},
        }
        BootstrapKeyCustody::retire_named_predecessor(&self.secrets, &name, identity)
    }
}
