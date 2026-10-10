//! Atomic bootstrap recovery-route publication, before root custody publication.
use super::*;

impl BootstrapArtifactAccess {
    pub(crate) fn read_system_key_envelope(&self) -> Result<Vec<u8>, BootstrapKeyFailure> {
        self.read_envelope(BootstrapArtifact::SystemKeyEnvelope)
    }
    fn read_envelope(&self, artifact: BootstrapArtifact) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let mut file = self.verified_envelope_file(artifact, OFlags::RDONLY)?;
        let size = usize::try_from(
            file.metadata()
                .map_err(|_| BootstrapKeyFailure::Custody)?
                .len(),
        )
        .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        if size == 0 || size > 16_384 {
            return Err(BootstrapKeyFailure::LimitExceeded);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        bytes.resize(size, 0);
        file.read_exact(&mut bytes)
            .map_err(|_| BootstrapKeyFailure::Custody)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| BootstrapKeyFailure::Custody)?
            != 0
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        Ok(bytes)
    }
    pub(crate) fn publish_recovered_system_envelope(
        &self,
        bytes: &[u8],
    ) -> Result<(), BootstrapKeyFailure> {
        self.publish_system_envelope(bytes, None)
    }
    pub(crate) fn replace_recovered_system_envelope(
        &self,
        expected: &[u8],
        bytes: &[u8],
    ) -> Result<(), BootstrapKeyFailure> {
        if expected.is_empty() || expected.len() > 16_384 {
            return Err(BootstrapKeyFailure::LimitExceeded);
        }
        self.publish_system_envelope(bytes, Some(expected))
    }
    fn publish_system_envelope(
        &self,
        bytes: &[u8],
        expected: Option<&[u8]>,
    ) -> Result<(), BootstrapKeyFailure> {
        if bytes.is_empty() || bytes.len() > 16_384 {
            return Err(BootstrapKeyFailure::LimitExceeded);
        }
        let final_artifact = BootstrapArtifact::SystemKeyEnvelope;
        let staging = BootstrapArtifact::SystemKeyEnvelopeStaging;
        let previous = if self
            .exists(final_artifact)
            .map_err(|_| BootstrapKeyFailure::Custody)?
        {
            let original = self.read_envelope(final_artifact)?;
            if original == bytes {
                return BootstrapKeyCustody::synchronize_root_envelope_directory(&self.data);
            }
            if expected != Some(original.as_slice()) {
                return Err(BootstrapKeyFailure::Authentication);
            }
            Some(self.verified_envelope_file(final_artifact, OFlags::RDONLY)?)
        } else {
            if expected.is_some() {
                return Err(BootstrapKeyFailure::Authentication);
            }
            None
        };
        if self
            .exists(staging)
            .map_err(|_| BootstrapKeyFailure::Custody)?
        {
            let file = self.verified_envelope_file(staging, OFlags::RDONLY)?;
            let matching = self
                .read_envelope(staging)
                .is_ok_and(|staged| staged == bytes);
            if matching {
                file.sync_all().map_err(|_| BootstrapKeyFailure::Custody)?;
            } else {
                drop(file);
                self.remove(staging)
                    .map_err(|_| BootstrapKeyFailure::Custody)?;
            }
        }
        if !self
            .exists(staging)
            .map_err(|_| BootstrapKeyFailure::Custody)?
        {
            let mut file = self
                .verified_envelope_file(staging, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
            BootstrapKeyCustody::write_root_envelope(&mut file, bytes)?;
        }
        let file = self.verified_envelope_file(staging, OFlags::RDONLY)?;
        if self.read_envelope(staging)? != bytes {
            return Err(BootstrapKeyFailure::Authentication);
        }
        file.sync_all().map_err(|_| BootstrapKeyFailure::Custody)?;
        if let Some(previous) = previous.as_ref() {
            let held = previous
                .metadata()
                .map_err(|_| BootstrapKeyFailure::Custody)?;
            let current = self.verified_envelope_file(final_artifact, OFlags::RDONLY)?;
            let entry = current
                .metadata()
                .map_err(|_| BootstrapKeyFailure::Custody)?;
            if held.dev() != entry.dev()
                || held.ino() != entry.ino()
                || self.read_envelope(final_artifact)?.as_slice()
                    != expected.ok_or(BootstrapKeyFailure::Authentication)?
            {
                return Err(BootstrapKeyFailure::Authentication);
            }
        }
        unix_fs::renameat_with(
            &self.data,
            staging.name(),
            &self.data,
            final_artifact.name(),
            if previous.is_some() {
                RenameFlags::empty()
            } else {
                RenameFlags::NOREPLACE
            },
        )
        .map_err(|_| BootstrapKeyFailure::Custody)?;
        BootstrapKeyCustody::synchronize_root_envelope_directory(&self.data)
    }

    fn verified_envelope_file(
        &self,
        artifact: BootstrapArtifact,
        flags: OFlags,
    ) -> Result<File, BootstrapKeyFailure> {
        let file = unix_fs::openat(
            &self.data,
            artifact.name(),
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|_| BootstrapKeyFailure::Custody)?;
        let metadata = file.metadata().map_err(|_| BootstrapKeyFailure::Custody)?;
        let owner = self
            .data
            .metadata()
            .map_err(|_| BootstrapKeyFailure::Custody)?
            .uid();
        let entry = unix_fs::statat(&self.data, artifact.name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| BootstrapKeyFailure::Custody)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o600
            || entry.st_dev as u64 != metadata.dev()
            || entry.st_ino != metadata.ino()
            || entry.st_nlink != 1
        {
            return Err(BootstrapKeyFailure::Custody);
        }
        Ok(file)
    }
}
