use super::UpgradeFailure;

/// Content identity measured from an opened native artifact under resource admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradeArtifactIdentity {
    digest: [u8; 32],
    bytes: u64,
}

impl UpgradeArtifactIdentity {
    /// Measures a regular file through one no-follow descriptor. The descriptor,
    /// buffer, and I/O permit are admitted before the file is opened.
    pub fn measure(
        instance: &crate::InitializedInstance,
        path: &std::path::Path,
        expected: [u8; 32],
        expected_bytes: u64,
    ) -> Result<Self, UpgradeFailure> {
        use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim};
        use sha2::{Digest, Sha256};
        use std::io::Read;
        const MAX_ARTIFACT_BYTES: u64 = 1_073_741_824;
        const BUFFER_BYTES: usize = 65_536;
        if !path.is_absolute()
            || expected == [0; 32]
            || expected_bytes == 0
            || expected_bytes > MAX_ARTIFACT_BYTES
        {
            return Err(UpgradeFailure::InvalidRequest);
        }
        let amounts =
            ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| match dimension {
                ResourceDimension::MemoryBytes => BUFFER_BYTES as u64,
                ResourceDimension::FileDescriptors
                | ResourceDimension::IoPermits
                | ResourceDimension::CpuWorkUnits => 1,
                _ => 0,
            }));
        let _reservation = instance
            .resource_governor()
            .reserve(
                WorkClaim::upgrade_preflight(amounts)
                    .map_err(|_| UpgradeFailure::CapacityUnavailable)?,
            )
            .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        let mut file = std::fs::File::from(descriptor);
        let before = file
            .metadata()
            .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        if !before.is_file() {
            return Err(UpgradeFailure::ArtifactUnavailable);
        }
        if before.len() != expected_bytes {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        let mut hash = Sha256::new();
        let mut buffer = vec![0_u8; BUFFER_BYTES];
        let mut bytes = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(read as u64)
                .ok_or(UpgradeFailure::ArtifactMismatch)?;
            if bytes > expected_bytes {
                return Err(UpgradeFailure::ArtifactMismatch);
            }
            hash.update(
                buffer
                    .get(..read)
                    .ok_or(UpgradeFailure::ArtifactUnavailable)?,
            );
        }
        let after = file
            .metadata()
            .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        let digest: [u8; 32] = hash.finalize().into();
        if bytes != expected_bytes
            || digest != expected
            || before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        Ok(Self { digest, bytes })
    }
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InitializationPlan, InstanceBootstrap};
    use sha2::{Digest, Sha256};
    #[test]
    fn measured_artifact_requires_exact_bytes_and_releases_resource_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let roots = crate::process_lifecycle::TestRoots::new("upgrade-artifact")?;
        let instance = InstanceBootstrap::initialize(
            &roots.bootstrap_paths()?,
            InitializationPlan::non_interactive(),
        )?;
        let path = roots.data.join("candidate");
        std::fs::write(&path, b"actual candidate bytes")?;
        let expected: [u8; 32] = Sha256::digest(b"actual candidate bytes").into();
        let identity = UpgradeArtifactIdentity::measure(&instance, &path, expected, 22)?;
        assert_eq!(identity.digest(), expected);
        assert_eq!(identity.bytes(), 22);
        assert_eq!(
            UpgradeArtifactIdentity::measure(&instance, &path, [7; 32], 22),
            Err(UpgradeFailure::ArtifactMismatch)
        );
        assert_eq!(
            UpgradeArtifactIdentity::measure(&instance, &path, expected, 21),
            Err(UpgradeFailure::ArtifactMismatch)
        );
        assert_eq!(
            UpgradeArtifactIdentity::measure(&instance, &roots.data, expected, 22),
            Err(UpgradeFailure::ArtifactUnavailable)
        );
        assert_eq!(
            UpgradeArtifactIdentity::measure(&instance, &path, expected, 0),
            Err(UpgradeFailure::InvalidRequest)
        );
        assert!(UpgradeArtifactIdentity::measure(&instance, &path, expected, 22).is_ok());
        Ok(())
    }
}
