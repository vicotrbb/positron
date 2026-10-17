use super::{UpgradeArtifactIdentity, UpgradeFailure, UpgradeReleasePlan};
use positron_governance::AdministrativeIdempotencyKey;
use positron_kernel::release_manifest::{ArtifactRole, ProductVersion, VerifiedReleaseManifest};
use std::path::PathBuf;

/// One file in the exact signed target artifact inventory.
#[derive(Clone, Debug)]
pub struct UpgradeArtifactInput {
    pub role: ArtifactRole,
    pub platform: String,
    pub path: PathBuf,
}

/// Explicit operator intent. Signatures are verified by the one Release Trust owner.
#[derive(Clone, Debug)]
pub struct UpgradeRequest {
    pub(crate) source: VerifiedReleaseManifest,
    pub(crate) target: VerifiedReleaseManifest,
    pub(crate) artifacts: Vec<UpgradeArtifactInput>,
    pub(crate) repository: [u8; 16],
    pub(crate) retention_seconds: u64,
    pub(crate) idempotency: AdministrativeIdempotencyKey,
    pub(crate) expected_generation: u64,
    #[cfg(test)]
    pub(crate) fixture_executable: Option<PathBuf>,
}
impl UpgradeRequest {
    /// Authenticates the currently executing native payload and every required
    /// target file before returning a supported signed transition.
    pub fn verify_payload(
        &self,
        instance: &crate::InitializedInstance,
        config_schema: u16,
        current_epoch: u32,
    ) -> Result<UpgradeReleasePlan, UpgradeFailure> {
        self.verify_payload_until(instance, config_schema, current_epoch, None)
    }

    pub(crate) fn verify_payload_until(
        &self,
        instance: &crate::InitializedInstance,
        config_schema: u16,
        current_epoch: u32,
        deadline: Option<std::time::Instant>,
    ) -> Result<UpgradeReleasePlan, UpgradeFailure> {
        super::check_admission_deadline(deadline)?;
        let plan = UpgradeReleasePlan::new(
            self.source.clone(),
            self.target.clone(),
            config_schema,
            current_epoch,
        )?;
        if self.source.manifest().version
            != ProductVersion::parse_exact(env!("CARGO_PKG_VERSION"))
                .map_err(|_| UpgradeFailure::UnsafeState)?
        {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        let executable =
            std::env::current_exe().map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        #[cfg(test)]
        let executable = self.fixture_executable.as_ref().unwrap_or(&executable);
        let source = UpgradeReleasePlan::native_artifact(&self.source)?;
        UpgradeArtifactIdentity::measure_until(
            instance,
            executable.as_ref(),
            source.sha256,
            source.size,
            deadline,
        )?;
        // The signed inventory has at most 64 entries, plus this source file.
        let mut measured = Vec::with_capacity(65);
        measured.push((executable.as_ref(), source.sha256, source.size));
        if self.artifacts.len() != self.target.manifest().artifacts.len() {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        for expected in &self.target.manifest().artifacts {
            let mut inputs = self
                .artifacts
                .iter()
                .filter(|input| input.role == expected.role && input.platform == expected.platform);
            let input = inputs.next().ok_or(UpgradeFailure::ArtifactMismatch)?;
            if inputs.next().is_some() {
                return Err(UpgradeFailure::ArtifactMismatch);
            }
            if !measured.iter().any(|(path, digest, size)| {
                *path == input.path.as_path()
                    && *digest == expected.sha256
                    && *size == expected.size
            }) {
                UpgradeArtifactIdentity::measure_until(
                    instance,
                    &input.path,
                    expected.sha256,
                    expected.size,
                    deadline,
                )?;
                measured.push((input.path.as_path(), expected.sha256, expected.size));
            }
        }
        super::check_admission_deadline(deadline)?;
        Ok(plan)
    }

    pub fn new(
        releases: (VerifiedReleaseManifest, VerifiedReleaseManifest),
        artifacts: Vec<UpgradeArtifactInput>,
        repository: [u8; 16],
        retention_seconds: u64,
        expected_generation: u64,
        idempotency: AdministrativeIdempotencyKey,
    ) -> Result<Self, UpgradeFailure> {
        if artifacts.len() > 64
            || repository == [0; 16]
            || expected_generation == 0
            || !(60..=315_360_000).contains(&retention_seconds)
        {
            return Err(UpgradeFailure::InvalidRequest);
        }
        Ok(Self {
            source: releases.0,
            target: releases.1,
            artifacts,
            repository,
            retention_seconds,
            idempotency,
            expected_generation,
            #[cfg(test)]
            fixture_executable: None,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{InitializationPlan, InstanceBootstrap};
    use positron_kernel::release_manifest::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sha2::{Digest, Sha256};
    pub(crate) fn signed(
        version: ProductVersion,
        artifact: [u8; 32],
        size: u64,
    ) -> Result<VerifiedReleaseManifest, Box<dyn std::error::Error>> {
        let key = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "key")?;
        let epoch = FormatCompatibility {
            readable_epochs: vec![2],
            writable_epoch: 2,
            migrations: vec![],
        };
        let manifest = ReleaseManifest {
            version,
            upgrade_from: vec![ProductVersion {
                major: 0,
                minor: 0,
                patch: 0,
            }],
            source_commit: "9fd68fd9eaa72ed45e070412d30656fda1277d79".into(),
            artifacts: [
                ArtifactRole::NativeExecutable,
                ArtifactRole::Schema,
                ArtifactRole::CompatibilityManifest,
                ArtifactRole::Sbom,
                ArtifactRole::Provenance,
            ]
            .into_iter()
            .map(|role| ReleaseArtifact {
                role,
                platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                sha256: artifact,
                size,
                complete: true,
            })
            .collect(),
            compatibility: ReleaseCompatibility {
                config_schema: 1,
                previous_config_schema: None,
                persistent: epoch.clone(),
                backup: epoch,
                api: [1; 32],
                query: [2; 32],
                schema: [3; 32],
                receiver: [4; 32],
                crd: [5; 32],
                operator: [6; 32],
            },
        };
        let mut message = b"positron.release-manifest.v1\0".to_vec();
        message.extend(manifest.canonical_bytes()?);
        let signature = key
            .sign(&message)
            .as_ref()
            .try_into()
            .map_err(|_| "signature")?;
        Ok(
            SignedReleaseManifest::new(manifest, signature)?.verify(&ProjectTrustRoot::new(
                key.public_key()
                    .as_ref()
                    .try_into()
                    .map_err(|_| "public key")?,
            ))?,
        )
    }
    #[test]
    fn preflight_measures_the_complete_target_inventory_before_any_catalog_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let roots = crate::process_lifecycle::TestRoots::new("upgrade-payload")?;
        let instance = InstanceBootstrap::initialize(
            &roots.bootstrap_paths()?,
            InitializationPlan::non_interactive(),
        )?;
        let path = roots.data.join("fixture-executable");
        std::fs::write(&path, b"signed artifact")?;
        let digest: [u8; 32] = Sha256::digest(b"signed artifact").into();
        let source = signed(
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
            digest,
            15,
        )?;
        let target = signed(
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 1,
            },
            digest,
            15,
        )?;
        let artifacts = target
            .manifest()
            .artifacts
            .iter()
            .map(|artifact| UpgradeArtifactInput {
                role: artifact.role,
                platform: artifact.platform.clone(),
                path: path.clone(),
            })
            .collect();
        let mut request = UpgradeRequest::new(
            (source, target),
            artifacts,
            [0x51; 16],
            3600,
            instance.catalog_generation(),
            AdministrativeIdempotencyKey::new([0x52; 16])?,
        )?;
        request.fixture_executable = Some(path.clone());
        let before = instance.catalog_generation();
        assert!(request.verify_payload(&instance, 1, 2).is_ok());
        request.artifacts.pop();
        assert!(matches!(
            request.verify_payload(&instance, 1, 2),
            Err(UpgradeFailure::ArtifactMismatch)
        ));
        assert_eq!(instance.catalog_generation(), before);
        Ok(())
    }
}
