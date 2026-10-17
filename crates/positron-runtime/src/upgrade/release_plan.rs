//! Signed release compatibility preflight; format transformation is deliberately unsupported.
use super::UpgradeFailure;
use positron_kernel::release_manifest::{ArtifactRole, ReleaseArtifact, VerifiedReleaseManifest};

#[derive(Clone, Debug)]
pub struct UpgradeReleasePlan {
    source: VerifiedReleaseManifest,
    target: VerifiedReleaseManifest,
    config_schema: u16,
    current_epoch: u32,
}
impl UpgradeReleasePlan {
    pub fn new(
        source: VerifiedReleaseManifest,
        target: VerifiedReleaseManifest,
        config_schema: u16,
        current_epoch: u32,
    ) -> Result<Self, UpgradeFailure> {
        let old = source.manifest();
        let new = target.manifest();
        let config = u32::from(config_schema);
        let backup_epoch = positron_backup::BackupFormatEpoch::NATIVE_WRITER.value();
        // Only the exact signed edge authorizes a product transition; opaque
        // independent claims are authenticated without guessing from semver.
        if new.version <= old.version
            || new.version.major != old.version.major
            || !new.upgrade_from.contains(&old.version)
            || (new.compatibility.config_schema != config
                && new.compatibility.previous_config_schema != Some(config))
            || old.compatibility.persistent.writable_epoch != current_epoch
            || new.compatibility.persistent.writable_epoch != current_epoch
            || !new
                .compatibility
                .persistent
                .readable_epochs
                .contains(&current_epoch)
            || old.compatibility.backup.writable_epoch != backup_epoch
            || new.compatibility.backup.writable_epoch != backup_epoch
            || !new
                .compatibility
                .backup
                .readable_epochs
                .contains(&old.compatibility.backup.writable_epoch)
        {
            return Err(UpgradeFailure::UnsupportedTransition);
        }
        Self::native_artifact(&source)?;
        Self::native_artifact(&target)?;
        Ok(Self {
            source,
            target,
            config_schema,
            current_epoch,
        })
    }
    pub fn source(&self) -> &VerifiedReleaseManifest {
        &self.source
    }
    pub fn target(&self) -> &VerifiedReleaseManifest {
        &self.target
    }
    pub const fn config_schema(&self) -> u16 {
        self.config_schema
    }
    pub const fn current_epoch(&self) -> u32 {
        self.current_epoch
    }
    pub fn native_artifact(
        manifest: &VerifiedReleaseManifest,
    ) -> Result<&ReleaseArtifact, UpgradeFailure> {
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let mut artifacts = manifest.manifest().artifacts.iter().filter(|artifact| {
            artifact.role == ArtifactRole::NativeExecutable && artifact.platform == platform
        });
        let artifact = artifacts.next().ok_or(UpgradeFailure::ArtifactMismatch)?;
        if artifacts.next().is_some() {
            return Err(UpgradeFailure::ArtifactMismatch);
        }
        Ok(artifact)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use positron_kernel::release_manifest::{
        FormatCompatibility, ProductVersion, ProjectTrustRoot, ReleaseCompatibility,
        ReleaseManifest, SignedReleaseManifest,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    fn version(patch: u32) -> ProductVersion {
        ProductVersion {
            major: 0,
            minor: 0,
            patch,
        }
    }
    fn fixture(patch: u32) -> ReleaseManifest {
        let format = FormatCompatibility {
            readable_epochs: vec![2],
            writable_epoch: 2,
            migrations: vec![],
        };
        ReleaseManifest {
            version: version(patch),
            upgrade_from: vec![version(0)],
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
                sha256: [9; 32],
                size: 42,
                complete: true,
            })
            .collect(),
            compatibility: ReleaseCompatibility {
                config_schema: 1,
                previous_config_schema: None,
                persistent: format.clone(),
                backup: format,
                receiver: [6; 32],
                api: [1; 32],
                query: [2; 32],
                schema: [3; 32],
                crd: [4; 32],
                operator: [5; 32],
            },
        }
    }
    fn signed(manifest: ReleaseManifest) -> VerifiedReleaseManifest {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).expect("test key");
        let mut message = b"positron.release-manifest.v1\0".to_vec();
        message.extend(manifest.canonical_bytes().expect("valid fixture"));
        SignedReleaseManifest::new(
            manifest,
            pair.sign(&message).as_ref().try_into().expect("signature"),
        )
        .expect("signed fixture")
        .verify(&ProjectTrustRoot::new(
            pair.public_key().as_ref().try_into().expect("public key"),
        ))
        .expect("authenticated fixture")
    }
    #[test]
    fn signed_backup_claim_must_match_native_verification_capabilities() {
        for unsupported_epoch in [1, 99] {
            let mut source = fixture(0);
            let mut target = fixture(1);
            for manifest in [&mut source, &mut target] {
                manifest.compatibility.backup.writable_epoch = unsupported_epoch;
                manifest.compatibility.backup.readable_epochs = vec![unsupported_epoch];
            }
            assert!(matches!(
                UpgradeReleasePlan::new(signed(source), signed(target), 1, 2),
                Err(UpgradeFailure::UnsupportedTransition)
            ));
        }
    }
    #[test]
    fn exact_published_patch_path_preserves_verified_identities() {
        let source = signed(fixture(0));
        let target = signed(fixture(1));
        let target_digest = target.digest();
        let plan = UpgradeReleasePlan::new(source, target, 1, 2).expect("compatible signed patch");
        assert_eq!(plan.target().digest(), target_digest);
        assert_eq!(plan.source().manifest().version, version(0));
        assert_eq!(plan.config_schema(), 1);
        assert_eq!(plan.current_epoch(), 2);
        assert_eq!(
            UpgradeReleasePlan::native_artifact(plan.target())
                .expect("native artifact")
                .size,
            42
        );
    }
    #[test]
    fn release_plan_refuses_unpublished_skew_and_unsupported_instance_formats() {
        for mutate in [
            |m: &mut ReleaseManifest| m.upgrade_from.clear(),
            |m: &mut ReleaseManifest| m.version = version(0),
            |m: &mut ReleaseManifest| {
                m.version = ProductVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                }
            },
            |m: &mut ReleaseManifest| m.upgrade_from = vec![version(9)],
            |m: &mut ReleaseManifest| {
                m.compatibility.config_schema = 3;
                m.compatibility.previous_config_schema = Some(2);
            },
            |m: &mut ReleaseManifest| {
                m.compatibility.persistent.writable_epoch = 3;
                m.compatibility.persistent.readable_epochs = vec![2, 3];
            },
            |m: &mut ReleaseManifest| {
                m.compatibility.backup.writable_epoch = 3;
                m.compatibility.backup.readable_epochs = vec![2, 3];
            },
            |m: &mut ReleaseManifest| m.artifacts[0].platform = "foreign-platform".into(),
        ] {
            let mut target = fixture(1);
            mutate(&mut target);
            assert!(UpgradeReleasePlan::new(signed(fixture(0)), signed(target), 1, 2).is_err());
        }
        assert!(UpgradeReleasePlan::new(signed(fixture(0)), signed(fixture(1)), 1, 3).is_err());
    }
    #[test]
    fn published_additive_claims_and_previous_config_remain_supported() {
        let mut target = fixture(1);
        target.version = ProductVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        target.compatibility.api = [10; 32];
        target.compatibility.query = [11; 32];
        target.compatibility.schema = [12; 32];
        target.compatibility.receiver = [13; 32];
        target.compatibility.config_schema = 2;
        target.compatibility.previous_config_schema = Some(1);
        target.compatibility.persistent.readable_epochs.push(3);
        target.compatibility.backup.readable_epochs.push(3);
        assert!(UpgradeReleasePlan::new(signed(fixture(0)), signed(target), 1, 2).is_ok());
        let mut downgrade = fixture(1);
        downgrade.upgrade_from = vec![version(2)];
        assert!(matches!(
            UpgradeReleasePlan::new(signed(fixture(2)), signed(downgrade), 1, 2),
            Err(UpgradeFailure::UnsupportedTransition)
        ));
        let mut source = fixture(0);
        source.artifacts[0].platform = "foreign-platform".into();
        assert!(matches!(
            UpgradeReleasePlan::new(signed(source), signed(fixture(1)), 1, 2),
            Err(UpgradeFailure::ArtifactMismatch)
        ));
    }
}
