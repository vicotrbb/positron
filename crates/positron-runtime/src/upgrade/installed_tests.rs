use super::*;
use positron_kernel::release_manifest::ProductVersion;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::os::unix::fs::PermissionsExt;
// These tests authenticate installed metadata; payload measurement stays at verify_payload.
struct Fixture {
    root: std::path::PathBuf,
    target: VerifiedReleaseManifest,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-installed-release-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root)?;
        let root = std::fs::canonicalize(root)?;
        let pair = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "fixture root")?;
        std::fs::write(root.join("root.pub"), pair.public_key().as_ref())?;
        let source = super::super::request::tests::signed(
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
            [7; 32],
            15,
        )?;
        let target = super::super::request::tests::signed(
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 1,
            },
            [8; 32],
            15,
        )?;
        std::fs::write(root.join("current"), source.signed_bytes())?;
        std::fs::write(root.join("candidate"), target.signed_bytes())?;
        Ok(Self { root, target })
    }
    fn configuration(
        &self,
        extra: &str,
    ) -> Result<EffectiveConfiguration, Box<dyn std::error::Error>> {
        let artifacts = self
            .target
            .manifest()
            .artifacts
            .iter()
            .enumerate()
            .map(|(index, _)| format!("'{}/artifact-{index}'", self.root.display()))
            .collect::<Vec<_>>()
            .join(",");
        let doc = format!(
            "schema_version=1\n[release.installation]\nproject_trust_root_file='{}/root.pub'\ncurrent_manifest_file='{}/current'\ncandidate_manifest_file='{}/candidate'\ncandidate_artifact_files=[{artifacts}]\n{extra}",
            self.root.display(),
            self.root.display(),
            self.root.display()
        );
        let inputs = positron_config::ConfigurationInputs::try_new(
            Some(&doc),
            positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?;
        Ok(positron_config::resolve(inputs)?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn installed_candidate_is_selected_only_by_its_authenticated_digest()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.configuration("")?;
    let key = AdministrativeIdempotencyKey::new([3; 16])?;
    let request = installed_upgrade_request(
        &configuration,
        fixture.target.digest(),
        [4; 16],
        3600,
        key,
        1,
    )?;
    assert_eq!(request.target.digest(), fixture.target.digest());
    assert_eq!(
        request.artifacts.len(),
        fixture.target.manifest().artifacts.len()
    );
    assert!(matches!(
        installed_upgrade_request(&configuration, [0; 32], [4; 16], 3600, key, 1),
        Err(UpgradeFailure::ArtifactMismatch)
    ));
    assert!(installed_upgrade_startup(&configuration)?.is_some());
    Ok(())
}
#[test]
fn missing_root_bad_signature_and_symlink_authority_are_refused()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.configuration("")?;
    let root = std::fs::read(fixture.root.join("root.pub"))?;
    let other = Ed25519KeyPair::from_seed_unchecked(&[0x92; 32]).map_err(|_| "other root")?;
    std::fs::write(fixture.root.join("root.pub"), other.public_key().as_ref())?;
    assert!(matches!(
        installed_upgrade_startup(&configuration),
        Err(UpgradeFailure::AuthenticationFailed)
    ));
    std::fs::write(fixture.root.join("root.pub"), &root)?;
    std::fs::remove_file(fixture.root.join("root.pub"))?;
    assert!(installed_upgrade_startup(&configuration).is_err());
    std::fs::write(fixture.root.join("root.real"), &root)?;
    std::os::unix::fs::symlink(
        fixture.root.join("root.real"),
        fixture.root.join("root.pub"),
    )?;
    assert!(installed_upgrade_startup(&configuration).is_err());
    std::fs::remove_file(fixture.root.join("root.pub"))?;
    std::fs::write(fixture.root.join("root.pub"), root)?;
    let mut manifest = std::fs::read(fixture.root.join("current"))?;
    *manifest.first_mut().ok_or("signature")? ^= 1;
    std::fs::write(fixture.root.join("current"), manifest)?;
    assert!(matches!(
        installed_upgrade_startup(&configuration),
        Err(UpgradeFailure::AuthenticationFailed)
    ));
    Ok(())
}
#[test]
fn startup_query_key_stays_private_and_unconfigured_release_is_absent()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let path = fixture.root.join("query.key");
    std::fs::write(&path, format!("pos_{}\n", "ab".repeat(32)))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let configuration =
        fixture.configuration(&format!("query_credential_file='{}'\n", path.display()))?;
    let startup = installed_upgrade_startup(&configuration)?.ok_or("startup")?;
    assert!(!format!("{startup:?}").contains(&"ab".repeat(32)));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(installed_upgrade_startup(&configuration).is_err());
    let ordinary = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            None,
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|failure| format!("configuration: {failure:?}"))?,
    )?;
    assert!(installed_upgrade_startup(&ordinary)?.is_none());
    Ok(())
}
