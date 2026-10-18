use super::*;
use positron_kernel::release_manifest::ProductVersion;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::os::unix::fs::PermissionsExt;
// These tests authenticate installed metadata; payload measurement stays at verify_payload.
fn write_complete_target(
    root: &std::path::Path,
    base: VerifiedReleaseManifest,
) -> Result<VerifiedReleaseManifest, Box<dyn std::error::Error>> {
    use positron_kernel::release_manifest::{ProjectTrustRoot, SignedReleaseManifest};
    let pair = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "key")?;
    let (manifest, inventory) = super::super::fixture_metadata::complete_metadata(base.manifest())?;
    std::fs::write(root.join("inventory.json"), inventory)?;
    let signature = pair
        .sign(&manifest.signing_message()?)
        .as_ref()
        .try_into()?;
    let signed = SignedReleaseManifest::new(manifest, signature)?;
    std::fs::write(root.join("candidate"), signed.to_bytes()?)?;
    Ok(signed.verify(&ProjectTrustRoot::new(
        pair.public_key().as_ref().try_into()?,
    ))?)
}
struct Fixture {
    root: std::path::PathBuf,
    target: VerifiedReleaseManifest,
    clock: positron_kernel::RetentionTimeAuthority,
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
        std::fs::write(
            root.join("root.pub"),
            super::super::request::tests::installed_trust(&pair)?,
        )?;
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
        let target = write_complete_target(&root, target)?;
        std::fs::write(root.join("current"), source.signed_bytes())?;
        std::fs::write(root.join("candidate"), target.signed_bytes())?;
        Ok(Self {
            root,
            target,
            clock: positron_kernel::RetentionTimeAuthority::establish()?,
        })
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
            .map(|(index, artifact)| {
                if artifact.role == ArtifactRole::ReleaseInventory {
                    format!("'{}/inventory.json'", self.root.display())
                } else {
                    format!("'{}/artifact-{index}'", self.root.display())
                }
            })
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
        &fixture.clock,
    )?;
    assert_eq!(request.target.digest(), fixture.target.digest());
    assert_eq!(
        request.artifacts.len(),
        fixture.target.manifest().artifacts.len()
    );
    assert!(matches!(
        installed_upgrade_request(
            &configuration,
            [0; 32],
            [4; 16],
            3600,
            key,
            1,
            &fixture.clock
        ),
        Err(UpgradeFailure::ArtifactMismatch)
    ));
    assert!(installed_upgrade_startup(&configuration, &fixture.clock)?.is_some());
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
        installed_upgrade_startup(&configuration, &fixture.clock),
        Err(UpgradeFailure::AuthenticationFailed)
    ));
    std::fs::write(fixture.root.join("root.pub"), &root)?;
    std::fs::remove_file(fixture.root.join("root.pub"))?;
    assert!(installed_upgrade_startup(&configuration, &fixture.clock).is_err());
    std::fs::write(fixture.root.join("root.real"), &root)?;
    std::os::unix::fs::symlink(
        fixture.root.join("root.real"),
        fixture.root.join("root.pub"),
    )?;
    assert!(installed_upgrade_startup(&configuration, &fixture.clock).is_err());
    std::fs::remove_file(fixture.root.join("root.pub"))?;
    std::fs::write(fixture.root.join("root.pub"), root)?;
    let mut manifest = std::fs::read(fixture.root.join("current"))?;
    *manifest.first_mut().ok_or("signature")? ^= 1;
    std::fs::write(fixture.root.join("current"), manifest)?;
    assert!(matches!(
        installed_upgrade_startup(&configuration, &fixture.clock),
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
    let startup = installed_upgrade_startup(&configuration, &fixture.clock)?.ok_or("startup")?;
    assert!(!format!("{startup:?}").contains(&"ab".repeat(32)));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(installed_upgrade_startup(&configuration, &fixture.clock).is_err());
    let ordinary = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            None,
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|failure| format!("configuration: {failure:?}"))?,
    )?;
    assert!(installed_upgrade_startup(&ordinary, &fixture.clock)?.is_none());
    Ok(())
}

#[test]
fn an_authenticated_out_of_support_source_can_start_and_take_its_signed_supported_upgrade_path()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let next = ProductVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    fixture.target = write_complete_target(
        &fixture.root,
        super::super::request::tests::signed(next, [8; 32], 15)?,
    )?;
    std::fs::write(
        fixture.root.join("candidate"),
        fixture.target.signed_bytes(),
    )?;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "key")?;
    let mut installed = positron_release::InstalledReleaseTrust::from_bytes(&std::fs::read(
        fixture.root.join("root.pub"),
    )?)?;
    let mut snapshot = positron_release::TrustSnapshot::from_bytes(
        installed.signed_snapshot.get(64..).ok_or("payload")?,
    )?;
    snapshot.current_version = next;
    installed.signed_snapshot = snapshot.sign(&pair)?;
    std::fs::write(fixture.root.join("root.pub"), installed.canonical_bytes()?)?;
    let configuration = fixture.configuration("")?;
    assert!(installed_upgrade_startup(&configuration, &fixture.clock)?.is_some());
    installed_upgrade_request(
        &configuration,
        fixture.target.digest(),
        [4; 16],
        3600,
        AdministrativeIdempotencyKey::new([3; 16])?,
        1,
        &fixture.clock,
    )?;
    snapshot.current_version.minor = 4;
    installed.signed_snapshot = snapshot.sign(&pair)?;
    std::fs::write(fixture.root.join("root.pub"), installed.canonical_bytes()?)?;
    assert!(installed_upgrade_startup(&configuration, &fixture.clock)?.is_some());
    assert!(matches!(
        installed_upgrade_request(
            &configuration,
            fixture.target.digest(),
            [4; 16],
            3600,
            AdministrativeIdempotencyKey::new([3; 16])?,
            1,
            &fixture.clock
        ),
        Err(UpgradeFailure::UnsupportedTransition)
    ));
    Ok(())
}

#[test]
fn a_signed_native_only_candidate_cannot_omit_the_complete_target_inventory()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    fixture.target = super::super::request::tests::signed(
        ProductVersion {
            major: 0,
            minor: 0,
            patch: 1,
        },
        [8; 32],
        15,
    )?;
    std::fs::write(
        fixture.root.join("candidate"),
        fixture.target.signed_bytes(),
    )?;
    assert!(matches!(
        installed_upgrade_request(
            &fixture.configuration("")?,
            fixture.target.digest(),
            [4; 16],
            3600,
            AdministrativeIdempotencyKey::new([3; 16])?,
            1,
            &fixture.clock
        ),
        Err(UpgradeFailure::AuthenticationFailed)
    ));
    assert!(
        installed_upgrade_startup(&fixture.configuration("")?, &fixture.clock)?.is_some(),
        "legacy source authentication must remain available"
    );
    Ok(())
}

#[test]
fn staged_or_invalid_target_inventory_cannot_enter_native_upgrade()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::release_manifest::{ProjectTrustRoot, SignedReleaseManifest};
    let mut fixture = Fixture::new()?;
    let mut inventory = positron_release::ReleaseInventory::from_bytes(&std::fs::read(
        fixture.root.join("inventory.json"),
    )?)?;
    inventory.artifacts[0].publication.state = positron_release::PublicationState::Staged;
    let bytes = inventory.canonical_bytes()?;
    let mut manifest = fixture.target.manifest().clone();
    let entry = manifest
        .artifacts
        .iter_mut()
        .find(|entry| entry.role == ArtifactRole::ReleaseInventory)
        .ok_or("inventory")?;
    let identity = positron_release::FileIdentity::of(&bytes);
    entry.sha256 = identity.sha256;
    entry.size = identity.size;
    let pair = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "key")?;
    let signature = pair
        .sign(&manifest.signing_message()?)
        .as_ref()
        .try_into()?;
    let signed = SignedReleaseManifest::new(manifest, signature)?;
    fixture.target = signed.verify(&ProjectTrustRoot::new(
        pair.public_key().as_ref().try_into()?,
    ))?;
    std::fs::write(fixture.root.join("candidate"), signed.to_bytes()?)?;
    for bytes in [bytes.as_slice(), b"{}"] {
        std::fs::write(fixture.root.join("inventory.json"), bytes)?;
        assert!(matches!(
            installed_upgrade_request(
                &fixture.configuration("")?,
                fixture.target.digest(),
                [4; 16],
                3600,
                AdministrativeIdempotencyKey::new([3; 16])?,
                1,
                &fixture.clock
            ),
            Err(UpgradeFailure::AuthenticationFailed)
        ));
    }
    Ok(())
}

#[test]
fn successor_release_signer_keeps_the_authenticated_installed_source_available()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let root = Ed25519KeyPair::from_seed_unchecked(&[0x91; 32]).map_err(|_| "root")?;
    let successor = Ed25519KeyPair::from_seed_unchecked(&[0x92; 32]).map_err(|_| "successor")?;
    let mut installed = positron_release::InstalledReleaseTrust::from_bytes(&std::fs::read(
        fixture.root.join("root.pub"),
    )?)?;
    let mut snapshot = positron_release::TrustSnapshot::from_bytes(
        installed.signed_snapshot.get(64..).ok_or("snapshot")?,
    )?;
    let mut identity = snapshot.identities.first().ok_or("identity")?.clone();
    identity.public_key = successor.public_key().as_ref().try_into()?;
    identity.purpose = positron_release::KeyPurpose::Release;
    snapshot.identities.push(identity);
    for identity in &mut snapshot.identities {
        if identity.public_key == root.public_key().as_ref()
            && identity.purpose == positron_release::KeyPurpose::Release
        {
            identity.purpose = positron_release::KeyPurpose::InstalledSource;
        }
    }
    installed.release_signer = successor.public_key().as_ref().try_into()?;
    installed.signed_snapshot = snapshot.sign(&root)?;
    std::fs::write(fixture.root.join("root.pub"), installed.canonical_bytes()?)?;
    let manifest = fixture.target.manifest().clone();
    let signed = positron_kernel::release_manifest::SignedReleaseManifest::new(
        manifest.clone(),
        successor
            .sign(&manifest.signing_message()?)
            .as_ref()
            .try_into()?,
    )?;
    std::fs::write(fixture.root.join("candidate"), signed.to_bytes()?)?;
    let configuration = fixture.configuration("")?;
    assert!(installed_upgrade_startup(&configuration, &fixture.clock)?.is_some());
    installed_upgrade_request(
        &configuration,
        fixture.target.digest(),
        [4; 16],
        3600,
        AdministrativeIdempotencyKey::new([3; 16])?,
        1,
        &fixture.clock,
    )?;
    let now = fixture.clock.security_time_seconds()?;
    let trust = installed.verify(now)?;
    let source = std::fs::read(fixture.root.join("current"))?;
    assert!(
        positron_release::verify_manifest(&source, root.public_key().as_ref().try_into()?, &trust)
            .is_err()
    );
    snapshot
        .revoked_keys
        .push(root.public_key().as_ref().try_into()?);
    installed.signed_snapshot = snapshot.sign(&root)?;
    std::fs::write(fixture.root.join("root.pub"), installed.canonical_bytes()?)?;
    assert!(installed_upgrade_startup(&configuration, &fixture.clock).is_err());
    snapshot.revoked_keys.clear();
    snapshot
        .revoked_keys
        .push(successor.public_key().as_ref().try_into()?);
    installed.signed_snapshot = snapshot.sign(&root)?;
    std::fs::write(fixture.root.join("root.pub"), installed.canonical_bytes()?)?;
    assert!(
        installed_upgrade_request(
            &configuration,
            fixture.target.digest(),
            [4; 16],
            3600,
            AdministrativeIdempotencyKey::new([3; 16])?,
            1,
            &fixture.clock
        )
        .is_err()
    );
    Ok(())
}
