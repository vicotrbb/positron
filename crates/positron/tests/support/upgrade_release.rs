//! Independently signed fixture metadata; no distribution qualification claim.
use positron_kernel::release_manifest::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[path = "../../../positron-release/tests/support/upgrade_metadata.rs"]
mod upgrade_metadata;
fn release(
    epoch: u32,
    version: ProductVersion,
    executable: &Path,
    key: &Ed25519KeyPair,
    source_commit: &str,
    distribution: positron_config::ExecutableDistribution,
) -> Result<(VerifiedReleaseManifest, Vec<u8>)> {
    let bytes = fs::read(executable)?;
    let digest = Sha256::digest(&bytes).into();
    let backup = positron_backup::BackupFormatEpoch::NATIVE_WRITER.value();
    let manifest = ReleaseManifest {
        version,
        upgrade_from: vec![ProductVersion {
            major: 0,
            minor: 0,
            patch: 0,
        }],
        // Fixture metadata is signed independently; only executable bytes and
        // the compiled package version are real build identities in this test.
        source_commit: source_commit.into(),
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
            sha256: digest,
            size: bytes.len() as u64,
            complete: true,
        })
        .collect(),
        compatibility: ReleaseCompatibility {
            config_schema: 1,
            previous_config_schema: None,
            persistent: FormatCompatibility {
                readable_epochs: vec![epoch],
                writable_epoch: epoch,
                migrations: vec![],
            },
            backup: FormatCompatibility {
                readable_epochs: vec![backup],
                writable_epoch: backup,
                migrations: vec![],
            },
            receiver: [1; 32],
            api: [2; 32],
            query: [3; 32],
            schema: [4; 32],
            crd: [5; 32],
            operator: [6; 32],
        },
    };
    let (mut manifest, inventory) = upgrade_metadata::complete_metadata(&manifest)?;
    let mut inventory = positron_release::ReleaseInventory::from_bytes(&inventory)?;
    if version.patch == 0 {
        let prefix = match distribution {
            positron_config::ExecutableDistribution::Native => "",
            positron_config::ExecutableDistribution::Nix => "nix-",
        };
        let selected = format!(
            "{prefix}{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        let foreign = positron_release::FileIdentity::of(b"another executable distribution");
        for artifact in &mut inventory.artifacts {
            if artifact.surface == positron_release::Surface::NativeExecutable
                && artifact.target != selected
            {
                inventory
                    .files
                    .iter_mut()
                    .find(|file| file.id == artifact.file)
                    .ok_or("fixture file")?
                    .identity = foreign.clone();
                artifact.publication.immutable_identity = format!(
                    "sha256:{}",
                    foreign
                        .sha256
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
                let entry = manifest
                    .artifacts
                    .iter_mut()
                    .find(|entry| {
                        entry.role == ArtifactRole::NativeExecutable
                            && entry.platform == artifact.target
                    })
                    .ok_or("fixture executable")?;
                entry.sha256 = foreign.sha256;
                entry.size = foreign.size;
            }
        }
    }
    inventory.validate_complete()?;
    let inventory = inventory.canonical_bytes()?;
    let identity = positron_release::FileIdentity::of(&inventory);
    let entry = manifest
        .artifacts
        .iter_mut()
        .find(|entry| entry.role == ArtifactRole::ReleaseInventory)
        .ok_or("fixture inventory")?;
    entry.sha256 = identity.sha256;
    entry.size = identity.size;
    let mut signed = b"positron.release-manifest.v1\0".to_vec();
    signed.extend(manifest.canonical_bytes()?);
    let signature = key
        .sign(&signed)
        .as_ref()
        .try_into()
        .map_err(|_| "signature")?;
    Ok((
        SignedReleaseManifest::new(manifest, signature)?.verify(&ProjectTrustRoot::new(
            key.public_key()
                .as_ref()
                .try_into()
                .map_err(|_| "trust root")?,
        ))?,
        inventory,
    ))
}
pub(crate) fn configuration(
    root: &Path,
    distribution: positron_config::ExecutableDistribution,
    epoch: u32,
    query: &str,
    executables: (&Path, &Path),
    commits: (&str, &str),
) -> Result<(positron_config::EffectiveConfiguration, [u8; 32])> {
    let (source_executable, candidate_executable) = executables;
    let (source_commit, candidate_commit) = commits;
    let key =
        Ed25519KeyPair::from_seed_unchecked(&[0x93; 32]).map_err(|_| "fixture signing key")?;
    let (source, source_inventory) = release(
        epoch,
        ProductVersion::parse_exact(env!("CARGO_PKG_VERSION"))?,
        source_executable,
        &key,
        source_commit,
        distribution,
    )?;
    let (target, _) = release(
        epoch,
        ProductVersion {
            major: 0,
            minor: 0,
            patch: 1,
        },
        candidate_executable,
        &key,
        candidate_commit,
        distribution,
    )?;
    let export = root.join("export");
    let trust = export.join("project.pub");
    let current = export.join("current.manifest");
    let candidate = export.join("candidate.manifest");
    let credential = export.join("query.credential");
    let current_inventory = export.join("current.inventory.json");
    fs::write(&current_inventory, source_inventory)?;
    let target_paths =
        upgrade_metadata::artifact_paths(target.manifest(), candidate_executable, &export)?;
    use positron_release::{
        InstalledProjectTrustRoot, InstalledReleaseTrust, KeyPurpose, SigningIdentity,
        TrustSnapshot,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let public_key = key.public_key().as_ref().try_into()?;
    let snapshot = TrustSnapshot {
        format: 1,
        sequence: 1,
        current_version: ProductVersion {
            major: 0,
            minor: 0,
            patch: 1,
        },
        issued_unix: now - 60,
        expires_unix: now + 3600,
        identities: vec![SigningIdentity {
            public_key,
            purpose: KeyPurpose::Release,
            not_before_unix: now - 60,
            expires_unix: now + 3600,
        }],
        native_publishers: vec![],
        revoked_keys: vec![],
        revoked_manifests: vec![],
        revoked_artifacts: vec![],
    };
    let installed = InstalledReleaseTrust {
        format: 1,
        root: InstalledProjectTrustRoot {
            public_key,
            minimum_sequence: 1,
        },
        release_signer: public_key,
        signed_snapshot: snapshot.sign(&key)?,
    }
    .canonical_bytes()?;
    for (path, bytes) in [
        (&trust, installed.as_slice()),
        (&current, source.signed_bytes()),
        (&candidate, target.signed_bytes()),
        (&credential, query.as_bytes()),
    ] {
        fs::write(path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let artifacts = target
        .manifest()
        .artifacts
        .iter()
        .zip(&target_paths)
        .map(|(_, path)| format!("{path:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let distribution = match distribution {
        positron_config::ExecutableDistribution::Native => "native",
        positron_config::ExecutableDistribution::Nix => "nix",
    };
    let text = format!(
        "schema_version=1\n[storage]\ndata_directory={:?}\nsecrets_directory={:?}\n\
        [release.installation]\nexecutable_distribution={distribution:?}\nproject_trust_root_file={trust:?}\ncurrent_manifest_file={current:?}\ncurrent_inventory_file={current_inventory:?}\n\
        candidate_manifest_file={candidate:?}\ncandidate_artifact_files=[{artifacts}]\nquery_credential_file={credential:?}\n",
        root.join("data"),
        root.join("secrets")
    );
    let path = root.join("positron.toml");
    fs::write(&path, text)?;
    let effective = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&path),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|_| "fixture configuration inputs")?,
    )?;
    Ok((effective, target.digest()))
}
