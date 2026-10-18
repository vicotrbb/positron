//! Declared release metadata for native Upgrade lifecycle fixtures.
//! These descriptors do not claim that SDK package bytes were staged or qualified.
use positron_kernel::release_manifest::{ArtifactRole, ReleaseArtifact, ReleaseManifest};
use positron_release::{
    Artifact, BuildInput, FileIdentity, InventoryFile, Publication, PublicationState,
    ReleaseInventory, SecuritySupport, Surface, required_release_one,
};
use std::{
    error::Error,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn complete_metadata(base: &ReleaseManifest) -> Result<(ReleaseManifest, Vec<u8>)> {
    let native = base
        .artifacts
        .iter()
        .find(|entry| entry.role == ArtifactRole::NativeExecutable)
        .ok_or("native fixture executable missing")?;
    let identity = FileIdentity {
        sha256: native.sha256,
        size: native.size,
    };
    let mut compatibility = base.compatibility.clone();
    compatibility.schema = identity.sha256;
    let mut inventory = ReleaseInventory {
        format: 1,
        version: base.version,
        source_commit: base.source_commit.clone(),
        build_identity: "native-upgrade-fixture".into(),
        api_version: "positron.v1".into(),
        compatibility,
        inputs: Vec::new(),
        files: Vec::new(),
        artifacts: Vec::new(),
        security_support: SecuritySupport {
            expires_unix: u64::MAX,
            upgrade_paths: vec![identity.sha256],
        },
    };
    for name in [
        "rust",
        "linker",
        "protobuf",
        "openapi",
        "sdk",
        "frontend",
        "packaging",
        "documentation",
        "lockfile",
    ] {
        let file = format!("input-{name}");
        inventory.files.push(InventoryFile {
            id: file.clone(),
            identity: identity.clone(),
        });
        inventory.inputs.push(BuildInput {
            name: name.into(),
            version: "1.0.0".into(),
            file,
        });
    }
    let version = format!(
        "{}.{}.{}",
        base.version.major, base.version.minor, base.version.patch
    );
    for (index, &(surface, target)) in required_release_one().iter().enumerate() {
        if surface == Surface::SdkJava {
            for (classifier, extension) in [
                ("", "pom"),
                ("", "jar"),
                ("sources", "jar"),
                ("javadoc", "jar"),
            ] {
                let suffix = if classifier.is_empty() {
                    String::new()
                } else {
                    format!("-{classifier}")
                };
                let file = format!("sdk-{version}{suffix}.{extension}");
                let query = if classifier.is_empty() {
                    format!("type={extension}")
                } else {
                    format!("classifier={classifier}&type={extension}")
                };
                add(
                    &mut inventory,
                    surface,
                    target,
                    file,
                    (
                        "https://repo.maven.apache.org/maven2".into(),
                        format!("pkg:maven/dev.positron/sdk@{version}?{query}"),
                    ),
                    extension != "pom",
                    &identity,
                )?;
            }
        } else {
            let (registry, subject) = match surface {
                Surface::SdkRust => (
                    "https://crates.io".into(),
                    format!("pkg:cargo/positron-sdk@{version}"),
                ),
                Surface::SdkTypeScript => (
                    "https://registry.npmjs.org".into(),
                    format!("pkg:npm/positron-sdk@{version}"),
                ),
                Surface::SdkPython => (
                    "https://pypi.org".into(),
                    format!("positron_sdk-{version}-py3-none-any.whl"),
                ),
                Surface::SdkGo => (
                    "https://proxy.golang.org".into(),
                    format!("pkg:golang/github.com/vicotrbb/positron/sdk/go@{version}"),
                ),
                Surface::SdkDotNet => (
                    "https://api.nuget.org/v3/index.json".into(),
                    format!("pkg:nuget/Positron.SDK@{version}"),
                ),
                Surface::Homebrew => (
                    "https://github.com/vicotrbb/homebrew-positron".into(),
                    "positron.rb".into(),
                ),
                _ => (
                    "https://github.com/vicotrbb/positron".into(),
                    format!("artifact-{index}"),
                ),
            };
            add(
                &mut inventory,
                surface,
                target,
                if surface == Surface::SdkPython {
                    subject.clone()
                } else {
                    format!("artifact-{index}")
                },
                (registry, subject),
                true,
                &identity,
            )?;
        }
    }
    inventory.validate_complete()?;
    let inventory_bytes = inventory.canonical_bytes()?;
    let compatibility_bytes = serde_json::to_vec(&inventory.compatibility)?;
    let entry = |role, platform: String, identity: &FileIdentity| ReleaseArtifact {
        role,
        platform,
        sha256: identity.sha256,
        size: identity.size,
        complete: true,
    };
    let mut artifacts = Vec::new();
    for artifact in &inventory.artifacts {
        if artifact.surface == Surface::NativeExecutable {
            artifacts.push(entry(
                ArtifactRole::NativeExecutable,
                artifact.target.clone(),
                &inventory.file(&artifact.file)?.identity,
            ));
        }
    }
    let api = inventory
        .artifacts
        .iter()
        .find(|row| row.surface == Surface::Api)
        .ok_or("API metadata missing")?;
    let first = inventory.artifacts.first().ok_or("inventory empty")?;
    for (role, identity) in [
        (
            ArtifactRole::Schema,
            inventory.file(&api.file)?.identity.clone(),
        ),
        (
            ArtifactRole::CompatibilityManifest,
            FileIdentity::of(&compatibility_bytes),
        ),
        (
            ArtifactRole::Sbom,
            inventory.file(&first.spdx)?.identity.clone(),
        ),
        (
            ArtifactRole::Provenance,
            inventory.file(&first.provenance)?.identity.clone(),
        ),
        (
            ArtifactRole::ReleaseInventory,
            FileIdentity::of(&inventory_bytes),
        ),
    ] {
        artifacts.push(entry(role, "any".into(), &identity));
    }
    let manifest = ReleaseManifest {
        version: base.version,
        upgrade_from: base.upgrade_from.clone(),
        source_commit: base.source_commit.clone(),
        artifacts,
        compatibility: inventory.compatibility,
    };
    manifest.canonical_bytes()?;
    Ok((manifest, inventory_bytes))
}

fn add(
    inventory: &mut ReleaseInventory,
    surface: Surface,
    target: &str,
    file: String,
    publication: (String, String),
    payload: bool,
    identity: &FileIdentity,
) -> Result<()> {
    let metadata = format!("metadata-{}", inventory.artifacts.len());
    for id in [&file, &metadata] {
        inventory.files.push(InventoryFile {
            id: id.clone(),
            identity: identity.clone(),
        });
    }
    let revision = if surface == Surface::Homebrew {
        Some(
            inventory
                .source_commit
                .get(..40)
                .ok_or("source revision too short")?
                .into(),
        )
    } else {
        None
    };
    inventory.artifacts.push(Artifact {
        file: file.clone(),
        surface,
        target: target.into(),
        payload: payload.then_some(file),
        spdx: metadata.clone(),
        cyclonedx: metadata.clone(),
        provenance: metadata.clone(),
        license_notices: metadata.clone(),
        evidence: metadata.clone(),
        publication: Publication {
            registry: publication.0,
            immutable_identity: format!("sha256:{}", hex(&identity.sha256)),
            native_subject: publication.1,
            native_revision: revision,
            state: PublicationState::Published,
            proof: format!("{metadata}.proof"),
        },
    });
    Ok(())
}

pub fn artifact_paths(
    manifest: &ReleaseManifest,
    executable: &Path,
    directory: &Path,
) -> Result<Vec<PathBuf>> {
    let (reconstructed, inventory) = complete_metadata(manifest)?;
    if reconstructed != *manifest {
        return Err("native Upgrade metadata is not canonical".into());
    }
    std::fs::create_dir_all(directory)?;
    let compatibility_path = directory.join("compatibility.json");
    let inventory_path = directory.join("inventory.json");
    std::fs::write(
        &compatibility_path,
        serde_json::to_vec(&manifest.compatibility)?,
    )?;
    std::fs::write(&inventory_path, inventory)?;
    Ok(manifest
        .artifacts
        .iter()
        .map(|artifact| match artifact.role {
            ArtifactRole::CompatibilityManifest => compatibility_path.clone(),
            ArtifactRole::ReleaseInventory => inventory_path.clone(),
            _ => executable.to_path_buf(),
        })
        .collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
