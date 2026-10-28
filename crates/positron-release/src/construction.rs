use crate::{files::Bundle, *};
use positron_kernel::release_manifest::{
    ArtifactRole, ProductVersion, ReleaseArtifact, ReleaseManifest,
};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Prepared signing inputs only. This type makes no authentication or publication claim.
#[derive(Clone, Debug)]
pub struct ReleaseConstruction {
    pub manifest: ReleaseManifest,
    pub inventory_bytes: Vec<u8>,
    pub compatibility_bytes: Vec<u8>,
}
impl ReleaseConstruction {
    pub fn signing_message(&self) -> Result<Vec<u8>, ReleaseError> {
        self.manifest
            .signing_message()
            .map_err(|_| ReleaseError::Invalid)
    }
}
/// Validate every declared input and independently rebuilt functional payload before signing.
pub fn construct_release(
    inventory: &ReleaseInventory,
    bundle: &Path,
    rebuild: &Path,
    canaries: &[Vec<u8>],
    upgrade_from: Vec<ProductVersion>,
) -> Result<ReleaseConstruction, ReleaseError> {
    inventory.validate_complete()?;
    verify_payloads(
        inventory,
        &Bundle::open(bundle)?,
        &Bundle::open(rebuild)?,
        canaries,
    )?;
    prepare_manifest(inventory, upgrade_from)
}
pub(crate) fn prepare_manifest(
    inventory: &ReleaseInventory,
    upgrade_from: Vec<ProductVersion>,
) -> Result<ReleaseConstruction, ReleaseError> {
    inventory.validate_complete()?;
    let inventory_bytes = inventory.canonical_bytes()?;
    let compatibility_bytes =
        serde_json::to_vec(&inventory.compatibility).map_err(|_| ReleaseError::Invalid)?;
    let mut artifacts = Vec::new();
    let entry = |role, platform: String, identity: &FileIdentity| ReleaseArtifact {
        role,
        platform,
        sha256: identity.sha256,
        size: identity.size,
        complete: true,
    };
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
        .find(|artifact| artifact.surface == Surface::Api)
        .ok_or(ReleaseError::PartialSet)?;
    let first = inventory
        .artifacts
        .first()
        .ok_or(ReleaseError::PartialSet)?;
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
        version: inventory.version,
        upgrade_from,
        source_commit: inventory.source_commit.clone(),
        artifacts,
        compatibility: inventory.compatibility.clone(),
    };
    manifest
        .canonical_bytes()
        .map_err(|_| ReleaseError::Invalid)?;
    Ok(ReleaseConstruction {
        manifest,
        inventory_bytes,
        compatibility_bytes,
    })
}
pub(crate) fn verify_payloads(
    inventory: &ReleaseInventory,
    bundle: &Bundle,
    rebuild: &Bundle,
    canaries: &[Vec<u8>],
) -> Result<(), ReleaseError> {
    let mut total = 0_u64;
    for file in &inventory.files {
        total = total
            .checked_add(file.identity.size)
            .filter(|total| *total <= 1_099_511_627_776)
            .ok_or(ReleaseError::LimitExceeded)?;
        if bundle.inspect(&file.id, canaries)? != file.identity {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    for artifact in &inventory.artifacts {
        if let Some(payload) = &artifact.payload {
            if bundle.same_file(rebuild, payload)? {
                return Err(ReleaseError::Unreproducible);
            }
            let declared = &inventory.file(payload)?.identity;
            let expected = match artifact.surface {
                Surface::OciImage => None,
                Surface::Rpm => Some(FileIdentity::of(crate::rpm_functional_payload(
                    &bundle.read(&artifact.file, 64 << 20)?,
                )?)),
                Surface::SdkDotNet if &inventory.file(&artifact.file)?.identity != declared => {
                    Some(FileIdentity::of(
                        &crate::nuget_zip::package(&bundle.read(&artifact.file, 64 << 20)?)?
                            .unsigned,
                    ))
                },
                _ => Some(inventory.file(&artifact.file)?.identity.clone()),
            };
            if expected
                .as_ref()
                .is_some_and(|expected| expected != declared)
            {
                return Err(ReleaseError::Unreproducible);
            }
            if rebuild.inspect(payload, canaries)? != inventory.file(payload)?.identity {
                return Err(ReleaseError::Unreproducible);
            }
        }
    }
    let api = inventory
        .artifacts
        .iter()
        .find(|artifact| artifact.surface == Surface::Api)
        .ok_or(ReleaseError::PartialSet)?;
    if inventory.file(&api.file)?.identity.sha256 != inventory.compatibility.schema {
        return Err(ReleaseError::IdentityMismatch);
    }
    for artifact in &inventory.artifacts {
        if artifact.surface == Surface::Homebrew
            && bundle.read(&artifact.file, 65_536)?
                != crate::homebrew_formula(inventory)?.as_bytes()
        {
            return Err(ReleaseError::IdentityMismatch);
        }
        if artifact.surface == Surface::Compose
            && bundle.read(&artifact.file, 65_536)?
                != crate::compose_deployment(inventory)?.as_bytes()
        {
            return Err(ReleaseError::IdentityMismatch);
        }
        crate::archive_scan::scan_bundle_contents(bundle, &artifact.file, canaries)?;
        if let Some(payload) = &artifact.payload {
            crate::archive_scan::scan_bundle_contents(bundle, payload, canaries)?;
        }
    }
    crate::oci::verify_oci(inventory, bundle)?;
    crate::metadata::verify_metadata(inventory, bundle)?;
    Ok(())
}
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
