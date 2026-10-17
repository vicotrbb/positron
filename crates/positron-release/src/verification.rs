use crate::{files::Bundle, inventory::hex, *};
use positron_kernel::release_manifest::{
    ArtifactRole, ReleaseSigningPublicKey, SignedReleaseManifest, VerifiedReleaseManifest,
};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct ReleaseVerificationReport {
    manifest: VerifiedReleaseManifest,
    artifact_count: usize,
    trust_sequence: u64,
    verified_at_unix_seconds: u64,
}
impl ReleaseVerificationReport {
    pub fn manifest(&self) -> &VerifiedReleaseManifest {
        &self.manifest
    }
    pub fn artifact_count(&self) -> usize {
        self.artifact_count
    }
    pub fn trust_sequence(&self) -> u64 {
        self.trust_sequence
    }
    pub fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }
}
/// The same kernel authentication used by native Upgrade, with current offline authorization and revocation.
pub fn verify_manifest(
    bytes: &[u8],
    signer: [u8; 32],
    trust: &VerifiedTrust,
) -> Result<VerifiedReleaseManifest, ReleaseError> {
    trust.authorize(&signer, KeyPurpose::Release)?;
    let manifest = SignedReleaseManifest::from_bytes(bytes)
        .and_then(|signed| signed.verify_signature(&ReleaseSigningPublicKey::new(signer)))
        .map_err(|_| ReleaseError::Authentication)?;
    check_manifest_revocations(&manifest, trust)?;
    Ok(manifest)
}
/// Authenticate a historical source under current root-authorized verification
/// identities. A source-only identity cannot authorize target acceptance.
pub fn verify_installed_source_manifest(
    bytes: &[u8],
    trust: &VerifiedTrust,
) -> Result<VerifiedReleaseManifest, ReleaseError> {
    let signed =
        SignedReleaseManifest::from_bytes(bytes).map_err(|_| ReleaseError::Authentication)?;
    let mut authenticated = None;
    for key in trust.installed_source_keys() {
        if let Ok(manifest) = signed.verify_signature(&ReleaseSigningPublicKey::new(key)) {
            if authenticated.is_some() {
                return Err(ReleaseError::Authentication);
            }
            authenticated = Some(manifest);
        }
    }
    let manifest = authenticated.ok_or(ReleaseError::Authentication)?;
    check_manifest_revocations(&manifest, trust)?;
    Ok(manifest)
}
fn check_manifest_revocations(
    manifest: &VerifiedReleaseManifest,
    trust: &VerifiedTrust,
) -> Result<(), ReleaseError> {
    trust.check_manifest(&manifest.digest())?;
    for artifact in &manifest.manifest().artifacts {
        trust.check_artifact(&artifact.sha256)?;
    }
    Ok(())
}
/// Authenticated, complete published target metadata. Construction is restricted
/// to the owning validator; an older signed source manifest is not a target.
#[derive(Clone, Debug)]
pub struct VerifiedReleaseTarget {
    manifest: VerifiedReleaseManifest,
    inventory_bytes: Vec<u8>,
    signer: [u8; 32],
    trust: VerifiedTrust,
}
impl VerifiedReleaseTarget {
    pub fn verified_manifest(&self) -> &VerifiedReleaseManifest {
        &self.manifest
    }
    pub fn manifest(&self) -> &positron_kernel::release_manifest::ReleaseManifest {
        self.manifest.manifest()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.manifest.digest()
    }
    /// Recheck this explicitly supplied authority at the caller's owning clock.
    /// Native admission separately reloads current independently installed trust.
    pub fn revalidate_at(&self, now: u64) -> Result<(), ReleaseError> {
        let trust = self.trust.at_time(now)?;
        verify_target_metadata(
            self.manifest.signed_bytes(),
            &self.inventory_bytes,
            self.signer,
            &trust,
        )
        .map(|_| ())
    }
}
pub fn verify_target_metadata(
    bytes: &[u8],
    inventory_bytes: &[u8],
    signer: [u8; 32],
    trust: &VerifiedTrust,
) -> Result<VerifiedReleaseTarget, ReleaseError> {
    let manifest = verify_manifest(bytes, signer, trust)?;
    trust.require_supported_version(manifest.manifest().version)?;
    let inventory = verify_manifest_inventory(&manifest, inventory_bytes, trust)?;
    if inventory
        .artifacts
        .iter()
        .any(|artifact| artifact.publication.state != PublicationState::Published)
    {
        return Err(ReleaseError::PartialSet);
    }
    if inventory.security_support.expires_unix <= trust.now()
        || inventory.security_support.upgrade_paths.is_empty()
        || inventory.security_support.upgrade_paths.contains(&[0; 32])
    {
        return Err(ReleaseError::Unsupported);
    }
    Ok(VerifiedReleaseTarget {
        manifest,
        inventory_bytes: inventory_bytes.to_vec(),
        signer,
        trust: trust.clone(),
    })
}
/// Offline only. Bundled files and detached publication bundles are read from explicit local roots.
#[allow(clippy::too_many_arguments)]
pub fn verify_release(
    bytes: &[u8],
    inventory_bytes: &[u8],
    signer: [u8; 32],
    trust: &VerifiedTrust,
    bundle: &Path,
    rebuild: &Path,
    target: &str,
    canaries: &[Vec<u8>],
) -> Result<ReleaseVerificationReport, ReleaseError> {
    let verified = verify_manifest(bytes, signer, trust)?;
    trust.require_supported_version(verified.manifest().version)?;
    let inventory = verify_manifest_inventory(&verified, inventory_bytes, trust)?;
    if !required_release_one().contains(&(Surface::NativeExecutable, target)) {
        return Err(ReleaseError::Unsupported);
    }
    let prepared = construct_release(
        &inventory,
        bundle,
        rebuild,
        canaries,
        verified.manifest().upgrade_from.clone(),
    )?;
    if prepared.manifest != *verified.manifest() {
        return Err(ReleaseError::IdentityMismatch);
    }
    let support = &inventory.security_support;
    if support.expires_unix <= trust.now()
        || support.upgrade_paths.is_empty()
        || support.upgrade_paths.contains(&[0; 32])
    {
        return Err(ReleaseError::Unsupported);
    }
    let bundle = Bundle::open(bundle)?;
    crate::native_maven_package::verify_set(&inventory, &bundle)?;
    for file in &inventory.files {
        trust.check_artifact(&file.identity.sha256)?;
    }
    for artifact in &inventory.artifacts {
        if artifact.publication.state != PublicationState::Published {
            return Err(ReleaseError::PartialSet);
        }
        crate::publication::verify_publication(
            &bundle.read(&artifact.publication.proof, 1_048_576)?,
            artifact,
            &hex(&inventory.file(&artifact.file)?.identity.sha256),
            &verified.digest(),
            trust,
            &bundle,
            &inventory,
        )?;
    }
    Ok(ReleaseVerificationReport {
        manifest: verified,
        artifact_count: inventory.artifacts.len(),
        trust_sequence: trust.sequence(),
        verified_at_unix_seconds: trust.now(),
    })
}

/// Authenticate the inventory reference and all declared identities for installed native preflight.
/// This does not measure artifact files or establish full publication completeness.
pub fn verify_manifest_inventory(
    verified: &VerifiedReleaseManifest,
    bytes: &[u8],
    trust: &VerifiedTrust,
) -> Result<ReleaseInventory, ReleaseError> {
    let identity = FileIdentity::of(bytes);
    let entries: Vec<_> = verified
        .manifest()
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == ArtifactRole::ReleaseInventory)
        .collect();
    if entries.len() != 1
        || entries.first().is_none_or(|artifact| {
            artifact.platform != "any"
                || artifact.sha256 != identity.sha256
                || artifact.size != identity.size
        })
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let inventory = ReleaseInventory::from_bytes(bytes)?;
    let api = inventory
        .artifacts
        .iter()
        .find(|artifact| artifact.surface == Surface::Api)
        .ok_or(ReleaseError::PartialSet)?;
    if inventory.file(&api.file)?.identity.sha256 != inventory.compatibility.schema {
        return Err(ReleaseError::IdentityMismatch);
    }
    if inventory.canonical_bytes()? != bytes {
        return Err(ReleaseError::Invalid);
    }
    let prepared = crate::construction::prepare_manifest(
        &inventory,
        verified.manifest().upgrade_from.clone(),
    )?;
    if prepared.manifest != *verified.manifest() {
        return Err(ReleaseError::IdentityMismatch);
    }
    for file in &inventory.files {
        trust.check_artifact(&file.identity.sha256)?;
    }
    Ok(inventory)
}
