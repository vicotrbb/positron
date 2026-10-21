//! Homebrew is a relocation of native archives, using the existing release authority.
use crate::{ReleaseError, ReleaseInventory, Surface};

/// Construct unsigned formula bytes from the canonical inventory. This does not
/// authenticate downloads, publish a tap, or install trust. Regenerate after any
/// native archive identity changes, before measuring the formula in the inventory.
pub fn homebrew_formula(inventory: &ReleaseInventory) -> Result<String, ReleaseError> {
    // Apply the same bounded names and identity validation as every release input.
    inventory.canonical_bytes()?;
    let version = inventory.version;
    let mut formula = include_str!("../../../deploy/homebrew/positron.rb.in")
        .replace("@SOURCE@", &inventory.source_commit)
        .replace(
            "@VERSION@",
            &format!("{}.{}.{}", version.major, version.minor, version.patch),
        );
    for (target, prefix) in [("macos-aarch64", "ARM"), ("macos-x86_64", "INTEL")] {
        let mut artifacts = inventory.artifacts.iter().filter(|artifact| {
            artifact.surface == Surface::NativeArchive && artifact.target == target
        });
        let artifact = artifacts.next().ok_or(ReleaseError::PartialSet)?;
        if artifacts.next().is_some() {
            return Err(ReleaseError::IdentityMismatch);
        }
        let identity = &inventory.file(&artifact.file)?.identity;
        let digest: String = identity
            .sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        formula = formula
            .replace(&format!("@{prefix}_FILE@"), &artifact.file)
            .replace(&format!("@{prefix}_SHA256@"), &digest);
    }
    Ok(formula)
}
