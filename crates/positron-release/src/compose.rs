//! Compose consumes the canonical OCI index, never a mutable image tag.
use crate::{ReleaseError, ReleaseInventory, Surface, inventory::hex};

/// Generate unsigned deployment bytes before measuring them in the inventory.
/// Only complete Release Trust verification authenticates the resulting artifact.
pub fn compose_deployment(inventory: &ReleaseInventory) -> Result<String, ReleaseError> {
    inventory.canonical_bytes()?;
    let mut indexes = inventory
        .artifacts
        .iter()
        .filter(|artifact| artifact.surface == Surface::OciIndex);
    let index = indexes.next().ok_or(ReleaseError::PartialSet)?;
    if indexes.next().is_some() {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(include_str!("../../../deploy/compose/compose.yaml.in")
        .replace("@SOURCE@", &inventory.source_commit)
        .replace(
            "@INDEX_SHA256@",
            &hex(&inventory.file(&index.file)?.identity.sha256),
        ))
}
