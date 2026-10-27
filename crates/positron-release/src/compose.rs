//! Compose consumes the canonical OCI index, never a mutable image tag.
use crate::{ReleaseError, ReleaseInventory, Surface, inventory::hex};

/// Generate unsigned deployment bytes before measuring them in the inventory.
/// Only complete Release Trust verification authenticates the resulting artifact.
pub fn compose_deployment(inventory: &ReleaseInventory) -> Result<String, ReleaseError> {
    inventory.canonical_bytes()?;
    // One release artifact covers every accepted native Drain deadline. A
    // changed/unbounded canonical domain must fail closed rather than guess.
    let definition = positron_config::setting_definitions()
        .into_iter()
        .find(|setting| setting.setting() == positron_config::Setting::RuntimeShutdownGraceSeconds)
        .ok_or(ReleaseError::Unsupported)?;
    let positron_config::ValueDomain::UnsignedIntegerRange(_, maximum) = definition.domain() else {
        return Err(ReleaseError::Unsupported);
    };
    let stop_grace = maximum.checked_add(5).ok_or(ReleaseError::LimitExceeded)?;

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
        .replace("@STOP_GRACE_SECONDS@", &stop_grace.to_string())
        .replace(
            "@INDEX_SHA256@",
            &hex(&inventory.file(&index.file)?.identity.sha256),
        ))
}
