//! OCI content descriptors bind independently rebuilt filesystem bytes to actual image identities.
use crate::{files::Bundle, inventory::hex, *};
use serde_json::Value;
pub(crate) fn verify_oci(
    inventory: &ReleaseInventory,
    bundle: &Bundle,
) -> Result<(), ReleaseError> {
    for artifact in &inventory.artifacts {
        if !matches!(artifact.surface, Surface::OciImage | Surface::OciIndex) {
            continue;
        }
        let document: Value = serde_json::from_slice(&bundle.read(&artifact.file, 1_048_576)?)
            .map_err(|_| ReleaseError::Invalid)?;
        if document.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
            return Err(ReleaseError::Invalid);
        }
        if artifact.surface == Surface::OciImage {
            if document.get("mediaType").and_then(Value::as_str)
                != Some("application/vnd.oci.image.manifest.v1+json")
            {
                return Err(ReleaseError::Unsupported);
            }
            let payload = inventory.file(
                artifact
                    .payload
                    .as_ref()
                    .ok_or(ReleaseError::Unreproducible)?,
            )?;
            let layers = document
                .get("layers")
                .and_then(Value::as_array)
                .ok_or(ReleaseError::Invalid)?;
            if layers.len() != 1 {
                return Err(ReleaseError::Unsupported);
            }
            let layer = layers.first().ok_or(ReleaseError::Invalid)?;
            if layer.get("mediaType").and_then(Value::as_str)
                != Some("application/vnd.oci.image.layer.v1.tar")
                || !descriptor(layer, &payload.identity)
            {
                return Err(ReleaseError::Unreproducible);
            }
            let config = document.get("config").ok_or(ReleaseError::Invalid)?;
            let config = inventory
                .files
                .iter()
                .find(|file| descriptor(config, &file.identity))
                .ok_or(ReleaseError::IdentityMismatch)?;
            let config: Value = serde_json::from_slice(&bundle.read(&config.id, 1_048_576)?)
                .map_err(|_| ReleaseError::Invalid)?;
            let architecture = if artifact.target == "linux-x86_64" {
                "amd64"
            } else {
                "arm64"
            };
            if config.get("architecture").and_then(Value::as_str) != Some(architecture)
                || config.get("os").and_then(Value::as_str) != Some("linux")
                || config.pointer("/rootfs/type").and_then(Value::as_str) != Some("layers")
                || config
                    .pointer("/rootfs/diff_ids")
                    .and_then(Value::as_array)
                    .is_none_or(|ids| {
                        ids.len() != 1
                            || ids.first().and_then(Value::as_str)
                                != Some(
                                    format!("sha256:{}", hex(&payload.identity.sha256)).as_str(),
                                )
                    })
            {
                return Err(ReleaseError::IdentityMismatch);
            }
        } else {
            if document.get("mediaType").and_then(Value::as_str)
                != Some("application/vnd.oci.image.index.v1+json")
            {
                return Err(ReleaseError::Unsupported);
            }
            let manifests = document
                .get("manifests")
                .and_then(Value::as_array)
                .ok_or(ReleaseError::Invalid)?;
            if manifests.len() != 2 {
                return Err(ReleaseError::PartialSet);
            }
            for image in inventory
                .artifacts
                .iter()
                .filter(|artifact| artifact.surface == Surface::OciImage)
            {
                let architecture = if image.target == "linux-x86_64" {
                    "amd64"
                } else {
                    "arm64"
                };
                let identity = &inventory.file(&image.file)?.identity;
                if !manifests.iter().any(|manifest| {
                    descriptor(manifest, identity)
                        && manifest.pointer("/platform/os").and_then(Value::as_str) == Some("linux")
                        && manifest
                            .pointer("/platform/architecture")
                            .and_then(Value::as_str)
                            == Some(architecture)
                }) {
                    return Err(ReleaseError::IdentityMismatch);
                }
            }
        }
    }
    Ok(())
}
fn descriptor(value: &Value, identity: &FileIdentity) -> bool {
    value.get("digest").and_then(Value::as_str)
        == Some(format!("sha256:{}", hex(&identity.sha256)).as_str())
        && value.get("size").and_then(Value::as_u64) == Some(identity.size)
}
