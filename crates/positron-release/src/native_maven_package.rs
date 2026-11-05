//! Required Maven Central publication members under the signed inventory.
use crate::{files::Bundle, *};
use std::collections::BTreeMap;
mod sdk;
const REGISTRY: &str = "https://repo.maven.apache.org/maven2";

pub(crate) fn verify_metadata(inventory: &ReleaseInventory) -> Result<(), ReleaseError> {
    verify(inventory, None)
}
pub(crate) fn verify_set(inventory: &ReleaseInventory, files: &Bundle) -> Result<(), ReleaseError> {
    verify(inventory, Some(files))
}
fn verify(inventory: &ReleaseInventory, files: Option<&Bundle>) -> Result<(), ReleaseError> {
    let version = format!(
        "{}.{}.{}",
        inventory.version.major, inventory.version.minor, inventory.version.patch
    );
    let members: Vec<_> = inventory
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.surface == Surface::SdkJava && artifact.publication.registry == REGISTRY
        })
        .collect();
    if members.is_empty() {
        return Ok(());
    }
    if members.len() < 4 {
        return Err(ReleaseError::PartialSet);
    }
    let mut packages: BTreeMap<(String, String), u8> = BTreeMap::new();
    for artifact in members {
        let value = artifact
            .publication
            .native_subject
            .strip_prefix("pkg:maven/")
            .ok_or(ReleaseError::IdentityMismatch)?;
        let (gav, qualifiers) = value
            .split_once('?')
            .ok_or(ReleaseError::IdentityMismatch)?;
        let identity = gav
            .strip_suffix(&format!("@{version}"))
            .ok_or(ReleaseError::IdentityMismatch)?;
        let (group, name) = identity
            .split_once('/')
            .ok_or(ReleaseError::IdentityMismatch)?;
        if group != "dev.positron" || name != "sdk" {
            return Err(ReleaseError::IdentityMismatch);
        }
        let (bit, suffix) = match qualifiers {
            "type=pom" => (1, ".pom"),
            "type=jar" => (2, ".jar"),
            "classifier=sources&type=jar" => (4, "-sources.jar"),
            "classifier=javadoc&type=jar" => (8, "-javadoc.jar"),
            _ => return Err(ReleaseError::Unsupported),
        };
        let mask = packages.entry((group.into(), name.into())).or_default();
        if *mask & bit != 0 {
            return Err(ReleaseError::PartialSet);
        }
        *mask |= bit;
        if artifact.file != format!("{name}-{version}{suffix}") {
            return Err(ReleaseError::IdentityMismatch);
        }
        if bit != 1 && artifact.payload.is_none() {
            return Err(ReleaseError::Unreproducible);
        }
        if let Some(files) = files {
            let bytes = files.read(&artifact.file, 64 << 20)?;
            sdk::dependencies(files, artifact)?;
            if bit == 1 {
                pom(&bytes, &version)?;
            } else {
                sdk::inspect(&bytes, bit, inventory, &version)?;
            }
        }
    }
    if packages.values().any(|mask| *mask != 15) {
        return Err(ReleaseError::PartialSet);
    }
    Ok(())
}

fn pom(bytes: &[u8], version: &str) -> Result<(), ReleaseError> {
    // One generated POM owns coordinates, module/compiler inputs, runtime
    // dependency versions, license and packaging plugins. Do not authorize
    // extra build or runtime dependencies through a second metadata shape.
    let expected = include_str!("../../positron-api/java/pom.xml").replace("@VERSION@", version);
    if bytes != expected.as_bytes() {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(())
}
