//! Required Maven Central publication members under the signed inventory.
use crate::{files::Bundle, *};
use std::collections::BTreeMap;
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
        if group.is_empty()
            || name.is_empty()
            || !group
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
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
        if bit == 1
            && let Some(files) = files
        {
            let bytes = files.read(&artifact.file, 1 << 20)?;
            let document = crate::native_xml::document(&bytes)?;
            let root = document.root_element();
            if root.tag_name().name() != "project"
                || root.tag_name().namespace() != Some("http://maven.apache.org/POM/4.0.0")
            {
                return Err(ReleaseError::Unsupported);
            }
            for (field, expected) in [
                ("modelVersion", "4.0.0"),
                ("groupId", group),
                ("artifactId", name),
                ("version", version.as_str()),
            ] {
                if crate::native_xml::text(crate::native_xml::child(root, field)?)? != expected {
                    return Err(ReleaseError::IdentityMismatch);
                }
            }
        } else if bit != 1 && artifact.payload.is_none() {
            return Err(ReleaseError::Unreproducible);
        }
    }
    if packages.values().any(|mask| *mask != 15) {
        return Err(ReleaseError::PartialSet);
    }
    Ok(())
}
