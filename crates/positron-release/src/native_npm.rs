//! Inspect actual npm SDK bytes under the existing Release Trust authority.
use crate::{ReleaseError, construction::sha256, inventory::hex};
use serde_json::Value;
use std::{collections::BTreeSet, io::Read};

pub(crate) const MAX_INPUT: usize = 64 << 20;
const MAX_DECODED: u64 = 128 << 20;

pub(crate) fn inspect_sdk(
    contents: &[u8],
    version: &str,
    source_commit: &str,
    api: &str,
    schema: &[u8; 32],
) -> Result<(), ReleaseError> {
    if contents.len() > MAX_INPUT {
        return Err(ReleaseError::LimitExceeded);
    }
    let mut decoded = flate2::bufread::GzDecoder::new(contents).take(MAX_DECODED + 1);
    let mut archive = tar::Archive::new(&mut decoded);
    let mut paths = BTreeSet::new();
    let mut manifest = false;
    let mut definition = false;
    let mut digest = false;
    let mut entrypoint = false;
    let mut declarations = false;
    for (index, entry) in archive
        .entries()
        .map_err(|_| ReleaseError::Invalid)?
        .raw(true)
        .enumerate()
    {
        if index >= 16_384 {
            return Err(ReleaseError::LimitExceeded);
        }
        let mut entry = entry.map_err(|_| ReleaseError::Invalid)?;
        if !entry.header().entry_type().is_file() {
            return Err(ReleaseError::Unsupported);
        }
        if entry.size() > 16 << 20 {
            return Err(ReleaseError::LimitExceeded);
        }
        let raw = entry.path_bytes();
        let path = std::str::from_utf8(&raw).map_err(|_| ReleaseError::Invalid)?;
        let path = path
            .strip_prefix("package/")
            .ok_or(ReleaseError::IdentityMismatch)?
            .to_owned();
        let path = path.as_str();
        crate::native_crates::portable_path(path)?;
        let folded = path.to_ascii_lowercase();
        let mut parent = folded.as_str();
        while let Some((directory, _)) = parent.rsplit_once('/') {
            if paths.contains(directory) {
                return Err(ReleaseError::Invalid);
            }
            parent = directory;
        }
        if paths
            .range(format!("{folded}/")..)
            .next()
            .is_some_and(|child: &String| child.starts_with(&format!("{folded}/")))
            || !paths.insert(folded)
        {
            return Err(ReleaseError::Invalid);
        }
        match path {
            "package.json" | "api/positron.proto" | "api/schema.sha256" => {
                if entry.size() > 1 << 20 {
                    return Err(ReleaseError::LimitExceeded);
                }
                let mut bytes = Vec::new();
                entry
                    .read_to_end(&mut bytes)
                    .map_err(|_| ReleaseError::Invalid)?;
                if bytes.len() as u64 != entry.size() {
                    return Err(ReleaseError::Invalid);
                }
                match path {
                    "package.json" => {
                        verify_manifest(&bytes, version, source_commit, api, schema)?;
                        manifest = true;
                    },
                    "api/positron.proto" => {
                        if sha256(&bytes) != *schema {
                            return Err(ReleaseError::IdentityMismatch);
                        }
                        definition = true;
                    },
                    _ => {
                        if bytes != format!("{}\n", hex(schema)).as_bytes() {
                            return Err(ReleaseError::IdentityMismatch);
                        }
                        digest = true;
                    },
                }
            },
            _ => {
                if path == "dist/index.js" {
                    entrypoint = entry.size() > 0;
                }
                if path == "dist/index.d.ts" {
                    declarations = entry.size() > 0;
                }
                if std::io::copy(&mut entry, &mut std::io::sink())
                    .map_err(|_| ReleaseError::Invalid)?
                    != entry.size()
                {
                    return Err(ReleaseError::Invalid);
                }
            },
        }
    }
    drop(archive);
    // Require aligned tar termination, gzip integrity, and exactly one gzip member.
    let mut padding = Vec::new();
    decoded
        .read_to_end(&mut padding)
        .map_err(|_| ReleaseError::Invalid)?;
    if decoded.limit() == 0 {
        return Err(ReleaseError::LimitExceeded);
    }
    if padding.len() < 512
        || !padding.len().is_multiple_of(512)
        || padding.iter().any(|byte| *byte != 0)
        || !decoded.into_inner().into_inner().is_empty()
    {
        return Err(ReleaseError::Invalid);
    }
    if !manifest || !definition || !digest || !entrypoint || !declarations {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(())
}
fn verify_manifest(
    bytes: &[u8],
    version: &str,
    source_commit: &str,
    api: &str,
    schema: &[u8; 32],
) -> Result<(), ReleaseError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ReleaseError::Invalid)?;
    for (pointer, expected) in [
        ("/name", "@positron/sdk"),
        ("/version", version),
        ("/gitHead", source_commit),
        ("/type", "module"),
        ("/exports/./import", "./dist/index.js"),
        ("/exports/./types", "./dist/index.d.ts"),
        ("/positron/api_version", api),
        ("/positron/schema_digest", hex(schema).as_str()),
        ("/positron/release_manifest_surface", "SdkTypeScript"),
        ("/positron/registry", "https://registry.npmjs.org"),
        ("/publishConfig/registry", "https://registry.npmjs.org"),
        (
            "/positron/generator",
            "positron-api=1,typescript=5.9.3,protoc-bin-vendored=3.2.0",
        ),
    ] {
        if value.pointer(pointer).and_then(Value::as_str) != Some(expected) {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if value
        .get("scripts")
        .and_then(Value::as_object)
        .is_some_and(|scripts| scripts.keys().any(|name| name != "build"))
        || value
            .get("dependencies")
            .and_then(Value::as_object)
            .is_some_and(|dependencies| !dependencies.is_empty())
    {
        return Err(ReleaseError::Unsupported);
    }
    Ok(())
}
