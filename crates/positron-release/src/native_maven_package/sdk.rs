//! Bounded JVM payload inspection under the existing Maven publication owner.
use crate::{ReleaseError, ReleaseInventory, inventory::hex};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};
const MAX_JAR: usize = 64 << 20;
const MAX_MEMBER: u64 = 16 << 20;
const PREFIX: &str = "dev/positron/";
const GENERATOR: &str =
    "positron-api=1,java=21,maven=3.9.11,jackson=2.19.2,protoc-bin-vendored=3.2.0";
fn jar(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    if bytes.len() > MAX_JAR {
        return Err(ReleaseError::LimitExceeded);
    }
    let count = crate::archive_scan::check_zip_count(bytes, 16_384)?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ReleaseError::Invalid)?;
    if count != archive.len() || archive.offset() != 0 {
        return Err(ReleaseError::Invalid);
    }
    let mut files = BTreeMap::new();
    let mut decoded = 0_usize;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index_raw(index)
            .map_err(|_| ReleaseError::Invalid)?;
        let name = std::str::from_utf8(file.name_raw())
            .map_err(|_| ReleaseError::Invalid)?
            .to_owned();
        // JVM installers and class loaders must see the same local entries as
        // the central-directory identity inspected here. Generated JARs have
        // explicit sizes and no streaming descriptors or encrypted members.
        let local = usize::try_from(file.header_start()).map_err(|_| ReleaseError::Invalid)?;
        let word = |offset| -> Result<u16, ReleaseError> {
            Ok(u16::from_le_bytes(
                bytes
                    .get(local + offset..local + offset + 2)
                    .ok_or(ReleaseError::Invalid)?
                    .try_into()
                    .map_err(|_| ReleaseError::Invalid)?,
            ))
        };
        let number = |offset| -> Result<u32, ReleaseError> {
            Ok(u32::from_le_bytes(
                bytes
                    .get(local + offset..local + offset + 4)
                    .ok_or(ReleaseError::Invalid)?
                    .try_into()
                    .map_err(|_| ReleaseError::Invalid)?,
            ))
        };
        if bytes.get(local..local + 4) != Some(b"PK\x03\x04")
            || word(6)? & !0x800 != 0
            || usize::from(word(26)?) != name.len()
            || bytes.get(local + 30..local + 30 + name.len()) != Some(name.as_bytes())
            || !matches!(
                (word(8)?, file.compression()),
                (0, zip::CompressionMethod::Stored) | (8, zip::CompressionMethod::DEFLATE)
            )
            || number(14)? != file.crc32()
            || u64::from(number(18)?) != file.compressed_size()
            || u64::from(number(22)?) != file.size()
        {
            return Err(ReleaseError::Invalid);
        }
        if file.is_dir() {
            crate::native_crates::portable_path(name.trim_end_matches('/'))?;
            continue;
        }
        crate::native_crates::portable_path(&name.replace('$', "_"))?;
        if file.encrypted()
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(ReleaseError::Unsupported);
        }
        if file.size() > MAX_MEMBER {
            return Err(ReleaseError::LimitExceeded);
        }
        decoded = decoded
            .checked_add(usize::try_from(file.size()).map_err(|_| ReleaseError::LimitExceeded)?)
            .ok_or(ReleaseError::LimitExceeded)?;
        if decoded > 128 << 20 {
            return Err(ReleaseError::LimitExceeded);
        }
        let crc = file.crc32();
        let size = file.size();
        let input: Box<dyn Read> = match file.compression() {
            zip::CompressionMethod::Stored => Box::new(&mut file),
            zip::CompressionMethod::DEFLATE => {
                Box::new(flate2::read::DeflateDecoder::new(&mut file))
            },
            _ => return Err(ReleaseError::Unsupported),
        };
        let mut data = Vec::new();
        input
            .take(MAX_MEMBER + 1)
            .read_to_end(&mut data)
            .map_err(|_| ReleaseError::Invalid)?;
        if data.len() as u64 != size
            || crc32fast::hash(&data) != crc
            || files.insert(name, data).is_some()
        {
            return Err(ReleaseError::Invalid);
        }
    }
    Ok(files)
}
pub(super) fn inspect(
    bytes: &[u8],
    kind: u8,
    inventory: &ReleaseInventory,
    version: &str,
) -> Result<(), ReleaseError> {
    let files = jar(bytes)?;
    let read = |path: &str| {
        files
            .get(path)
            .filter(|value| !value.is_empty())
            .map(Vec::as_slice)
            .ok_or(ReleaseError::IdentityMismatch)
    };
    if kind == 8 {
        read("index.html")?;
        read("dev.positron.sdk/dev/positron/Client.html")?;
        return Ok(());
    }
    let release: Value = serde_json::from_slice(read("dev/positron/release.json")?)
        .map_err(|_| ReleaseError::Invalid)?;
    for (key, expected) in [
        ("group", "dev.positron"),
        ("artifact", "sdk"),
        ("version", version),
        ("source_commit", inventory.source_commit.as_str()),
        ("api_version", inventory.api_version.as_str()),
        (
            "schema_digest",
            hex(&inventory.compatibility.schema).as_str(),
        ),
        ("release_manifest_surface", "SdkJava"),
        ("registry", super::REGISTRY),
        ("generator", GENERATOR),
    ] {
        if release.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    let schema = &inventory.compatibility.schema;
    if <[u8; 32]>::from(Sha256::digest(read("dev/positron/api/positron.proto")?)) != *schema
        || read("dev/positron/api/schema.sha256")? != format!("{}\n", hex(schema)).as_bytes()
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let contract: Value = serde_json::from_slice(read("dev/positron/contract.json")?)
        .map_err(|_| ReleaseError::Invalid)?;
    if contract["api_version"] != inventory.api_version || contract["schema_digest"] != hex(schema)
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    if read("dev/positron/dependencies.json")?
        != include_bytes!("../../../positron-api/java/dependencies.json")
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    read("dev/positron/LICENSE")?;
    for class in [
        "Client",
        "Codec",
        "Query",
        "BatchTracker",
        "PositronException",
        "Types",
    ] {
        let bytes = read(&format!(
            "{PREFIX}{class}.{}",
            if kind == 2 { "class" } else { "java" }
        ))?;
        if kind == 2 && !bytes.starts_with(b"\xca\xfe\xba\xbe\0\0\0\x41") {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if kind == 2 {
        let manifest = std::str::from_utf8(read("META-INF/MANIFEST.MF")?)
            .map_err(|_| ReleaseError::Invalid)?;
        let mut entries = manifest
            .lines()
            .filter(|line| line.starts_with("Automatic-Module-Name:"));
        if entries.next() != Some("Automatic-Module-Name: dev.positron.sdk")
            || entries.next().is_some()
        {
            return Err(ReleaseError::IdentityMismatch);
        }
        super::pom(read("META-INF/maven/dev.positron/sdk/pom.xml")?, version)?;
    }
    Ok(())
}

pub(super) fn dependencies(
    files: &crate::files::Bundle,
    artifact: &crate::Artifact,
) -> Result<(), ReleaseError> {
    let expected: Value = serde_json::from_slice(include_bytes!(
        "../../../positron-api/java/dependencies.json"
    ))
    .map_err(|_| ReleaseError::Invalid)?;
    let spdx: Value = serde_json::from_slice(&files.read(&artifact.spdx, 1 << 20)?)
        .map_err(|_| ReleaseError::Invalid)?;
    let cdx: Value = serde_json::from_slice(&files.read(&artifact.cyclonedx, 1 << 20)?)
        .map_err(|_| ReleaseError::Invalid)?;
    for dependency in expected.as_array().ok_or(ReleaseError::Invalid)? {
        let packages = spdx["packages"]
            .as_array()
            .ok_or(ReleaseError::IdentityMismatch)?;
        let components = cdx["components"]
            .as_array()
            .ok_or(ReleaseError::IdentityMismatch)?;
        if !packages.iter().any(|p| {
            p["name"] == dependency["name"]
                && p["versionInfo"] == dependency["version"]
                && p["licenseConcluded"] == dependency["license"]
                && p["checksums"].as_array().is_some_and(|hashes| {
                    hashes.iter().any(|h| {
                        h["algorithm"] == "SHA256" && h["checksumValue"] == dependency["sha256"]
                    })
                })
        }) || !components.iter().any(|p| {
            p["group"] == dependency["group"]
                && p["name"] == dependency["name"]
                && p["version"] == dependency["version"]
                && p["hashes"].as_array().is_some_and(|hashes| {
                    hashes
                        .iter()
                        .any(|h| h["alg"] == "SHA-256" && h["content"] == dependency["sha256"])
                })
        }) {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    Ok(())
}
