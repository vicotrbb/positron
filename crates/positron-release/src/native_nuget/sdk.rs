//! Generated .NET package identity under the native NuGet owner.
use crate::{ReleaseError, ReleaseInventory, inventory::hex};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};
const GENERATOR: &str = "positron-api=1,dotnet=8.0.427,protoc-bin-vendored=3.2.0";
fn members(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    if bytes.len() > 64 << 20 {
        return Err(ReleaseError::LimitExceeded);
    }
    let count = crate::archive_scan::check_zip_count(bytes, 16_384)?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ReleaseError::Invalid)?;
    if archive.len() != count || archive.offset() != 0 {
        return Err(ReleaseError::Invalid);
    }
    let mut result = BTreeMap::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index_raw(index)
            .map_err(|_| ReleaseError::Invalid)?;
        let name = std::str::from_utf8(file.name_raw())
            .map_err(|_| ReleaseError::Invalid)?
            .to_owned();
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
            || number(14)? != file.crc32()
            || u64::from(number(18)?) != file.compressed_size()
            || u64::from(number(22)?) != file.size()
        {
            return Err(ReleaseError::Invalid);
        }
        if name != "[Content_Types].xml" {
            crate::native_crates::portable_path(&name)?;
        }
        if file.encrypted()
            || file.size() > 16 << 20
            || file.unix_mode().is_some_and(|v| v & 0o170000 == 0o120000)
        {
            return Err(ReleaseError::Invalid);
        }
        let expected = file.size();
        total = total
            .checked_add(expected)
            .filter(|v| *v <= 64 << 20)
            .ok_or(ReleaseError::LimitExceeded)?;
        let crc = file.crc32();
        let input: Box<dyn Read> = match file.compression() {
            zip::CompressionMethod::Stored => Box::new(&mut file),
            zip::CompressionMethod::DEFLATE => {
                Box::new(flate2::read::DeflateDecoder::new(&mut file))
            },
            _ => return Err(ReleaseError::Unsupported),
        };
        let mut content = Vec::new();
        input
            .take((16 << 20) + 1)
            .read_to_end(&mut content)
            .map_err(|_| ReleaseError::Invalid)?;
        if content.len() as u64 != expected
            || crc32fast::hash(&content) != crc
            || result.insert(name.to_ascii_lowercase(), content).is_some()
        {
            return Err(ReleaseError::Invalid);
        }
    }
    Ok(result)
}
pub(crate) fn inspect(bytes: &[u8], inventory: &ReleaseInventory) -> Result<(), ReleaseError> {
    let files = members(bytes)?;
    let get = |name: &str| files.get(name).ok_or(ReleaseError::IdentityMismatch);
    let version = format!(
        "{}.{}.{}",
        inventory.version.major, inventory.version.minor, inventory.version.patch
    );
    let release: Value =
        serde_json::from_slice(get("positron/release.json")?).map_err(|_| ReleaseError::Invalid)?;
    for (key, value) in [
        ("name", "Positron.SDK"),
        ("version", &version),
        ("source_commit", &inventory.source_commit),
        ("api_version", &inventory.api_version),
        ("schema_digest", &hex(&inventory.compatibility.schema)),
        ("release_manifest_surface", "SdkDotNet"),
        ("registry", "https://api.nuget.org/v3/index.json"),
        ("generator", GENERATOR),
    ] {
        if release[key].as_str() != Some(value) {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    let api = get("positron/api/positron.proto")?;
    let digest = hex(&Sha256::digest(api));
    if digest != hex(&inventory.compatibility.schema)
        || get("positron/api/schema.sha256")? != format!("{digest}\n").as_bytes()
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let contract: Value = serde_json::from_slice(get("positron/contract.json")?)
        .map_err(|_| ReleaseError::Invalid)?;
    if contract["api_version"] != inventory.api_version || contract["schema_digest"] != digest {
        return Err(ReleaseError::IdentityMismatch);
    }
    let xml = crate::native_xml::document(get("positron.sdk.nuspec")?)?;
    let metadata = crate::native_xml::child(xml.root_element(), "metadata")?;
    for (key, value) in [
        ("id", "Positron.SDK"),
        ("version", version.as_str()),
        ("license", "MIT"),
    ] {
        if crate::native_xml::text(crate::native_xml::child(metadata, key)?)? != value {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if !get("lib/net8.0/positron.sdk.dll")?.starts_with(b"MZ")
        || !get("lib/net8.0/positron.sdk.pdb")?.starts_with(b"BSJB")
        || !get("lib/net8.0/positron.sdk.xml")?.starts_with(b"<")
        || !get("positron/license")?.windows(3).any(|v| v == b"MIT")
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    for (file, expected) in [
        (
            "codec.cs",
            include_bytes!("../../../positron-api/dotnet/Codec.cs").as_slice(),
        ),
        (
            "query.cs",
            include_bytes!("../../../positron-api/dotnet/Query.cs"),
        ),
        (
            "batchtracker.cs",
            include_bytes!("../../../positron-api/dotnet/BatchTracker.cs"),
        ),
        (
            "positronexception.cs",
            include_bytes!("../../../positron-api/dotnet/PositronException.cs"),
        ),
    ] {
        if get(&format!("positron/source/{file}"))? != expected {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    for (file, expected) in [
        (
            "client.cs",
            include_bytes!("../../../../sdk/dotnet/Client.cs").as_slice(),
        ),
        (
            "types.cs",
            include_bytes!("../../../../sdk/dotnet/Types.cs").as_slice(),
        ),
    ] {
        if get(&format!("positron/source/{file}"))? != expected {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if get("positron/pack.py")? != include_bytes!("../../../positron-api/dotnet/pack.py")
        || get("positron/global.json")?
            != b"{\"sdk\":{\"version\":\"8.0.427\",\"rollForward\":\"disable\"}}\n"
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let project = include_str!("../../../positron-api/dotnet/Positron.SDK.csproj")
        .replace("@VERSION@", env!("CARGO_PKG_VERSION"));
    if get("positron/source/positron.sdk.csproj")? != project.as_bytes() {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(())
}
