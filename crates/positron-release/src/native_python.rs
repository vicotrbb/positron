//! Inspect the actual generated Python wheel under the existing Release Trust authority.
use crate::{ReleaseError, construction::sha256, inventory::hex};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
};

pub(crate) const MAX_INPUT: usize = 64 << 20;
const MAX_MEMBER: u64 = 16 << 20;
const MAX_DECODED: usize = 128 << 20;

pub(crate) fn inspect_sdk(
    contents: &[u8],
    version: &str,
    source_commit: &str,
    api: &str,
    schema: &[u8; 32],
) -> Result<(), ReleaseError> {
    let files = wheel(contents)?;
    let read = |path: &str| {
        files
            .get(path)
            .map(Vec::as_slice)
            .ok_or(ReleaseError::IdentityMismatch)
    };
    let release: Value = serde_json::from_slice(read("positron_sdk/release.json")?)
        .map_err(|_| ReleaseError::Invalid)?;
    for (name, expected) in [
        ("name", "positron-sdk"),
        ("version", version),
        ("source_commit", source_commit),
        ("api_version", api),
        ("schema_digest", hex(schema).as_str()),
        ("release_manifest_surface", "SdkPython"),
        ("registry", "https://pypi.org"),
        (
            "generator",
            "positron-api=1,python=3.11,protoc-bin-vendored=3.2.0",
        ),
    ] {
        if release.get(name).and_then(Value::as_str) != Some(expected) {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if sha256(read("positron_sdk/api/positron.proto")?) != *schema
        || read("positron_sdk/api/schema.sha256")? != format!("{}\n", hex(schema)).as_bytes()
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let contract: Value = serde_json::from_slice(read("positron_sdk/contract.json")?)
        .map_err(|_| ReleaseError::Invalid)?;
    if contract.get("api_version").and_then(Value::as_str) != Some(api)
        || contract.get("schema_digest").and_then(Value::as_str) != Some(hex(schema).as_str())
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    for name in [
        "__init__.py",
        "types.py",
        "client.py",
        "codec.py",
        "query.py",
        "errors.py",
    ] {
        if read(&format!("positron_sdk/{name}"))?.is_empty() {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    read("positron_sdk/py.typed")?;
    let dist = format!("positron_sdk-{version}.dist-info");
    let metadata = std::str::from_utf8(read(&format!("{dist}/METADATA"))?)
        .map_err(|_| ReleaseError::Invalid)?;
    for (key, expected) in [
        ("Metadata-Version", "2.4"),
        ("Name", "positron-sdk"),
        ("Version", version),
        ("Requires-Python", ">=3.11"),
    ] {
        header(metadata, key, expected)?;
    }
    if metadata
        .lines()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .any(|(key, _)| {
            key.eq_ignore_ascii_case("Requires-Dist") || key.eq_ignore_ascii_case("Provides-Extra")
        })
    {
        return Err(ReleaseError::Unsupported);
    }
    let wheel =
        std::str::from_utf8(read(&format!("{dist}/WHEEL"))?).map_err(|_| ReleaseError::Invalid)?;
    for (key, expected) in [
        ("Wheel-Version", "1.0"),
        ("Root-Is-Purelib", "true"),
        ("Tag", "py3-none-any"),
        ("Generator", "setuptools (80.9.0)"),
    ] {
        header(wheel, key, expected)?;
    }
    let record_path = format!("{dist}/RECORD");
    let record = std::str::from_utf8(read(&record_path)?).map_err(|_| ReleaseError::Invalid)?;
    let mut seen = BTreeSet::new();
    for line in record.lines() {
        let mut fields = line.trim_end_matches('\r').split(',');
        let path = fields.next().ok_or(ReleaseError::Invalid)?;
        let hash = fields.next().ok_or(ReleaseError::Invalid)?;
        let size = fields.next().ok_or(ReleaseError::Invalid)?;
        if fields.next().is_some() || !seen.insert(path) {
            return Err(ReleaseError::Invalid);
        }
        let bytes = read(path)?;
        if path == record_path {
            if !hash.is_empty() || !size.is_empty() {
                return Err(ReleaseError::Invalid);
            }
        } else if hash != format!("sha256={}", URL_SAFE_NO_PAD.encode(sha256(bytes)))
            || size != bytes.len().to_string()
        {
            return Err(ReleaseError::IdentityMismatch);
        }
    }
    if seen.len() != files.len() {
        return Err(ReleaseError::IdentityMismatch);
    }
    if files
        .keys()
        .any(|path| !(path.starts_with("positron_sdk/") || path.starts_with(&format!("{dist}/"))))
    {
        return Err(ReleaseError::Unsupported);
    }
    Ok(())
}

fn header(document: &str, name: &str, expected: &str) -> Result<(), ReleaseError> {
    let mut values = document
        .lines()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim());
    if values.next() != Some(expected) || values.next().is_some() {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(())
}

fn wheel(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    if bytes.len() > MAX_INPUT {
        return Err(ReleaseError::LimitExceeded);
    }
    let count = crate::archive_scan::check_zip_count(bytes, 16_384)?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ReleaseError::Invalid)?;
    if archive.len() != count || archive.offset() != 0 {
        return Err(ReleaseError::Invalid);
    }
    let mut files = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut decoded = 0_usize;
    let mut local_end = 0_u64;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index_raw(index)
            .map_err(|_| ReleaseError::Invalid)?;
        let name = std::str::from_utf8(file.name_raw())
            .map_err(|_| ReleaseError::Invalid)?
            .to_owned();
        crate::native_crates::portable_path(&name)?;
        // The canonical pure wheel has ordinary, contiguous local entries.
        // Authenticate local names/CRC/sizes too: installers read these headers.
        let local = usize::try_from(file.header_start()).map_err(|_| ReleaseError::Invalid)?;
        if file.header_start() != local_end || local > bytes.len().saturating_sub(30) {
            return Err(ReleaseError::Invalid);
        }
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
        let data = file.data_start().ok_or(ReleaseError::Invalid)?;
        if bytes.get(local..local + 4) != Some(b"PK\x03\x04")
            || word(6)? & !0x800 != 0
            || usize::from(word(26)?) != name.len()
            || bytes.get(local + 30..local + 30 + name.len()) != Some(name.as_bytes())
            || (local + 30 + name.len() + usize::from(word(28)?)) as u64 != data
            || number(14)? != file.crc32()
            || u64::from(number(18)?) != file.compressed_size()
            || u64::from(number(22)?) != file.size()
            || !matches!(
                (word(8)?, file.compression()),
                (0, zip::CompressionMethod::Stored) | (8, zip::CompressionMethod::DEFLATE)
            )
        {
            return Err(ReleaseError::Invalid);
        }
        local_end = data
            .checked_add(file.compressed_size())
            .ok_or(ReleaseError::Invalid)?;
        let folded = name.to_ascii_lowercase();
        let mut parent = folded.as_str();
        while let Some((directory, _)) = parent.rsplit_once('/') {
            if names.contains(directory) {
                return Err(ReleaseError::Invalid);
            }
            parent = directory;
        }
        if names
            .range(format!("{folded}/")..)
            .next()
            .is_some_and(|child: &String| child.starts_with(&format!("{folded}/")))
            || !names.insert(folded)
            || file.encrypted()
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(ReleaseError::Invalid);
        }
        if file.size() > MAX_MEMBER {
            return Err(ReleaseError::LimitExceeded);
        }
        let size = usize::try_from(file.size()).map_err(|_| ReleaseError::LimitExceeded)?;
        decoded = decoded
            .checked_add(size)
            .ok_or(ReleaseError::LimitExceeded)?;
        if decoded > MAX_DECODED {
            return Err(ReleaseError::LimitExceeded);
        }
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
            .take(MAX_MEMBER + 1)
            .read_to_end(&mut content)
            .map_err(|_| ReleaseError::Invalid)?;
        if content.len() != size || crc32fast::hash(&content) != crc {
            return Err(ReleaseError::Invalid);
        }
        files.insert(name, content);
    }
    if local_end != archive.central_directory_start() {
        return Err(ReleaseError::Invalid);
    }
    Ok(files)
}
