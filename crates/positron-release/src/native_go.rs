//! Offline Go checksum-database verification for stable SDK module ZIPs.
//! Native semantics: golang.org/x/mod/{module,zip,sumdb/dirhash,sumdb/tlog}.
use crate::ReleaseError;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use signed_note::{Note, StandardVerifier, VerifierList};
use sigstore_verify::types::Sha256Hash;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};

const MAX_ARCHIVE: usize = 64 << 20;
const MAX_MEMBER: u64 = 64 << 20;
const MAX_DECODED: u64 = 500 << 20; // Go's native module ZIP ceiling, within the caller's 512 MiB budget.
const MAX_ENTRIES: usize = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root<'a> {
    verifier_key: &'a str,
    checkpoint: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof<'a> {
    #[serde(borrow)]
    record: Record<'a>,
    checkpoint: &'a str,
    #[serde(borrow)]
    inclusion: Vec<&'a str>,
    #[serde(borrow)]
    consistency: Vec<&'a str>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<'a> {
    id: u64,
    text: &'a str,
}

/// The caller authenticates `root` with the installed Project Trust Root.
pub(crate) fn verify(
    root: &Value,
    proof: &Value,
    archive: &[u8],
    module: &str,
    version: &str,
) -> Result<(), ReleaseError> {
    for (value, path, maximum) in [
        (root, "/verifier_key", 1024),
        (root, "/checkpoint", 65_536),
        (proof, "/checkpoint", 65_536),
        (proof, "/record/text", 4096),
    ] {
        if value
            .pointer(path)
            .and_then(Value::as_str)
            .ok_or(ReleaseError::Invalid)?
            .len()
            > maximum
        {
            return Err(ReleaseError::LimitExceeded);
        }
    }
    for path in ["/inclusion", "/consistency"] {
        if proof
            .pointer(path)
            .and_then(Value::as_array)
            .ok_or(ReleaseError::Invalid)?
            .len()
            > 64
        {
            return Err(ReleaseError::LimitExceeded);
        }
    }
    if archive.len() > MAX_ARCHIVE || module.len() > 512 || version.len() > 64 {
        return Err(ReleaseError::LimitExceeded);
    }
    let root = Root::deserialize(root).map_err(|_| ReleaseError::Invalid)?;
    let proof = Proof::deserialize(proof).map_err(|_| ReleaseError::Invalid)?;
    identity(module, version)?;
    let verifiers = VerifierList::new(vec![Box::new(
        StandardVerifier::new(root.verifier_key).map_err(|_| ReleaseError::Authentication)?,
    )]);
    let (prior_size, prior_hash) = checkpoint(root.checkpoint, &verifiers)?;
    let (size, root_hash) = checkpoint(proof.checkpoint, &verifiers)?;
    let inclusion = proof
        .inclusion
        .iter()
        .map(|value| hash(value))
        .collect::<Result<Vec<_>, _>>()?;
    let consistency = proof
        .consistency
        .iter()
        .map(|value| hash(value))
        .collect::<Result<Vec<_>, _>>()?;
    sigstore_merkle::verify_consistency_proof(
        prior_size,
        size,
        &consistency,
        &prior_hash,
        &root_hash,
    )
    .map_err(|_| ReleaseError::Authentication)?;
    sigstore_merkle::verify_inclusion_proof(
        &sigstore_merkle::hash_leaf(proof.record.text.as_bytes()),
        proof.record.id,
        size,
        &inclusion,
        &root_hash,
    )
    .map_err(|_| ReleaseError::Authentication)?;
    let (zip_hash, mod_hash) = module_hashes(archive, module, version)?;
    let expected = format!("{module} {version} {zip_hash}\n{module} {version}/go.mod {mod_hash}\n");
    if proof.record.text != expected {
        return Err(ReleaseError::Authentication);
    }
    Ok(())
}

fn hash(value: &str) -> Result<Sha256Hash, ReleaseError> {
    if value.len() != 44 {
        return Err(ReleaseError::Invalid);
    }
    let bytes = B64.decode(value).map_err(|_| ReleaseError::Invalid)?;
    if B64.encode(&bytes) != value {
        return Err(ReleaseError::Invalid);
    }
    Ok(Sha256Hash::new(
        bytes.try_into().map_err(|_| ReleaseError::Invalid)?,
    ))
}

fn checkpoint(text: &str, verifiers: &VerifierList) -> Result<(u64, Sha256Hash), ReleaseError> {
    let note = Note::from_bytes(text.as_bytes()).map_err(|_| ReleaseError::Invalid)?;
    let _verified = note
        .verify(verifiers)
        .map_err(|_| ReleaseError::Authentication)?;
    let text = std::str::from_utf8(note.text()).map_err(|_| ReleaseError::Invalid)?;
    let mut lines = text.lines();
    if lines.next() != Some("go.sum database tree") {
        return Err(ReleaseError::IdentityMismatch);
    }
    let number = lines.next().ok_or(ReleaseError::Invalid)?;
    let size = number.parse::<u64>().map_err(|_| ReleaseError::Invalid)?;
    if size > i64::MAX as u64 || size.to_string() != number {
        return Err(ReleaseError::Invalid);
    }
    let root = hash(lines.next().ok_or(ReleaseError::Invalid)?)?;
    if lines.next().is_some() {
        return Err(ReleaseError::Unsupported);
    }
    if size == 0 && root != Sha256Hash::new(Sha256::digest([]).into()) {
        return Err(ReleaseError::Invalid);
    }
    Ok((size, root))
}

fn identity(module: &str, version: &str) -> Result<(), ReleaseError> {
    let numbers = version
        .strip_prefix('v')
        .ok_or(ReleaseError::Unsupported)?
        .split('.')
        .collect::<Vec<_>>();
    let [major, _, _] = numbers.as_slice() else {
        return Err(ReleaseError::Unsupported);
    };
    for number in &numbers {
        if number
            .parse::<u64>()
            .ok()
            .is_none_or(|value| value.to_string() != *number)
        {
            return Err(ReleaseError::Unsupported);
        }
    }
    let major = major
        .parse::<u64>()
        .map_err(|_| ReleaseError::Unsupported)?;
    let host = module.split('/').next().ok_or(ReleaseError::Invalid)?;
    if !host.contains('.')
        || host.starts_with('-')
        || host == "gopkg.in"
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
    {
        return Err(ReleaseError::Unsupported);
    }
    for element in module.split('/') {
        path_element(element)?;
        if element.starts_with('.')
            || !element
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        {
            return Err(ReleaseError::Unsupported);
        }
    }
    let last = module.rsplit('/').next().ok_or(ReleaseError::Invalid)?;
    let path_major = last.strip_prefix('v').filter(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    });
    if (path_major.is_some() && (major < 2 || last != format!("v{major}")))
        || (path_major.is_none() && major >= 2)
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(())
}

fn path_element(element: &str) -> Result<(), ReleaseError> {
    if !element.is_ascii() {
        return Err(ReleaseError::Unsupported);
    }
    if element.is_empty()
        || element.bytes().all(|b| b == b'.')
        || element.ends_with('.')
        || !element
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&()+,-.=@[]^_{}~ ".contains(&b))
    {
        return Err(ReleaseError::Invalid);
    }
    let base = element
        .split('.')
        .next()
        .ok_or(ReleaseError::Invalid)?
        .to_ascii_uppercase();
    if matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            base.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes().first(), Some(b'1'..=b'9'))
            })
        })
    {
        return Err(ReleaseError::Invalid);
    }
    Ok(())
}

fn module_hashes(
    bytes: &[u8],
    module: &str,
    version: &str,
) -> Result<(String, String), ReleaseError> {
    let count = crate::archive_scan::check_zip_count(bytes, MAX_ENTRIES)?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| ReleaseError::Invalid)?;
    if count != archive.len() {
        return Err(ReleaseError::Invalid);
    }
    let prefix = format!("{module}@{version}/");
    let mut paths = BTreeMap::<String, (String, bool)>::new();
    let mut path_bytes_remaining = 8_388_608_usize;
    let mut hashes = BTreeMap::<String, [u8; 32]>::new();
    let mut go_mod = None;
    let mut remaining = MAX_DECODED;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index_raw(index)
            .map_err(|_| ReleaseError::Invalid)?;
        if entry.encrypted()
            || entry
                .unix_mode()
                .is_some_and(|mode| !matches!(mode & 0o170_000, 0 | 0o100_000))
            || entry.name_raw().ends_with(b"/")
        {
            return Err(ReleaseError::Unsupported);
        }
        if entry.name_raw().len() > 4096 || entry.size() > MAX_MEMBER {
            return Err(ReleaseError::LimitExceeded);
        }
        let full = std::str::from_utf8(entry.name_raw())
            .map_err(|_| ReleaseError::Invalid)?
            .to_owned();
        let name = full
            .strip_prefix(&prefix)
            .ok_or(ReleaseError::IdentityMismatch)?;
        let elements = name.split('/').collect::<Vec<_>>();
        let mut path = String::new();
        for (index, element) in elements.iter().enumerate() {
            path_element(element)?;
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(element);
            let file = index + 1 == elements.len();
            let folded = path.to_ascii_lowercase();
            if let Some((original, previous_file)) = paths.get(&folded) {
                if *previous_file || file || original != &path {
                    return Err(ReleaseError::Invalid);
                }
            } else {
                if paths.len() >= 65_536 {
                    return Err(ReleaseError::LimitExceeded);
                }
                path_bytes_remaining = path_bytes_remaining
                    .checked_sub(path.len() * 2)
                    .ok_or(ReleaseError::LimitExceeded)?;
                paths.insert(folded, (path.clone(), file));
            }
            if element.eq_ignore_ascii_case("go.mod") && (name != "go.mod" || !file) {
                return Err(ReleaseError::Invalid);
            }
        }
        let expected_size = entry.size();
        if expected_size > remaining {
            return Err(ReleaseError::LimitExceeded);
        }
        if matches!(name, "go.mod" | "LICENSE") && expected_size > 16 << 20 {
            return Err(ReleaseError::LimitExceeded);
        }
        let expected_crc = entry.crc32();
        let method = entry.compression();
        let mut input: Box<dyn Read> = match method {
            zip::CompressionMethod::Stored => Box::new(&mut entry),
            zip::CompressionMethod::DEFLATE => {
                Box::new(flate2::read::DeflateDecoder::new(&mut entry))
            },
            _ => return Err(ReleaseError::Unsupported),
        };
        let mut digest = Sha256::new();
        let mut crc = crc32fast::Hasher::new();
        let mut size = 0_u64;
        let mut mod_bytes = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let count = input.read(&mut buffer).map_err(|_| ReleaseError::Invalid)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .ok_or(ReleaseError::LimitExceeded)?;
            remaining = remaining
                .checked_sub(count as u64)
                .ok_or(ReleaseError::LimitExceeded)?;
            if size > expected_size {
                return Err(ReleaseError::Invalid);
            }
            let chunk = buffer.get(..count).ok_or(ReleaseError::Invalid)?;
            digest.update(chunk);
            crc.update(chunk);
            if name == "go.mod" {
                mod_bytes.extend_from_slice(chunk);
            }
        }
        if size != expected_size || crc.finalize() != expected_crc {
            return Err(ReleaseError::Invalid);
        }
        let digest: [u8; 32] = digest.finalize().into();
        if name == "go.mod" {
            let first = std::str::from_utf8(&mod_bytes)
                .map_err(|_| ReleaseError::Invalid)?
                .lines()
                .next()
                .ok_or(ReleaseError::Invalid)?;
            let declared = first
                .strip_prefix("module ")
                .ok_or(ReleaseError::Unsupported)?
                .trim();
            let declared = declared
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or(declared);
            if declared != module {
                return Err(ReleaseError::IdentityMismatch);
            }
            go_mod = Some(digest);
        }
        hashes.insert(full, digest);
    }
    let go_mod = go_mod.ok_or(ReleaseError::Unsupported)?;
    Ok((
        dir_hash(&hashes),
        dir_hash(&BTreeMap::from([("go.mod".to_owned(), go_mod)])),
    ))
}

fn dir_hash(files: &BTreeMap<String, [u8; 32]>) -> String {
    let mut digest = Sha256::new();
    for (name, hash) in files {
        digest.update(format!("{}  {name}\n", crate::inventory::hex(hash)));
    }
    format!("h1:{}", B64.encode(digest.finalize()))
}

#[cfg(test)]
mod tests;
