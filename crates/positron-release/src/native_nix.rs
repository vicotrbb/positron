//! Nix binary-cache signatures authenticate the standard store-path fingerprint.
use crate::{
    files::Bundle,
    publication::{base64, verify_signature},
    *,
};
use serde_json::Value;
use std::{collections::BTreeMap, io::Read};

const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

pub(crate) fn verify(
    proof: &Value,
    artifact: &Artifact,
    inventory: &ReleaseInventory,
    files: &Bundle,
    trust: &VerifiedTrust,
    policy: &NativePublisherPolicy,
) -> Result<(), ReleaseError> {
    let NativePublisherPolicy::NixCache { key_name, key_hint } = policy else {
        return Err(ReleaseError::Unsupported);
    };
    let key = trust.publisher_key(key_hint)?;
    let text = proof
        .get("narinfo")
        .and_then(Value::as_str)
        .ok_or(ReleaseError::Authentication)?;
    if text.len() > 65_536 {
        return Err(ReleaseError::LimitExceeded);
    }
    if !text.ends_with('\n')
        || text
            .bytes()
            .any(|byte| byte != b'\n' && !(32..=126).contains(&byte))
    {
        return Err(ReleaseError::Invalid);
    }
    let mut fields = BTreeMap::new();
    let mut signatures = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= 32 {
            return Err(ReleaseError::LimitExceeded);
        }
        let (name, value) = line.split_once(": ").ok_or(ReleaseError::Invalid)?;
        if name == "Sig" {
            if signatures.len() >= 8 {
                return Err(ReleaseError::LimitExceeded);
            }
            signatures.push(value);
        } else if !matches!(
            name,
            "StorePath"
                | "URL"
                | "Compression"
                | "FileHash"
                | "FileSize"
                | "NarHash"
                | "NarSize"
                | "References"
                | "Deriver"
                | "CA"
        ) || fields.insert(name, value).is_some()
        {
            return Err(ReleaseError::Invalid);
        }
    }
    let field = |name| fields.get(name).copied().ok_or(ReleaseError::Invalid);
    let path = field("StorePath")?;
    if !store_path(path) || path != artifact.publication.native_subject {
        return Err(ReleaseError::IdentityMismatch);
    }
    if field("URL")?.is_empty() {
        return Err(ReleaseError::Invalid);
    }
    let identity = &inventory.file(&artifact.file)?.identity;
    let hash = format!("sha256:{}", nix32(&identity.sha256));
    let size = identity.size.to_string();
    if field("NarHash")? != hash || field("NarSize")? != size {
        return Err(ReleaseError::IdentityMismatch);
    }
    let mut references = Vec::new();
    for reference in field("References")?.split_whitespace() {
        if references.len() >= 256 {
            return Err(ReleaseError::LimitExceeded);
        }
        let full = format!("/nix/store/{reference}");
        if !store_path(&full) {
            return Err(ReleaseError::Invalid);
        }
        references.push(full);
    }
    references.sort();
    if references
        .windows(2)
        .any(|pair| pair.first() == pair.get(1))
    {
        return Err(ReleaseError::Invalid);
    }
    let mut header = [0; 24];
    files
        .file(&artifact.file)?
        .read_exact(&mut header)
        .map_err(|_| ReleaseError::Invalid)?;
    if header != *b"\x0d\0\0\0\0\0\0\0nix-archive-1\0\0\0" {
        return Err(ReleaseError::Invalid);
    }
    let fingerprint = format!("1;{path};{hash};{size};{}", references.join(","));
    for signature in signatures {
        let (name, signature) = signature.split_once(':').ok_or(ReleaseError::Invalid)?;
        if name == key_name {
            return verify_signature(&key, fingerprint.as_bytes(), &base64(signature)?);
        }
    }
    Err(ReleaseError::Authentication)
}

fn store_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((hash, name)) = name.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash.bytes().all(|byte| ALPHABET.contains(&byte))
        && !name.is_empty()
        && name.len() <= 211
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+._?=-".contains(&byte))
}

fn nix32(bytes: &[u8; 32]) -> String {
    (0..52)
        .rev()
        .filter_map(|position| {
            let bit = position * 5;
            let mut value = u16::from(*bytes.get(bit / 8)?) >> (bit % 8);
            if let Some(next) = bytes.get(bit / 8 + 1) {
                value |= u16::from(*next) << (8 - bit % 8);
            }
            ALPHABET
                .get(usize::from(value & 31))
                .copied()
                .map(char::from)
        })
        .collect()
}
