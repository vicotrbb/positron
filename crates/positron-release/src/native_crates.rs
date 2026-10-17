//! Validate captured crates.io metadata against a native Cargo package.
//! This profile contains no registry signature or independently verifiable upload receipt.
//! The caller authenticates the whole projection and explicitly authorizes this absence profile.
use crate::ReleaseError;
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, io::Read};

const PROFILE: &str = "crates-io-oidc-upload-no-offline-receipt-v1";
const MAX_INPUT: usize = 64 << 20;
const MAX_DECODED: u64 = 512 << 20;
const MAX_MEMBER: u64 = 64 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof<'a> {
    profile: &'a str,
    #[serde(borrow)]
    index: Index<'a>,
    #[serde(borrow)]
    trustpub: Trustpub<'a>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index<'a> {
    name: &'a str,
    vers: &'a str,
    cksum: &'a str,
    yanked: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trustpub<'a> {
    provider: &'a str,
    repository: &'a str,
    run_id: &'a str,
    sha: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vcs<'a> {
    #[serde(borrow)]
    git: Git<'a>,
    path_in_vcs: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Git<'a> {
    sha1: &'a str,
    dirty: Option<bool>,
}

pub(crate) fn verify(
    proof: &Value,
    contents: &[u8],
    name: &str,
    version: &str,
    source_commit: &str,
    expected_repository: &str,
) -> Result<(), ReleaseError> {
    if contents.len() > MAX_INPUT
        || name.len() > 64
        || version.len() > 64
        || expected_repository.len() > 256
    {
        return Err(ReleaseError::LimitExceeded);
    }
    for (path, maximum) in [
        ("/profile", 64),
        ("/index/name", 64),
        ("/index/vers", 64),
        ("/index/cksum", 64),
        ("/trustpub/provider", 16),
        ("/trustpub/repository", 256),
        ("/trustpub/run_id", 20),
        ("/trustpub/sha", 40),
    ] {
        if proof
            .pointer(path)
            .and_then(Value::as_str)
            .ok_or(ReleaseError::Invalid)?
            .len()
            > maximum
        {
            return Err(ReleaseError::LimitExceeded);
        }
    }
    let proof = Proof::deserialize(proof).map_err(|_| ReleaseError::Invalid)?;
    if proof.profile != PROFILE || proof.trustpub.provider != "github" {
        return Err(ReleaseError::Unsupported);
    }
    if !name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(ReleaseError::Invalid);
    }
    positron_kernel::release_manifest::ProductVersion::parse_exact(version)
        .map_err(|_| ReleaseError::Unsupported)?;
    let (owner, repository) = expected_repository
        .split_once('/')
        .ok_or(ReleaseError::Invalid)?;
    if owner.is_empty()
        || repository.is_empty()
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || !repository
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || matches!(repository, "." | "..")
    {
        return Err(ReleaseError::Invalid);
    }
    for (value, length) in [
        (source_commit, 40),
        (proof.trustpub.sha, 40),
        (proof.index.cksum, 64),
    ] {
        if value.len() != length
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(ReleaseError::Invalid);
        }
    }
    if proof
        .trustpub
        .run_id
        .parse::<u64>()
        .ok()
        .is_none_or(|id| id == 0 || id.to_string() != proof.trustpub.run_id)
    {
        return Err(ReleaseError::Invalid);
    }
    if proof.index.yanked
        || proof.index.name != name
        || proof.index.vers != version
        || proof.trustpub.sha != source_commit
        || proof.trustpub.repository != expected_repository
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    if proof.index.cksum != crate::inventory::hex(&crate::construction::sha256(contents)) {
        return Err(ReleaseError::Authentication);
    }
    let mut decoded = flate2::bufread::GzDecoder::new(contents).take(MAX_DECODED + 1);
    let inspected = inspect(
        &mut decoded,
        &format!("{name}-{version}/"),
        name,
        version,
        source_commit,
    );
    if decoded.limit() == 0 {
        return Err(ReleaseError::LimitExceeded);
    }
    inspected?;
    let mut buffer = [0_u8; 8192];
    let mut trailing = 0_u64;
    loop {
        let count = decoded
            .read(&mut buffer)
            .map_err(|_| ReleaseError::Invalid)?;
        if count == 0 {
            break;
        }
        if buffer
            .get(..count)
            .ok_or(ReleaseError::Invalid)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ReleaseError::Invalid);
        }
        trailing += count as u64;
    }
    if decoded.limit() == 0 {
        return Err(ReleaseError::LimitExceeded);
    }
    // tar consumed its first zero block. Require its second block and aligned padding.
    if trailing < 512
        || !trailing.is_multiple_of(512)
        || !decoded.into_inner().into_inner().is_empty()
    {
        return Err(ReleaseError::Invalid);
    }
    Ok(())
}

fn inspect(
    reader: &mut impl Read,
    prefix: &str,
    name: &str,
    version: &str,
    source_commit: &str,
) -> Result<(), ReleaseError> {
    let mut archive = tar::Archive::new(reader);
    let mut files = BTreeSet::<String>::new();
    let mut path_budget = 8_388_608_usize;
    let mut manifest = false;
    let mut source_vcs = false;
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
        if entry.size() > MAX_MEMBER {
            return Err(ReleaseError::LimitExceeded);
        }
        let path = entry.path_bytes();
        if path.len() > 4096 {
            return Err(ReleaseError::LimitExceeded);
        }
        let full = std::str::from_utf8(&path)
            .map_err(|_| ReleaseError::Invalid)?
            .to_owned();
        let relative = full
            .strip_prefix(prefix)
            .ok_or(ReleaseError::IdentityMismatch)?;
        portable_path(relative)?;
        path_budget = path_budget
            .checked_sub(full.len())
            .ok_or(ReleaseError::LimitExceeded)?;
        let folded = full.to_ascii_lowercase();
        let mut parent = folded.as_str();
        while let Some((directory, _)) = parent.rsplit_once('/') {
            if files.contains(directory) {
                return Err(ReleaseError::Invalid);
            }
            parent = directory;
        }
        let children = format!("{folded}/");
        if files
            .range(children.clone()..)
            .next()
            .is_some_and(|file| file.starts_with(&children))
            || !files.insert(folded)
        {
            return Err(ReleaseError::Invalid);
        }
        let expected = entry.size();
        if relative == "Cargo.toml" || relative == ".cargo_vcs_info.json" {
            let maximum = if relative == "Cargo.toml" {
                1 << 20
            } else {
                16 << 10
            };
            if expected > maximum {
                return Err(ReleaseError::LimitExceeded);
            }
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|_| ReleaseError::Invalid)?;
            if bytes.len() as u64 != expected {
                return Err(ReleaseError::Invalid);
            }
            if relative == "Cargo.toml" {
                let parsed: toml::Value =
                    toml::from_str(std::str::from_utf8(&bytes).map_err(|_| ReleaseError::Invalid)?)
                        .map_err(|_| ReleaseError::Invalid)?;
                let package = parsed
                    .get("package")
                    .and_then(toml::Value::as_table)
                    .ok_or(ReleaseError::Invalid)?;
                if package.get("name").and_then(toml::Value::as_str) != Some(name)
                    || package.get("version").and_then(toml::Value::as_str) != Some(version)
                {
                    return Err(ReleaseError::IdentityMismatch);
                }
                manifest = true;
            } else {
                let vcs: Vcs<'_> =
                    serde_json::from_slice(&bytes).map_err(|_| ReleaseError::Invalid)?;
                if vcs.git.sha1 != source_commit || vcs.git.dirty == Some(true) {
                    return Err(ReleaseError::IdentityMismatch);
                }
                if !vcs.path_in_vcs.is_empty() {
                    portable_path(vcs.path_in_vcs)?;
                }
                source_vcs = true;
            }
        } else if std::io::copy(&mut entry, &mut std::io::sink())
            .map_err(|_| ReleaseError::Invalid)?
            != expected
        {
            return Err(ReleaseError::Invalid);
        }
    }
    if !manifest || !source_vcs {
        return Err(ReleaseError::Invalid);
    }
    Ok(())
}

fn portable_path(path: &str) -> Result<(), ReleaseError> {
    if !path.is_ascii() {
        return Err(ReleaseError::Unsupported);
    }
    if path.len() > 4096 || path.split('/').count() > 64 {
        return Err(ReleaseError::LimitExceeded);
    }
    if path.split('/').any(|part| {
        part.is_empty()
            || part.bytes().all(|b| b == b'.')
            || part.ends_with('.')
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
    }) {
        return Err(ReleaseError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
