use crate::{FileIdentity, ReleaseError, inventory::token};
use base64::Engine;
use der::{Decode, Reader};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub(crate) struct Bundle {
    directory: File,
}
impl Bundle {
    pub(crate) fn open(path: &Path) -> Result<Self, ReleaseError> {
        let path = path.canonicalize().map_err(|_| ReleaseError::Unavailable)?;
        let mut directory: File = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ReleaseError::Unavailable)?
        .into();
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                directory = rustix::fs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| ReleaseError::Unavailable)?
                .into();
            }
        }
        Ok(Self { directory })
    }
    pub(crate) fn file(&self, id: &str) -> Result<File, ReleaseError> {
        if !token(id) {
            return Err(ReleaseError::Invalid);
        }
        let file: File = rustix::fs::openat(
            &self.directory,
            id,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ReleaseError::Unavailable)?
        .into();
        let metadata = file.metadata().map_err(|_| ReleaseError::Unavailable)?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return Err(ReleaseError::LimitExceeded);
        }
        Ok(file)
    }
    pub(crate) fn read(&self, id: &str, maximum: usize) -> Result<Vec<u8>, ReleaseError> {
        let mut bytes = Vec::new();
        self.file(id)?
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReleaseError::Unavailable)?;
        if bytes.len() > maximum {
            return Err(ReleaseError::LimitExceeded);
        }
        Ok(bytes)
    }
    pub(crate) fn same_file(&self, other: &Self, id: &str) -> Result<bool, ReleaseError> {
        use std::os::unix::fs::MetadataExt;
        let left = self
            .file(id)?
            .metadata()
            .map_err(|_| ReleaseError::Unavailable)?;
        let right = other
            .file(id)?
            .metadata()
            .map_err(|_| ReleaseError::Unavailable)?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
    pub(crate) fn inspect(
        &self,
        id: &str,
        canaries: &[Vec<u8>],
    ) -> Result<FileIdentity, ReleaseError> {
        inspect_reader(self.file(id)?, canaries, MAX_FILE_BYTES, false)
    }
}
pub(crate) fn inspect_reader(
    mut file: impl Read,
    canaries: &[Vec<u8>],
    maximum: u64,
    allow_empty: bool,
) -> Result<FileIdentity, ReleaseError> {
    if canaries.len() > 64
        || canaries
            .iter()
            .any(|value| !(8..=128).contains(&value.len()))
    {
        return Err(ReleaseError::Invalid);
    }

    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 65_536];
    let mut carry = Vec::new();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ReleaseError::Unavailable)?;
        if count == 0 {
            break;
        }
        let chunk = buffer.get(..count).ok_or(ReleaseError::Invalid)?;
        size = size
            .checked_add(count as u64)
            .filter(|size| *size <= maximum)
            .ok_or(ReleaseError::LimitExceeded)?;
        hash.update(chunk);
        carry.extend(chunk);
        if contains_secret(&carry, canaries) {
            return Err(ReleaseError::SecretDetected);
        }
        if carry.len() > 256 {
            carry.drain(..carry.len() - 256);
        }
    }
    if size == 0 && !allow_empty {
        return Err(ReleaseError::Invalid);
    }
    Ok(FileIdentity {
        sha256: hash.finalize().into(),
        size,
    })
}

/// Stream one artifact without following a member symlink, and scan known credential forms and caller canaries.
pub fn inspect_file(
    directory: &Path,
    id: &str,
    canaries: &[Vec<u8>],
) -> Result<FileIdentity, ReleaseError> {
    Bundle::open(directory)?.inspect(id, canaries)
}
pub(crate) fn contains_secret(bytes: &[u8], canaries: &[Vec<u8>]) -> bool {
    if canaries
        .iter()
        .any(|canary| bytes.windows(canary.len()).any(|window| window == canary))
    {
        return true;
    }
    for prefix in [
        b"ghp_".as_slice(),
        b"github_pat_",
        b"sk-proj-",
        b"AKIA",
        b"ASIA",
    ] {
        if bytes
            .windows(prefix.len())
            .enumerate()
            .any(|(index, window)| {
                window == prefix
                    && bytes.get(index + prefix.len()..).is_some_and(|tail| {
                        let aws = prefix == b"AKIA" || prefix == b"ASIA";
                        tail.iter()
                            .take_while(|byte| {
                                if aws {
                                    byte.is_ascii_uppercase() || byte.is_ascii_digit()
                                } else {
                                    byte.is_ascii_alphanumeric() || **byte == b'_'
                                }
                            })
                            .count()
                            >= if aws { 16 } else { 32 }
                    })
            })
        {
            return true;
        }
    }
    for header in [
        b"-----BEGIN PRIVATE KEY-----".as_slice(),
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
    ] {
        if bytes
            .windows(header.len())
            .enumerate()
            .any(|(index, window)| {
                window == header
                    && bytes
                        .get(index + header.len()..)
                        .is_some_and(private_key_prefix)
            })
        {
            return true;
        }
    }
    false
}

// PKCS#8, PKCS#1 RSA and SEC1 EC all begin with a DER SEQUENCE and
// INTEGER version 0 or 1. Inspect only this bounded prefix, including for
// truncated keys: an adjacent public string is not private-key encoding.
fn private_key_prefix(tail: &[u8]) -> bool {
    if !tail.starts_with(b"\n") && !tail.starts_with(b"\r\n") {
        return false;
    }
    let encoded: Vec<_> = tail
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .take(32)
        .collect();
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(mut reader) = der::SliceReader::new(&decoded) else {
        return false;
    };
    let Ok(header) = der::Header::decode(&mut reader) else {
        return false;
    };
    header.tag == der::Tag::Sequence
        && u32::from(header.length) >= 3
        && reader.decode::<u8>().is_ok_and(|version| version <= 1)
}

/// Read an explicitly named local release input with a strict allocation bound.
pub fn read_release_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ReleaseError> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ReleaseError::Invalid)?;
    Bundle::open(parent)?.read(name, maximum)
}
/// Read installed trust only from a regular file controlled by this user or root.
pub fn read_installed_trust_file(path: &Path, maximum: usize) -> Result<Vec<u8>, ReleaseError> {
    use std::os::unix::fs::MetadataExt;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ReleaseError::Invalid)?;
    let mut file = Bundle::open(parent)?.file(name)?;
    let metadata = file.metadata().map_err(|_| ReleaseError::Unavailable)?;
    if metadata.mode() & 0o022 != 0
        || (metadata.uid() != 0 && metadata.uid() != rustix::process::geteuid().as_raw())
    {
        return Err(ReleaseError::Authentication);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReleaseError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(ReleaseError::LimitExceeded);
    }
    Ok(bytes)
}
/// Create a new owner-only artifact. Existing files and member symlinks are refused.
pub fn write_release_file(path: &Path, bytes: &[u8]) -> Result<(), ReleaseError> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ReleaseError::Invalid)?;
    if !token(name) {
        return Err(ReleaseError::Invalid);
    }
    let bundle = Bundle::open(parent)?;
    let mut file: File = rustix::fs::openat(
        &bundle.directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| ReleaseError::Unavailable)?
    .into();
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ReleaseError::Unavailable)?;
    bundle
        .directory
        .sync_all()
        .map_err(|_| ReleaseError::Unavailable)
}
