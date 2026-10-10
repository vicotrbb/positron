//! Exact, owner-only held-file recovery artifact operations.
use super::super::{
    acl::{verify_directory_acl, verify_file_acl},
    initialization_io::synchronize_security_directory,
    security_directory::open_absolute_directory,
};
use super::{MAX_BUNDLE, RecoveryFailure, RecoverySession};
use rustix::fs::{self as fs, AtFlags, Mode, OFlags};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn parent(path: &Path) -> Result<(File, &std::ffi::OsStr), RecoveryFailure> {
    let name = path.file_name().ok_or(RecoveryFailure::Storage)?;
    let directory = open_absolute_directory(path.parent().ok_or(RecoveryFailure::Storage)?)
        .map_err(|_| RecoveryFailure::Storage)?;
    let metadata = directory.metadata().map_err(|_| RecoveryFailure::Storage)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err(RecoveryFailure::Storage);
    }
    verify_directory_acl(&directory).map_err(|_| RecoveryFailure::Storage)?;
    Ok((directory, name))
}
fn verify(directory: &File, name: &std::ffi::OsStr, file: &File) -> Result<(), RecoveryFailure> {
    let metadata = file.metadata().map_err(|_| RecoveryFailure::Storage)?;
    let entry = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| RecoveryFailure::Storage)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.dev() != entry.st_dev as u64
        || metadata.ino() != entry.st_ino
        || entry.st_nlink != 1
    {
        return Err(RecoveryFailure::Storage);
    }
    verify_file_acl(file).map_err(|_| RecoveryFailure::Storage)
}
impl RecoverySession<'_> {
    pub fn write_new(&self, path: &Path, ciphertext: &[u8]) -> Result<(), RecoveryFailure> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_BUNDLE {
            return Err(RecoveryFailure::LimitExceeded);
        }
        let (directory, name) = parent(path)?;
        let mut file = fs::openat(
            &directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                RecoveryFailure::AlreadyExists
            } else {
                RecoveryFailure::Storage
            }
        })?;
        verify(&directory, name, &file)?;
        file.write_all(ciphertext)
            .map_err(|_| RecoveryFailure::Storage)?;
        file.sync_all().map_err(|_| RecoveryFailure::Storage)?;
        verify(&directory, name, &file)?;
        directory.sync_all().map_err(|_| RecoveryFailure::Storage)
    }
    /// Removes only the exact authenticated ciphertext already superseded in the Catalog.
    pub fn retire(&self, path: &Path, expected_digest: [u8; 32]) -> Result<(), RecoveryFailure> {
        let (directory, name) = parent(path)?;
        let mut file = fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                // Absence after a prepared unlink is safe only after the held parent
                // has durably recorded it. A failed sync must retain prepared state.
                if synchronize_security_directory(&directory).is_err() {
                    RecoveryFailure::Storage
                } else {
                    RecoveryFailure::Missing
                }
            } else {
                RecoveryFailure::Storage
            }
        })?;
        verify(&directory, name, &file)?;
        let mut bytes = Vec::with_capacity(MAX_BUNDLE + 1);
        (&mut file)
            .take((MAX_BUNDLE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RecoveryFailure::Storage)?;
        if bytes.is_empty()
            || bytes.len() > MAX_BUNDLE
            || crate::data_protection::DataProtection::hash(&bytes)
                .map_err(|_| RecoveryFailure::Authentication)?
                != expected_digest
        {
            return Err(RecoveryFailure::Authentication);
        }
        verify(&directory, name, &file)?;
        fs::unlinkat(&directory, name, AtFlags::empty()).map_err(|_| RecoveryFailure::Storage)?;
        synchronize_security_directory(&directory).map_err(|_| RecoveryFailure::Storage)
    }
    pub fn read(&self, path: &Path) -> Result<Vec<u8>, RecoveryFailure> {
        let (directory, name) = parent(path)?;
        let mut file = fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                RecoveryFailure::Missing
            } else {
                RecoveryFailure::Storage
            }
        })?;
        verify(&directory, name, &file)?;
        let length = file.metadata().map_err(|_| RecoveryFailure::Storage)?.len();
        if length == 0 || length > MAX_BUNDLE as u64 {
            return Err(RecoveryFailure::LimitExceeded);
        }
        let mut bytes = Vec::with_capacity(MAX_BUNDLE + 1);
        (&mut file)
            .take((MAX_BUNDLE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| RecoveryFailure::Storage)?;
        verify(&directory, name, &file)?;
        if bytes.len() != length as usize {
            return Err(RecoveryFailure::Storage);
        }
        Ok(bytes)
    }
}

/// Bounded external age identity input remains in zeroizing custody and never reaches diagnostics.
pub(super) fn read_identity(path: &Path) -> Result<age::x25519::Identity, RecoveryFailure> {
    let (directory, name) = parent(path)?;
    let mut file = fs::openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| RecoveryFailure::Storage)?;
    verify(&directory, name, &file)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(129));
    (&mut file)
        .take(129)
        .read_to_end(&mut bytes)
        .map_err(|_| RecoveryFailure::Storage)?;
    verify(&directory, name, &file)?;
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(RecoveryFailure::LimitExceeded);
    }
    std::str::from_utf8(&bytes)
        .map_err(|_| RecoveryFailure::InvalidInput)?
        .trim_end_matches(['\n', '\r'])
        .parse()
        .map_err(|_| RecoveryFailure::InvalidInput)
}
