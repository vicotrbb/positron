use super::*;
use rustix::fs::{AtFlags, Dir, RenameFlags};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
pub(super) fn error(_: std::io::Error) -> CatalogFailure {
    fail(CatalogFailureCode::StorageUnavailable)
}
fn errno(_: rustix::io::Errno) -> CatalogFailure {
    fail(CatalogFailureCode::StorageUnavailable)
}
pub(super) fn name(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(crate) fn file_name(identity: [u8; 32]) -> String {
    format!("f-{}", name(&identity))
}
pub(super) fn directory(parent: &File, name: &str, create: bool) -> Result<File, CatalogFailure> {
    if create {
        match unix_fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {},
            Err(failure) => return Err(errno(failure)),
        }
    }
    let directory = unix_fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(errno)?;
    let metadata = directory.metadata().map_err(error)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(fail(CatalogFailureCode::IntegrityCorruption));
    }
    if create {
        parent.sync_all().map_err(error)?;
    }
    Ok(directory)
}
pub(super) fn capture_directory(
    root: &File,
    operation: [u8; 16],
    create: bool,
) -> Result<File, CatalogFailure> {
    if operation == [0; 16] {
        return Err(fail(CatalogFailureCode::InvalidInput));
    }
    let parent = directory(root, "backup-captures", create)?;
    directory(&parent, &name(&operation), create)
}
pub(crate) fn open(directory: &File, name: &str) -> Result<File, CatalogFailure> {
    let file = unix_fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(errno)?;
    let metadata = file.metadata().map_err(error)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(fail(CatalogFailureCode::IntegrityCorruption));
    }
    Ok(file)
}
pub(super) fn exists(directory: &File, name: &str) -> Result<bool, CatalogFailure> {
    match unix_fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(failure) => Err(errno(failure)),
    }
}
pub(super) fn write(directory: &File, name: &str, bytes: &[u8]) -> Result<(), CatalogFailure> {
    let mut file = unix_fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(errno)?;
    file.write_all(bytes).map_err(error)?;
    file.sync_all().map_err(error)?;
    directory.sync_all().map_err(error)
}
pub(super) fn publish_index(directory: &File, bytes: &[u8]) -> Result<(), CatalogFailure> {
    write(directory, "index.partial", bytes)?;
    unix_fs::renameat_with(
        directory,
        "index.partial",
        directory,
        "index",
        RenameFlags::NOREPLACE,
    )
    .map_err(errno)?;
    directory.sync_all().map_err(error)
}
pub(super) fn read(
    directory: &File,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, CatalogFailure> {
    let mut file = open(directory, name)?;
    let length = usize::try_from(file.metadata().map_err(error)?.len())
        .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
    if length == 0 || length > maximum {
        return Err(fail(CatalogFailureCode::LimitExceeded));
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(error)?;
    Ok(bytes)
}
pub(super) fn clear_incomplete(directory: &File) -> Result<bool, CatalogFailure> {
    let mut entries = Dir::read_from(directory).map_err(errno)?;
    let mut count = 0;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(errno)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." || name == b"index" {
            continue;
        }
        let metadata = name.len() == 66
            && name.starts_with(b"f-")
            && name
                .get(2..)
                .is_some_and(|suffix| suffix.iter().all(u8::is_ascii_hexdigit));
        let segment = (name.len() == 40 && name.ends_with(b".segment")
            || name.len() == 41 && name.ends_with(b".frontier"))
            && name
                .get(..32)
                .is_some_and(|prefix| prefix.iter().all(u8::is_ascii_hexdigit));
        let flags = if name == b"active" {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        if name != b"index.partial"
            && name != b"active"
            && name != b"registry"
            && !metadata
            && !segment
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        unix_fs::unlinkat(directory, name, flags).map_err(errno)?;
        if name == b"registry" {
            directory.sync_all().map_err(error)?;
            super::super::storage::after_backup_capture_registry_removal()?;
        }
        count += 1;
        if count == 32 {
            directory.sync_all().map_err(error)?;
            return Ok(false);
        }
    }
    directory.sync_all().map_err(error)?;
    Ok(true)
}

/// Reclaims at most 32 obsolete continuation generations, retaining the exact
/// authoritative predecessor and an idempotent unpublished proposal.
pub(super) fn retain_verification_generations(
    directory: &File,
    predecessor: Option<[u8; 32]>,
    proposal: [u8; 32],
) -> Result<bool, CatalogFailure> {
    let predecessor = predecessor.map(file_name);
    let proposal = file_name(proposal);
    let mut entries = Dir::read_from(directory).map_err(errno)?;
    let mut removed = 0usize;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(errno)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b".." | b"index") {
            continue;
        }
        if name.len() != 66
            || !name.starts_with(b"f-")
            || !name
                .get(2..)
                .is_some_and(|suffix| suffix.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        if name == proposal.as_bytes()
            || predecessor
                .as_ref()
                .is_some_and(|value| name == value.as_bytes())
        {
            continue;
        }
        unix_fs::unlinkat(directory, name, AtFlags::empty()).map_err(errno)?;
        removed += 1;
        if removed == 32 {
            directory.sync_all().map_err(error)?;
            return Ok(false);
        }
    }
    directory.sync_all().map_err(error)?;
    Ok(true)
}

pub(super) fn discard_unpublished_verification_file(
    directory: &File,
    identity: [u8; 32],
) -> Result<(), CatalogFailure> {
    let name = file_name(identity);
    // Unsafe ownership/modes or a link remain an integrity failure, never repair.
    drop(open(directory, &name)?);
    unix_fs::unlinkat(directory, name.as_str(), AtFlags::empty()).map_err(errno)?;
    directory.sync_all().map_err(error)
}
pub(super) fn has_captures(root: &File) -> Result<bool, CatalogFailure> {
    match unix_fs::statat(root, "backup-captures", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(failure) => return Err(errno(failure)),
        Ok(_) => {},
    }
    let parent = directory(root, "backup-captures", false)?;
    let mut entries = Dir::read_from(&parent).map_err(errno)?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(errno)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if name.len() != 32 || !name.iter().all(u8::is_ascii_hexdigit) {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        // Every unfinished operation, including a crash before its index, is
        // managed key-bearing state until its exact cleanup completes.
        return Ok(true);
    }
    Ok(false)
}
pub(super) fn capture_exists(root: &File, operation: [u8; 16]) -> Result<bool, CatalogFailure> {
    if operation == [0; 16] {
        return Err(fail(CatalogFailureCode::InvalidInput));
    }
    match unix_fs::statat(root, "backup-captures", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(failure) => return Err(errno(failure)),
        Ok(_) => {},
    }
    let parent = directory(root, "backup-captures", false)?;
    match unix_fs::statat(&parent, name(&operation), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(failure) => Err(errno(failure)),
    }
}
pub(super) fn release(root: &File, operation: [u8; 16]) -> Result<bool, CatalogFailure> {
    let parent = directory(root, "backup-captures", false)?;
    let name = name(&operation);
    match unix_fs::statat(&parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(true),
        Err(failure) => return Err(errno(failure)),
        Ok(_) => {},
    }
    let capture = directory(&parent, &name, false)?;
    if !clear_incomplete(&capture)? {
        return Ok(false);
    }
    match unix_fs::unlinkat(&capture, "index", AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {},
        Err(failure) => return Err(errno(failure)),
    }
    capture.sync_all().map_err(error)?;
    unix_fs::unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR).map_err(errno)?;
    parent.sync_all().map_err(error)?;
    Ok(true)
}
