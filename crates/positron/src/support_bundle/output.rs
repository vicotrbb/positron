use std::{
    ffi::OsString,
    fs::File,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use rand::{RngCore, rngs::OsRng};
use rustix::fs::{self as unix_fs, AtFlags, Mode, OFlags};

/// An output parent opened component-by-component without following a
/// symlink. Keeping this handle open binds creation and publication to the
/// directory that passed the managed-root check.
pub(super) struct OutputDestination {
    directory: File,
    name: OsString,
    // Keep the checked managed roots bound for the complete export operation.
    _data_root: File,
    _secrets_root: File,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

pub(super) fn prepare_destination(
    output: &Path,
    data_root: &Path,
    secrets_root: &Path,
) -> Result<OutputDestination, ()> {
    prepare_destination_after_managed_roots(output, data_root, secrets_root, || {})
}

#[cfg(test)]
pub(super) fn prepare_destination_with_after_managed_root_hook(
    output: &Path,
    data_root: &Path,
    secrets_root: &Path,
    hook: impl FnOnce(),
) -> Result<OutputDestination, ()> {
    prepare_destination_after_managed_roots(output, data_root, secrets_root, hook)
}

fn prepare_destination_after_managed_roots(
    output: &Path,
    data_root: &Path,
    secrets_root: &Path,
    after_managed_roots: impl FnOnce(),
) -> Result<OutputDestination, ()> {
    let output = absolute_path(output)?;
    let parent = output.parent().ok_or(())?;
    // Canonicalization supplies a stable, absolute component sequence, but it
    // is not a security decision. Each path is then opened with NOFOLLOW and
    // identities are compared after all handles are bound.
    let data_root = std::fs::canonicalize(data_root).map_err(|_| ())?;
    let secrets_root = std::fs::canonicalize(secrets_root).map_err(|_| ())?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|_| ())?;
    let name = output.file_name().ok_or(())?.to_os_string();
    let data_root = open_directory_without_symlinks(&data_root, &[])?;
    let secrets_root = open_directory_without_symlinks(&secrets_root, &[])?;
    let forbidden = [
        directory_identity(&data_root)?,
        directory_identity(&secrets_root)?,
    ];
    after_managed_roots();
    let directory = open_directory_without_symlinks(&canonical_parent, &forbidden)?;
    Ok(OutputDestination {
        directory,
        name,
        _data_root: data_root,
        _secrets_root: secrets_root,
    })
}

pub(super) fn write_new_owner_only(
    destination: &OutputDestination,
    bytes: &[u8],
) -> Result<(), ()> {
    write_new_owner_only_after_close(destination, bytes, || {})
}

#[cfg(test)]
pub(super) fn write_new_owner_only_with_after_close_hook(
    destination: &OutputDestination,
    bytes: &[u8],
    after_close: impl FnOnce(),
) -> Result<(), ()> {
    write_new_owner_only_after_close(destination, bytes, after_close)
}

fn write_new_owner_only_after_close(
    destination: &OutputDestination,
    bytes: &[u8],
    after_close: impl FnOnce(),
) -> Result<(), ()> {
    let temporary = create_private_temporary_directory(&destination.directory)?;
    let mut file = match unix_fs::openat(
        &temporary.directory,
        "archive",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(file) => File::from(file),
        Err(_) => {
            remove_empty_private_temporary_directory(&destination.directory, temporary)?;
            return Err(());
        },
    };
    let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if write_result.is_err() {
        remove_private_temporary_directory(&destination.directory, temporary)?;
        return Err(());
    }
    after_close();
    if unix_fs::linkat(
        &temporary.directory,
        "archive",
        &destination.directory,
        &destination.name,
        AtFlags::empty(),
    )
    .is_err()
    {
        remove_private_temporary_directory(&destination.directory, temporary)?;
        return Err(());
    }
    remove_private_temporary_directory(&destination.directory, temporary)?;
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf, ()> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map_err(|_| ())
            .map(|cwd| cwd.join(path))
    }
}

fn open_directory_without_symlinks(
    path: &Path,
    forbidden: &[DirectoryIdentity],
) -> Result<File, ()> {
    let mut current = File::open("/").map_err(|_| ())?;
    for component in path.components() {
        match component {
            Component::RootDir => {},
            Component::Normal(name) => {
                current = unix_fs::openat(
                    &current,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)
                .map_err(|_| ())?;
                if forbidden.contains(&directory_identity(&current)?) {
                    return Err(());
                }
            },
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => return Err(()),
        }
    }
    Ok(current)
}

fn directory_identity(directory: &File) -> Result<DirectoryIdentity, ()> {
    let metadata = directory.metadata().map_err(|_| ())?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

struct PrivateTemporaryDirectory {
    directory: File,
    name: OsString,
}

fn create_private_temporary_directory(parent: &File) -> Result<PrivateTemporaryDirectory, ()> {
    const ATTEMPTS: usize = 8;
    for _ in 0..ATTEMPTS {
        let mut bytes = [0_u8; 16];
        OsRng.try_fill_bytes(&mut bytes).map_err(|_| ())?;
        let name = OsString::from(format!(".positron-export-{}", hex(&bytes)?));
        if unix_fs::mkdirat(parent, &name, Mode::RUSR | Mode::WUSR | Mode::XUSR).is_err() {
            continue;
        }
        let directory = match unix_fs::openat(
            parent,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => File::from(directory),
            Err(_) => {
                unix_fs::unlinkat(parent, &name, AtFlags::REMOVEDIR).map_err(|_| ())?;
                return Err(());
            },
        };
        return Ok(PrivateTemporaryDirectory { directory, name });
    }
    Err(())
}

fn remove_private_temporary_directory(
    parent: &File,
    temporary: PrivateTemporaryDirectory,
) -> Result<(), ()> {
    unix_fs::unlinkat(&temporary.directory, "archive", AtFlags::empty()).map_err(|_| ())?;
    drop(temporary.directory);
    unix_fs::unlinkat(parent, &temporary.name, AtFlags::REMOVEDIR).map_err(|_| ())
}

fn remove_empty_private_temporary_directory(
    parent: &File,
    temporary: PrivateTemporaryDirectory,
) -> Result<(), ()> {
    drop(temporary.directory);
    unix_fs::unlinkat(parent, &temporary.name, AtFlags::REMOVEDIR).map_err(|_| ())
}

fn hex(bytes: &[u8]) -> Result<String, ()> {
    let mut rendered = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut rendered, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(rendered)
}
