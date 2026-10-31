//! Explicit preparation of two configured terminal roots, without initializing an instance.
use super::*;
use std::{ffi::OsString, path::Component};

struct RootPlan {
    parent: File,
    leaf: OsString,
    existing: Option<File>,
}

impl InstanceBootstrapStorage {
    /// Create missing terminal roots with private custody; never repair existing paths.
    /// Parents must already exist. This creates no instance, key, Catalog or claim.
    pub fn prepare(
        data: &Path,
        secrets: &Path,
        qualification: MountQualification,
    ) -> Result<Self, BootstrapStorageFailure> {
        let data = checked_path(data)?;
        let secrets = checked_path(secrets)?;
        if data.starts_with(&secrets) || secrets.starts_with(&data) {
            return Err(BootstrapStorageFailure::InvalidRoots);
        }
        // Validate both parents and all existing leaves before creating either.
        let data_plan = plan(&data)?;
        let secrets_plan = plan(&secrets)?;
        for root in [&data_plan, &secrets_plan] {
            if let Some(directory) = &root.existing {
                verify_private(directory)?;
            }
        }
        if let (Some(data), Some(secrets)) = (&data_plan.existing, &secrets_plan.existing) {
            let data = data
                .metadata()
                .map_err(|_| BootstrapStorageFailure::Unavailable)?;
            let secrets = secrets
                .metadata()
                .map_err(|_| BootstrapStorageFailure::Unavailable)?;
            if data.dev() == secrets.dev() && data.ino() == secrets.ino() {
                return Err(BootstrapStorageFailure::InvalidRoots);
            }
        }
        let data_directory = prepare(data_plan)?;
        let secrets_directory = prepare(secrets_plan)?;
        let identity = |directory: &File| {
            directory
                .metadata()
                .map(|metadata| RootIdentity {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                })
                .map_err(|_| BootstrapStorageFailure::Unavailable)
        };
        // Pin the no-follow descriptors already validated above; never canonicalize
        // a possibly replaced pathname into a different root after preparation.
        Ok(Self {
            data,
            secrets,
            data_identity: identity(&data_directory)?,
            secrets_identity: identity(&secrets_directory)?,
            qualification,
        })
    }
}

fn checked_path(path: &Path) -> Result<PathBuf, BootstrapStorageFailure> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 4096
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        || path.file_name().is_none()
    {
        return Err(BootstrapStorageFailure::InvalidRoots);
    }
    Ok(path.components().collect())
}

fn plan(path: &Path) -> Result<RootPlan, BootstrapStorageFailure> {
    let leaf = path
        .file_name()
        .ok_or(BootstrapStorageFailure::InvalidRoots)?
        .to_owned();
    let mut parent = File::open("/").map_err(|_| BootstrapStorageFailure::Unavailable)?;
    for component in path
        .parent()
        .ok_or(BootstrapStorageFailure::InvalidRoots)?
        .components()
    {
        if let Component::Normal(name) = component {
            parent =
                open_directory(&parent, name).map_err(|_| BootstrapStorageFailure::InvalidRoots)?;
        }
    }
    let existing = match open_directory(&parent, &leaf) {
        Ok(directory) => Some(directory),
        Err(rustix::io::Errno::NOENT) => None,
        Err(_) => return Err(BootstrapStorageFailure::UnsafeOrCorrupt),
    };
    Ok(RootPlan {
        parent,
        leaf,
        existing,
    })
}

fn open_directory(parent: &File, leaf: &std::ffi::OsStr) -> Result<File, rustix::io::Errno> {
    unix_fs::openat(
        parent,
        leaf,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

fn prepare(plan: RootPlan) -> Result<File, BootstrapStorageFailure> {
    if let Some(directory) = plan.existing {
        verify_private(&directory)?;
        return Ok(directory);
    }
    let created = match unix_fs::mkdirat(
        &plan.parent,
        &plan.leaf,
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    ) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(_) => return Err(BootstrapStorageFailure::Unavailable),
    };
    let directory = open_directory(&plan.parent, &plan.leaf)
        .map_err(|_| BootstrapStorageFailure::UnsafeOrCorrupt)?;
    if created {
        // A setgid CSI parent produces mode 2700. Only this newly created inode
        // may lose inherited setgid; an existing unsafe root is never repaired.
        let metadata = directory
            .metadata()
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
        }
        unix_fs::fchmod(&directory, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|_| BootstrapStorageFailure::Unavailable)?;
        synchronize(&directory)?;
        synchronize(&plan.parent)?;
    }
    verify_private(&directory)?;
    Ok(directory)
}

fn verify_private(directory: &File) -> Result<(), BootstrapStorageFailure> {
    let metadata = directory
        .metadata()
        .map_err(|_| BootstrapStorageFailure::Unavailable)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
    }
    if !crate::data_protection::has_private_directory_acl(directory) {
        return Err(BootstrapStorageFailure::UnsafeOrCorrupt);
    }
    Ok(())
}
