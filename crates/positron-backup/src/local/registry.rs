use super::*;
use crate::{CasOutcome, MAX_REGISTRY_HEAD_BYTES, ObjectVersion, RegistryHead, RegistryHeadChange};

pub(super) fn read(
    root: &File,
    slot: crate::HeadSlot,
) -> Result<Option<RegistryHead>, RepositoryFailure> {
    let file = match fs::openat(
        root,
        slot.name().as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(storage(error)),
    };
    #[cfg(test)]
    super::read_interleave::after_open(root)?;
    let meta = file.metadata().map_err(io_failure)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 {
        return Err(RepositoryFailure::CorruptState);
    }
    let mut bytes = Vec::new();
    file.take((MAX_REGISTRY_HEAD_BYTES + 41) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_failure)?;
    RegistryHead::decode_frame(&bytes).map(Some)
}
pub(super) fn publish(
    root: &File,
    expected: &RepositoryIdentity,
    slot: crate::HeadSlot,
    change: RegistryHeadChange,
    faults: &fault::Controller,
) -> Result<CasOutcome, RepositoryFailure> {
    let _lock = DirectoryLock::new(root)?;
    verify_identity(root, expected)?;
    let current = read(root, slot)?.map(|head| head.version());
    if current != change.expected {
        return Ok(CasOutcome::Conflict(current));
    }
    let pending = format!("p-{}", slot.name());
    match fs::unlinkat(root, pending.as_str(), fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {},
        Err(error) => return Err(storage(error)),
    }
    let mut file = fs::openat(
        root,
        pending.as_str(),
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(storage)?;
    file.write_all(&change.successor.encode_frame())
        .map_err(io_failure)?;
    file.sync_all().map_err(io_failure)?;
    faults.at(fault::LocalFaultPoint::BeforeRegistryPublication)?;
    fs::renameat(root, pending.as_str(), root, slot.name().as_str()).map_err(storage)?;
    root.sync_all()
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    faults.at(fault::LocalFaultPoint::AfterRegistryPublication)?;
    Ok(CasOutcome::Published(change.successor.version()))
}

pub(super) fn delete(
    root: &File,
    expected: &RepositoryIdentity,
    slot: crate::HeadSlot,
    version: ObjectVersion,
) -> Result<DeleteOutcome, RepositoryFailure> {
    let _lock = DirectoryLock::new(root)?;
    verify_identity(root, expected)?;
    let Some(current) = read(root, slot)? else {
        return Ok(DeleteOutcome::AlreadyAbsent);
    };
    if current.version() != version {
        return Err(RepositoryFailure::PreconditionFailed);
    }
    fs::unlinkat(root, slot.name().as_str(), fs::AtFlags::empty()).map_err(storage)?;
    root.sync_all()
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    Ok(DeleteOutcome::Deleted)
}
