use super::*;
use crate::{UploadId, UploadOutcome, UploadPart, UploadPlan, UploadState};
const HEADER: u64 = 88;
fn header(state: UploadState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(88);
    bytes.extend_from_slice(b"POSUPL01");
    bytes.extend_from_slice(&state.plan.object.checksum());
    bytes.extend_from_slice(&state.plan.size.to_be_bytes());
    bytes.extend_from_slice(&state.written.to_be_bytes());
    bytes.extend_from_slice(&state.checksum);
    bytes
}
fn pending_file(root: &File, name: &str) -> Result<File, RepositoryFailure> {
    match fs::unlinkat(root, name, fs::AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {},
        Err(error) => return Err(storage(error)),
    }
    fs::openat(
        root,
        name,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(storage)
}
pub(super) fn inspect(
    root: &File,
    id: UploadId,
) -> Result<Option<(File, UploadState)>, RepositoryFailure> {
    inspect_named(root, id, &id.name())
}
fn inspect_named(
    root: &File,
    id: UploadId,
    name: &str,
) -> Result<Option<(File, UploadState)>, RepositoryFailure> {
    let mut file = match fs::openat(
        root,
        name,
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
    let mut bytes = [0; 88];
    file.read_exact(&mut bytes)
        .map_err(|_| RepositoryFailure::CorruptState)?;
    fn field<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], RepositoryFailure> {
        bytes
            .get(start..start + N)
            .and_then(|value| value.try_into().ok())
            .ok_or(RepositoryFailure::CorruptState)
    }
    if bytes.get(..8) != Some(&b"POSUPL01"[..]) {
        return Err(RepositoryFailure::CorruptState);
    }
    let plan = UploadPlan::new(
        ObjectId::from_checksum(field(&bytes, 8)?),
        u64::from_be_bytes(field(&bytes, 40)?),
    )
    .map_err(|_| RepositoryFailure::CorruptState)?;
    let state = UploadState {
        plan,
        written: u64::from_be_bytes(field(&bytes, 48)?),
        checksum: field(&bytes, 56)?,
    };
    if state.id() != id || state.written > plan.size || meta.len() != HEADER + state.written {
        return Err(RepositoryFailure::CorruptState);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut observed = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(io_failure)?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        if observed > plan.size {
            return Err(RepositoryFailure::CorruptState);
        }
        hash.update(buffer.get(..count).ok_or(RepositoryFailure::CorruptState)?);
    }
    if observed != state.written || <[u8; 32]>::from(hash.finalize()) != state.checksum {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    Ok(Some((file, state)))
}
pub(super) fn begin(
    root: &File,
    expected: &RepositoryIdentity,
    plan: UploadPlan,
    faults: &fault::Controller,
) -> Result<UploadState, RepositoryFailure> {
    let _lock = DirectoryLock::new(root)?;
    verify_identity(root, expected)?;
    match open_object(root, plan.object) {
        Ok(mut file) => {
            let meta = metadata(&mut file, plan.object)?;
            if meta.size != plan.size {
                return Err(RepositoryFailure::InvalidInput);
            }
            cleanup_upload(root, plan.id())?;
            return Ok(UploadState {
                plan,
                written: plan.size,
                checksum: plan.object.checksum(),
            });
        },
        Err(RepositoryFailure::NotFound) => {},
        Err(failure) => return Err(failure),
    }
    if let Some((mut file, state)) = inspect(root, plan.id())? {
        if state.complete() {
            publish_completed(root, &mut file, state, faults)?;
        }
        return Ok(state);
    }
    let state = UploadState {
        plan,
        written: 0,
        checksum: Sha256::digest([]).into(),
    };
    let pending = format!("p-{}", plan.id().name());
    let mut file = pending_file(root, &pending)?;
    file.write_all(&header(state)).map_err(io_failure)?;
    file.sync_all().map_err(io_failure)?;
    faults.at(fault::LocalFaultPoint::BeforeUploadPublication)?;
    fs::renameat(root, pending.as_str(), root, plan.id().name().as_str()).map_err(storage)?;
    root.sync_all()
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    Ok(state)
}
pub(super) fn resume(
    root: &File,
    expected: &RepositoryIdentity,
    part: UploadPart,
    faults: &fault::Controller,
) -> Result<UploadOutcome, RepositoryFailure> {
    let _lock = DirectoryLock::new(root)?;
    verify_identity(root, expected)?;
    match open_object(root, part.state.plan.object) {
        Ok(mut file) => {
            if metadata(&mut file, part.state.plan.object)?.size != part.state.plan.size {
                return Err(RepositoryFailure::InvalidInput);
            }
            cleanup_upload(root, part.state.id())?;
            return Ok(UploadOutcome::Complete(PutOutcome::AlreadyPresent));
        },
        Err(RepositoryFailure::NotFound) => {},
        Err(failure) => return Err(failure),
    }
    let (mut previous, current) =
        inspect(root, part.state.id())?.ok_or(RepositoryFailure::NotFound)?;
    if current != part.state {
        return Err(RepositoryFailure::PreconditionFailed);
    }
    let pending = format!("p-{}", current.id().name());
    let mut file = pending_file(root, &pending)?;
    file.write_all(&[0; 88]).map_err(io_failure)?;
    previous.seek(SeekFrom::Start(HEADER)).map_err(io_failure)?;
    let copied =
        std::io::copy(&mut previous.take(current.written), &mut file).map_err(io_failure)?;
    if copied != current.written {
        return Err(RepositoryFailure::CorruptState);
    }
    file.write_all(&part.bytes).map_err(io_failure)?;
    let written = current
        .written
        .checked_add(part.bytes.len() as u64)
        .ok_or(RepositoryFailure::LimitExceeded)?;
    file.seek(SeekFrom::Start(HEADER)).map_err(io_failure)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut observed = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(io_failure)?;
        if count == 0 {
            break;
        }
        observed += count as u64;
        if observed > written {
            return Err(RepositoryFailure::CorruptState);
        }
        hash.update(buffer.get(..count).ok_or(RepositoryFailure::CorruptState)?);
    }
    if observed != written {
        return Err(RepositoryFailure::CorruptState);
    }
    let state = UploadState {
        plan: current.plan,
        written,
        checksum: hash.finalize().into(),
    };
    if state.complete() && state.checksum != state.plan.object.checksum() {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    file.seek(SeekFrom::Start(0)).map_err(io_failure)?;
    file.write_all(&header(state)).map_err(io_failure)?;
    file.sync_all().map_err(io_failure)?;
    faults.at(fault::LocalFaultPoint::BeforeUploadPublication)?;
    fs::renameat(root, pending.as_str(), root, current.id().name().as_str()).map_err(storage)?;
    root.sync_all()
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    faults.at(fault::LocalFaultPoint::AfterUploadPublication)?;
    if !state.complete() {
        return Ok(UploadOutcome::Pending(state));
    }
    publish_completed(root, &mut file, state, faults)?;
    Ok(UploadOutcome::Complete(PutOutcome::Created))
}
fn publish_completed(
    root: &File,
    file: &mut File,
    state: UploadState,
    faults: &fault::Controller,
) -> Result<(), RepositoryFailure> {
    if !state.complete() || state.checksum != state.plan.object.checksum() {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    let object_pending = format!("p-{}", state.plan.object.name());
    let mut object = pending_file(root, &object_pending)?;
    file.seek(SeekFrom::Start(HEADER)).map_err(io_failure)?;
    let copied = std::io::copy(&mut file.take(state.written), &mut object).map_err(io_failure)?;
    if copied != state.written {
        return Err(RepositoryFailure::CorruptState);
    }
    object.sync_all().map_err(io_failure)?;
    fs::renameat(
        root,
        object_pending.as_str(),
        root,
        state.plan.object.name().as_str(),
    )
    .map_err(storage)?;
    root.sync_all()
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    faults.at(fault::LocalFaultPoint::AfterObjectPublication)?;
    fs::unlinkat(root, state.id().name().as_str(), fs::AtFlags::empty())
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    root.sync_all()
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    Ok(())
}
pub(super) fn abort(
    root: &File,
    expected: &RepositoryIdentity,
    id: UploadId,
) -> Result<DeleteOutcome, RepositoryFailure> {
    let _lock = DirectoryLock::new(root)?;
    verify_identity(root, expected)?;
    cleanup_upload(root, id)
}
fn cleanup_upload(root: &File, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
    let current = id.name();
    let pending = format!("p-{current}");
    // Validate both exact owned records before removing either. A malformed
    // or foreign staging file remains conservative evidence, not cleanup work.
    let (current_present, pending_present) = (
        inspect_named(root, id, &current)?.is_some(),
        inspect_named(root, id, &pending)?.is_some(),
    );
    if !current_present && !pending_present {
        return Ok(DeleteOutcome::AlreadyAbsent);
    }
    for (name, exists) in [(current, current_present), (pending, pending_present)] {
        if exists {
            fs::unlinkat(root, name.as_str(), fs::AtFlags::empty())
                .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
        }
    }
    root.sync_all()
        .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
    Ok(DeleteOutcome::Deleted)
}
