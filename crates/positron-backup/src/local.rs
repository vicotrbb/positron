mod fault;
mod listing;
mod registry;
#[cfg(feature = "test-support")]
pub use fault::{LocalFault, LocalFaultEffect, LocalFaultPoint};
mod upload;
use crate::{
    ChecksummedBytes, DeleteOutcome, ImmutableObject, MAX_OBJECT_BYTES, ObjectId, ObjectMetadata,
    ObjectRange, PutOutcome, Repository, RepositoryFailure, RepositoryIdentity,
};
use rustix::fs::{self, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Native filesystem credentials are the effective OS identity and protected
/// directory access. No serialized secret or impersonation credential exists.
#[derive(Clone)]
pub struct LocalRepository {
    root: Arc<File>,
    faults: fault::Controller,
    identity: RepositoryIdentity,
    listing: Arc<std::sync::Mutex<listing::State>>,
}
impl std::fmt::Debug for LocalRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalRepository")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
impl LocalRepository {
    #[cfg(feature = "test-support")]
    pub fn with_faults(mut self, faults: Vec<LocalFault>) -> Result<Self, RepositoryFailure> {
        self.faults = fault::Controller::new(faults)?;
        Ok(self)
    }
    pub async fn initialize(
        path: &Path,
        identity: RepositoryIdentity,
    ) -> Result<Self, RepositoryFailure> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let root = open_root(&path)?;
            let current = RepositoryIdentity::local(
                identity.repository_id(),
                identity.instance_id(),
                identity.integrity_fingerprint(),
                &path,
            )?;
            if current != identity {
                return Err(RepositoryFailure::IdentityMismatch);
            }
            let lock = DirectoryLock::new(&root)?;
            let entries = fs::Dir::read_from(&root).map_err(storage)?;
            for entry in entries {
                let entry = entry.map_err(storage)?;
                if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                    return Err(RepositoryFailure::ForeignPrefix);
                }
            }
            let mut file = fs::openat(
                &root,
                "identity",
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(storage)?;
            file.write_all(&identity.encode()).map_err(io_failure)?;
            file.sync_all()
                .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
            root.sync_all()
                .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
            drop(lock);
            Ok(Self {
                root: Arc::new(root),
                faults: fault::Controller::default(),
                identity,
                listing: Arc::new(std::sync::Mutex::new(listing::State::new()?)),
            })
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
    pub async fn attach(
        path: &Path,
        expected: &RepositoryIdentity,
    ) -> Result<Self, RepositoryFailure> {
        let path: PathBuf = path.to_path_buf();
        let expected = expected.clone();
        tokio::task::spawn_blocking(move || {
            let root = open_root(&path)?;
            let identity = read_identity(&root)?;
            if identity != expected {
                return Err(RepositoryFailure::IdentityMismatch);
            }
            let current = RepositoryIdentity::local(
                identity.repository_id(),
                identity.instance_id(),
                identity.integrity_fingerprint(),
                &path,
            )?;
            if current != identity {
                return Err(RepositoryFailure::IdentityMismatch);
            }
            Ok(Self {
                root: Arc::new(root),
                faults: fault::Controller::default(),
                identity,
                listing: Arc::new(std::sync::Mutex::new(listing::State::new()?)),
            })
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
}
#[async_trait::async_trait]
impl Repository for LocalRepository {
    async fn identify(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || {
            let found = read_identity(&root)?;
            if found != expected {
                return Err(RepositoryFailure::IdentityMismatch);
            }
            Ok(found)
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn head(&self, object: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || {
            verify_identity(&root, &expected)?;
            let mut file = open_object(&root, object)?;
            metadata(&mut file, object)
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn read_range(&self, range: ObjectRange) -> Result<ChecksummedBytes, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || {
            verify_identity(&root, &expected)?;
            let mut file = open_object(&root, range.object)?;
            let meta = metadata(&mut file, range.object)?;
            if range
                .offset
                .checked_add(range.length)
                .is_none_or(|end| end > meta.size)
            {
                return Err(RepositoryFailure::InvalidInput);
            }
            file.seek(SeekFrom::Start(range.offset))
                .map_err(io_failure)?;
            let length =
                usize::try_from(range.length).map_err(|_| RepositoryFailure::LimitExceeded)?;
            let mut bytes = vec![0; length];
            file.read_exact(&mut bytes).map_err(io_failure)?;
            Ok(ChecksummedBytes {
                checksum: Sha256::digest(&bytes).into(),
                bytes,
            })
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        let faults = self.faults.clone();
        tokio::task::spawn_blocking(move || {
            let _lock = DirectoryLock::new(&root)?;
            verify_identity(&root, &expected)?;
            match open_object(&root, object.id()) {
                Ok(mut file) => {
                    metadata(&mut file, object.id())?;
                    return Ok(PutOutcome::AlreadyPresent);
                },
                Err(RepositoryFailure::NotFound) => {},
                Err(failure) => return Err(failure),
            }
            let pending = format!("p-{}", object.id().name());
            // A previous interrupted write is never current and can be replaced
            // only under the same content identity and exclusive directory lock.
            match fs::unlinkat(&root, pending.as_str(), fs::AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {},
                Err(error) => return Err(storage(error)),
            }
            let mut file = fs::openat(
                &root,
                pending.as_str(),
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(storage)?;
            file.write_all(object.bytes()).map_err(io_failure)?;
            file.sync_all().map_err(io_failure)?;
            faults.at(fault::LocalFaultPoint::BeforeObjectPublication)?;
            fs::renameat(&root, pending.as_str(), &root, object.id().name().as_str())
                .map_err(storage)?;
            root.sync_all()
                .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
            faults.at(fault::LocalFaultPoint::AfterObjectPublication)?;
            Ok(PutOutcome::Created)
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn delete(&self, object: ObjectId) -> Result<DeleteOutcome, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        let faults = self.faults.clone();
        tokio::task::spawn_blocking(move || {
            let _lock = DirectoryLock::new(&root)?;
            verify_identity(&root, &expected)?;
            match open_object(&root, object) {
                Ok(mut file) => {
                    metadata(&mut file, object)?;
                },
                Err(RepositoryFailure::NotFound) => return Ok(DeleteOutcome::AlreadyAbsent),
                Err(failure) => return Err(failure),
            }
            faults.at(fault::LocalFaultPoint::BeforeDeletion)?;
            fs::unlinkat(&root, object.name().as_str(), fs::AtFlags::empty()).map_err(storage)?;
            root.sync_all()
                .map_err(|_| RepositoryFailure::OutcomeUnknown)?;
            faults.at(fault::LocalFaultPoint::AfterDeletion)?;
            Ok(DeleteOutcome::Deleted)
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }

    async fn registry_head_at(
        &self,
        slot: crate::HeadSlot,
    ) -> Result<Option<crate::RegistryHead>, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || {
            verify_identity(&root, &expected)?;
            registry::read(&root, slot)
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn delete_head_if_version(
        &self,
        slot: crate::HeadSlot,
        version: crate::ObjectVersion,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || registry::delete(&root, &expected, slot, version))
            .await
            .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn compare_and_swap_head_at(
        &self,
        slot: crate::HeadSlot,
        change: crate::RegistryHeadChange,
    ) -> Result<crate::CasOutcome, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        let faults = self.faults.clone();
        tokio::task::spawn_blocking(move || {
            registry::publish(&root, &expected, slot, change, &faults)
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }

    async fn begin_upload(
        &self,
        plan: crate::UploadPlan,
    ) -> Result<crate::UploadState, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || upload::begin(&root, &expected, plan))
            .await
            .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn inspect_upload(
        &self,
        id: crate::UploadId,
    ) -> Result<Option<crate::UploadState>, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || {
            verify_identity(&root, &expected)?;
            Ok(upload::inspect(&root, id)?.map(|(_, state)| state))
        })
        .await
        .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn resume_upload(
        &self,
        part: crate::UploadPart,
    ) -> Result<crate::UploadOutcome, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        let faults = self.faults.clone();
        tokio::task::spawn_blocking(move || upload::resume(&root, &expected, part, &faults))
            .await
            .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn abort_upload(&self, id: crate::UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        tokio::task::spawn_blocking(move || upload::abort(&root, &expected, id))
            .await
            .map_err(|_| RepositoryFailure::Interrupted)?
    }
    async fn list(
        &self,
        request: crate::ListRequest,
    ) -> Result<crate::ListPage, RepositoryFailure> {
        let root = Arc::clone(&self.root);
        let expected = self.identity.clone();
        let state = Arc::clone(&self.listing);
        tokio::task::spawn_blocking(move || listing::list(&root, &expected, &state, request))
            .await
            .map_err(|_| RepositoryFailure::Interrupted)?
    }
}
fn open_root(path: &Path) -> Result<File, RepositoryFailure> {
    let file = fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(storage)?;
    let metadata = file.metadata().map_err(io_failure)?;
    if metadata.mode() & 0o7777 != 0o700 || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(RepositoryFailure::PermissionDenied);
    }
    Ok(file)
}
fn read_identity(root: &File) -> Result<RepositoryIdentity, RepositoryFailure> {
    let directory = root.metadata().map_err(io_failure)?;
    if directory.mode() & 0o7777 != 0o700 || directory.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(RepositoryFailure::PermissionDenied);
    }
    let file = fs::openat(
        root,
        "identity",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(storage)?;
    let metadata = file.metadata().map_err(io_failure)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(RepositoryFailure::CorruptState);
    }
    if metadata.mode() & 0o7777 != 0o600 || metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(RepositoryFailure::PermissionDenied);
    }
    let mut bytes = Vec::with_capacity(109);
    file.take(109).read_to_end(&mut bytes).map_err(io_failure)?;
    RepositoryIdentity::decode(&bytes)
}
struct DirectoryLock {
    _file: File,
}
impl DirectoryLock {
    fn new(root: &File) -> Result<Self, RepositoryFailure> {
        let file = fs::openat(
            root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(storage)?;
        fs::flock(&file, fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| RepositoryFailure::Busy)?;
        Ok(Self { _file: file })
    }
}
fn storage(error: rustix::io::Errno) -> RepositoryFailure {
    match error {
        rustix::io::Errno::NOENT => RepositoryFailure::NotFound,
        rustix::io::Errno::EXIST => RepositoryFailure::AlreadyExists,
        rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => RepositoryFailure::PermissionDenied,
        _ => RepositoryFailure::StorageUnavailable,
    }
}
fn io_failure(error: std::io::Error) -> RepositoryFailure {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => RepositoryFailure::PermissionDenied,
        _ => RepositoryFailure::StorageUnavailable,
    }
}

fn verify_identity(root: &File, expected: &RepositoryIdentity) -> Result<(), RepositoryFailure> {
    if read_identity(root)? != *expected {
        return Err(RepositoryFailure::IdentityMismatch);
    }
    Ok(())
}
fn open_object(root: &File, object: ObjectId) -> Result<File, RepositoryFailure> {
    let file = fs::openat(
        root,
        object.name().as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(storage)?;
    let meta = file.metadata().map_err(io_failure)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 {
        return Err(RepositoryFailure::CorruptState);
    }
    Ok(file)
}
fn metadata(file: &mut File, object: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
    let size = file.metadata().map_err(io_failure)?.len();
    if size > MAX_OBJECT_BYTES {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut observed = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(io_failure)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        if observed > MAX_OBJECT_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        hash.update(buffer.get(..read).ok_or(RepositoryFailure::CorruptState)?);
    }
    let checksum: [u8; 32] = hash.finalize().into();
    if observed != size || checksum != object.checksum() {
        return Err(RepositoryFailure::ChecksumMismatch);
    }
    Ok(ObjectMetadata { size, checksum })
}
