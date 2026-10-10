//! Fresh-root proof consumption and durable one-time key initialization.

use std::fs::File;
use std::io::Read;

use std::os::unix::fs::MetadataExt;

use rustix::fs::{self as unix_fs, AtFlags, Mode, OFlags, RenameFlags};
use zeroize::Zeroize;

use super::acl::{verify_directory_acl, verify_file_acl};
use super::codec::{EncodedLocalKeyFile, SecretRootKey, encode_file_v1, parse_file_v1};
pub(super) use super::security_directory::FreshInitializationRootProof;
use super::{
    LOCAL_KEY_FILE_NAME, LOCAL_KEY_STAGING_FILE_NAME, LocalKeyCreationTime, LocalKeyFailure,
    LocalKeyFailureCode, LocalKeyId, VerifiedLocalKey, initialization_io,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LocalKeyInitializationEvent {
    OpenSecurityDirectory,
    InspectSecurityDirectoryAcl,
    CreateFinalKeyFile,
    RequestEntropy,
    #[cfg(test)]
    PredecessorOpened,
}

pub(super) fn initialize_local_key(
    proof: FreshInitializationRootProof,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    initialization_event(LocalKeyInitializationEvent::OpenSecurityDirectory);
    proof.verify()?;
    let directory = proof.directory();
    initialization_event(LocalKeyInitializationEvent::InspectSecurityDirectoryAcl);
    verify_directory_acl(directory)?;

    initialize_named_local_key(
        directory,
        proof.expected_owner(),
        LOCAL_KEY_FILE_NAME,
        LOCAL_KEY_STAGING_FILE_NAME,
    )
}

pub(super) fn initialize_named_local_key(
    directory: &File,
    expected_owner: u32,
    final_name: &str,
    staging_name: &str,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    if exists(directory, final_name)? {
        initialization_io::synchronize_security_directory(directory).map_err(|_| {
            LocalKeyFailure::new(LocalKeyFailureCode::SynchronizeSecurityDirectoryFailed)
        })?;
        return super::persistence::open_named_local_key_in(directory, final_name);
    }
    if exists(directory, staging_name)? {
        if let Ok(staged) = read_staged_key(directory, expected_owner, staging_name) {
            publish_staged_key(directory, final_name, staging_name)?;
            return Ok(staged);
        }
        remove_staged_key(directory, expected_owner, staging_name)?;
    }

    initialization_event(LocalKeyInitializationEvent::CreateFinalKeyFile);
    let mut file = unix_fs::openat(
        directory,
        staging_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            LocalKeyFailure::new(LocalKeyFailureCode::KeyAlreadyExists)
        } else {
            LocalKeyFailure::new(LocalKeyFailureCode::CreateKeyFileFailed)
        }
    })?;
    verify_named_key_file(directory, &file, expected_owner, staging_name)?;
    verify_file_acl(&file)?;

    initialization_event(LocalKeyInitializationEvent::RequestEntropy);
    let mut key_id_bytes = [0_u8; 16];
    initialization_io::fill_random(&mut key_id_bytes)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::EntropyUnavailable))?;
    let key_id = LocalKeyId::new(key_id_bytes)?;
    let mut root_key_bytes = Box::new([0_u8; 32]);
    if initialization_io::fill_random(root_key_bytes.as_mut()).is_err() {
        root_key_bytes.zeroize();
        return Err(LocalKeyFailure::new(
            LocalKeyFailureCode::EntropyUnavailable,
        ));
    }
    let root_key = SecretRootKey::from_owned(root_key_bytes);
    let creation_seconds = initialization_io::unix_creation_seconds()
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::ClockUnavailable))?;
    let encoded = encode_file_v1(
        key_id,
        LocalKeyCreationTime::from_unix_seconds(creation_seconds),
        root_key,
    )?;
    initialization_io::write_new_key(&mut file, encoded.as_bytes())
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::WriteFailed))?;
    initialization_io::synchronize_key_file(&file)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::SynchronizeKeyFileFailed))?;
    verify_named_key_file(directory, &file, expected_owner, staging_name)?;
    verify_file_acl(&file)?;
    let verified = parse_file_v1(encoded)?;
    drop(file);
    publish_staged_key(directory, final_name, staging_name)?;
    Ok(verified)
}

fn exists(directory: &File, name: &str) -> Result<bool, LocalKeyFailure> {
    match unix_fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile)),
    }
}

fn read_staged_key(
    directory: &File,
    expected_owner: u32,
    staging_name: &str,
) -> Result<VerifiedLocalKey, LocalKeyFailure> {
    let mut file = unix_fs::openat(
        directory,
        staging_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::OpenKeyFileFailed))?;
    verify_named_key_file(directory, &file, expected_owner, staging_name)?;
    verify_file_acl(&file)?;
    let mut encoded = EncodedLocalKeyFile::zeroed();
    file.read_exact(encoded.bytes.as_mut())
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile))?
        != 0
    {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::MalformedFile));
    }
    parse_file_v1(encoded)
}

fn remove_staged_key(
    directory: &File,
    expected_owner: u32,
    staging_name: &str,
) -> Result<(), LocalKeyFailure> {
    let file = unix_fs::openat(
        directory,
        staging_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile))?;
    verify_named_key_file(directory, &file, expected_owner, staging_name)?;
    unix_fs::unlinkat(directory, staging_name, AtFlags::empty())
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::WriteFailed))?;
    initialization_io::synchronize_security_directory(directory)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::SynchronizeSecurityDirectoryFailed))
}

fn publish_staged_key(
    directory: &File,
    final_name: &str,
    staging_name: &str,
) -> Result<(), LocalKeyFailure> {
    unix_fs::renameat_with(
        directory,
        staging_name,
        directory,
        final_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::KeyAlreadyExists))?;
    initialization_io::synchronize_security_directory(directory)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::SynchronizeSecurityDirectoryFailed))
}

pub(super) fn verify_key_file(
    directory: &File,
    file: &File,
    expected_owner: u32,
) -> Result<(), LocalKeyFailure> {
    verify_named_key_file(directory, file, expected_owner, LOCAL_KEY_FILE_NAME)
}

pub(super) fn verify_named_key_file(
    directory: &File,
    file: &File,
    expected_owner: u32,
    name: &str,
) -> Result<(), LocalKeyFailure> {
    let metadata = file
        .metadata()
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile))?;
    let entry = unix_fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile))?;
    let safe = metadata.file_type().is_file()
        && metadata.uid() == expected_owner
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
        && entry.st_dev as u64 == metadata.dev()
        && entry.st_ino == metadata.ino()
        && entry.st_nlink == 1;
    if safe {
        Ok(())
    } else {
        Err(LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile))
    }
}

pub(super) fn initialization_event(_event: LocalKeyInitializationEvent) {
    #[cfg(test)]
    {
        INITIALIZATION_EVENTS.with(|events| events.borrow_mut().push(_event));
        INITIALIZATION_EVENT_ACTION.with(|action| {
            let mut current = action.borrow_mut().take();
            if let Some(callback) = current.as_mut() {
                callback(_event);
            }
            *action.borrow_mut() = current;
        });
    }
}

#[cfg(test)]
type InitializationEventAction = Box<dyn FnMut(LocalKeyInitializationEvent)>;

#[cfg(test)]
thread_local! {
    static INITIALIZATION_EVENTS: std::cell::RefCell<Vec<LocalKeyInitializationEvent>> = const { std::cell::RefCell::new(Vec::new()) };
    static INITIALIZATION_EVENT_ACTION: std::cell::RefCell<Option<InitializationEventAction>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn capture_initialization_events<T>(
    action: impl FnOnce() -> T,
) -> (T, Vec<LocalKeyInitializationEvent>) {
    INITIALIZATION_EVENTS.with(|events| events.borrow_mut().clear());
    let result = action();
    let events = INITIALIZATION_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()));
    (result, events)
}

#[cfg(test)]
pub(super) fn with_initialization_event_action<T>(
    action: impl FnMut(LocalKeyInitializationEvent) + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    INITIALIZATION_EVENT_ACTION.with(|injected| {
        let previous = injected.replace(Some(Box::new(action)));
        let result = operation();
        injected.replace(previous);
        result
    })
}

/// Restores authenticated existing key material; it never creates replacement entropy.
pub(super) fn publish_recovered_local_key(
    directory: &File,
    key: &VerifiedLocalKey,
    final_name: &str,
    staging_name: &str,
) -> Result<(), LocalKeyFailure> {
    let metadata = directory
        .metadata()
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::UnsafeSecurityDirectory))?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err(LocalKeyFailure::new(
            LocalKeyFailureCode::UnsafeSecurityDirectory,
        ));
    }
    verify_directory_acl(directory)?;
    if exists(directory, final_name)? {
        return Err(LocalKeyFailure::new(LocalKeyFailureCode::KeyAlreadyExists));
    }
    if exists(directory, staging_name)? {
        let staged = read_staged_key(directory, metadata.uid(), staging_name)?;
        if staged.evidence() != key.evidence() {
            return Err(LocalKeyFailure::new(LocalKeyFailureCode::IdentityMismatch));
        }
        let file = unix_fs::openat(
            directory,
            staging_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::UnsafeKeyFile))?;
        verify_named_key_file(directory, &file, metadata.uid(), staging_name)?;
        verify_file_acl(&file)?;
        initialization_io::synchronize_key_file(&file)
            .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::SynchronizeKeyFileFailed))?;
        return publish_staged_key(directory, final_name, staging_name);
    }
    let mut file = unix_fs::openat(
        directory,
        staging_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::CreateKeyFileFailed))?;
    verify_named_key_file(directory, &file, metadata.uid(), staging_name)?;
    verify_file_acl(&file)?;
    let bytes = key.root_key.0.expose_to_backend();
    let encoded = encode_file_v1(
        key.evidence.key_id,
        key.evidence.creation_time,
        SecretRootKey::from_owned(Box::new(*bytes)),
    )?;
    initialization_io::write_new_key(&mut file, encoded.as_bytes())
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::WriteFailed))?;
    initialization_io::synchronize_key_file(&file)
        .map_err(|_| LocalKeyFailure::new(LocalKeyFailureCode::SynchronizeKeyFileFailed))?;
    verify_named_key_file(directory, &file, metadata.uid(), staging_name)?;
    verify_file_acl(&file)?;
    drop(file);
    publish_staged_key(directory, final_name, staging_name)
}
