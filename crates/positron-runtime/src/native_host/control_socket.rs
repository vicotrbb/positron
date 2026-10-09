//! Crash-safe reclamation of an owner-only control socket.

use std::fs::{self, Metadata};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, connect, socket};

use crate::ListenerFailure;

pub(super) fn bind(path: &Path) -> Result<UnixListener, ListenerFailure> {
    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            let _reclamation_guard = reclaim(path)?;
            UnixListener::bind(path).map_err(|_| ListenerFailure::BindUnavailable)
        },
        Err(_) => Err(ListenerFailure::BindUnavailable),
    }
}

fn reclaim(path: &Path) -> Result<fs::File, ListenerFailure> {
    let unavailable = || ListenerFailure::BindUnavailable;
    let parent = path.parent().ok_or_else(unavailable)?;
    let directory = fs::symlink_metadata(parent).map_err(|_| unavailable())?;
    let socket_metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    let owner = rustix::process::geteuid().as_raw();
    if !directory.file_type().is_dir()
        || (directory.uid() != owner && directory.uid() != 0)
        || directory.mode() & 0o022 != 0
        || !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != owner
        || socket_metadata.mode() & 0o7777 != 0o600
    {
        return Err(unavailable());
    }
    // Serialize participating same-owner startups through rebind without a
    // persistent sidecar. An unsupported or busy directory lock fails closed.
    let directory_handle = fs::File::open(parent).map_err(|_| unavailable())?;
    rustix::fs::flock(
        &directory_handle,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|_| unavailable())?;
    if !same_identity_and_metadata(
        &directory,
        &directory_handle.metadata().map_err(|_| unavailable())?,
    ) {
        return Err(unavailable());
    }
    // A nonblocking probe cannot hang behind a live listener's full backlog.
    // Only an explicit refusal proves that this pathname has no active peer;
    // successful, in-progress, permission-denied, and vanished probes all fail closed.
    let probe = socket(AddressFamily::UNIX, SocketType::STREAM, None).map_err(|_| unavailable())?;
    rustix::io::fcntl_setfd(&probe, rustix::io::FdFlags::CLOEXEC).map_err(|_| unavailable())?;
    let probe = UnixStream::from(probe);
    probe.set_nonblocking(true).map_err(|_| unavailable())?;
    let address = SocketAddrUnix::new(path).map_err(|_| unavailable())?;
    if connect(&probe, &address) != Err(rustix::io::Errno::CONNREFUSED) {
        return Err(unavailable());
    }
    let current_directory = fs::symlink_metadata(parent).map_err(|_| unavailable())?;
    let current_socket = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if !same_identity_and_metadata(&directory, &current_directory)
        || !same_identity_and_metadata(&socket_metadata, &current_socket)
    {
        return Err(unavailable());
    }
    fs::remove_file(path).map_err(|_| unavailable())?;
    Ok(directory_handle)
}

fn same_identity_and_metadata(first: &Metadata, second: &Metadata) -> bool {
    first.dev() == second.dev()
        && first.ino() == second.ino()
        && first.uid() == second.uid()
        && first.gid() == second.gid()
        && first.mode() == second.mode()
        && first.mtime() == second.mtime()
        && first.mtime_nsec() == second.mtime_nsec()
        && first.ctime() == second.ctime()
        && first.ctime_nsec() == second.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::{NativeBindings, NativeHost};
    use crate::{ListenerFactory, ListenerRequest, ListenerRole, health::ProcessState};

    struct Root(PathBuf);
    impl Root {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path =
                std::env::temp_dir().join(format!("pos-control-{}-{nonce}", std::process::id()));
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self(path))
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            if let Err(error) = fs::remove_dir_all(&self.0) {
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            }
        }
    }
    fn host(path: &Path) -> Result<NativeHost, Box<dyn std::error::Error>> {
        let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        Ok(NativeHost::new(NativeBindings::new(
            path.to_owned(),
            loopback,
            loopback,
            loopback,
            loopback,
            loopback,
        )?))
    }
    fn request() -> ListenerRequest {
        ListenerRequest::new(ListenerRole::Control, ProcessState::starting().health())
    }
    fn stale(path: &Path) -> Result<(), std::io::Error> {
        drop(UnixListener::bind(path)?);
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }

    #[test]
    fn stale_control_socket_is_reclaimed_in_a_private_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let path = root.0.join("control.sock");
        stale(&path)?;
        let host = host(&path)?;
        let listener = host.bind(request())?;
        assert!(UnixStream::connect(&path).is_ok());
        assert_eq!(fs::symlink_metadata(&path)?.mode() & 0o777, 0o600);
        drop(listener);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn concurrent_control_reclamation_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let path = root.0.join("control.sock");
        stale(&path)?;
        let before = fs::symlink_metadata(&path)?;
        let directory = fs::File::open(&root.0)?;
        rustix::fs::flock(
            &directory,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )?;
        assert!(host(&path)?.bind(request()).is_err());
        assert_eq!(before.ino(), fs::symlink_metadata(&path)?.ino());
        drop(directory);
        let listener = host(&path)?.bind(request())?;
        assert!(UnixStream::connect(&path).is_ok());
        drop(listener);
        Ok(())
    }

    #[test]
    fn active_control_socket_is_never_reclaimed() -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let path = root.0.join("control.sock");
        let original = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let before = fs::symlink_metadata(&path)?;
        assert!(host(&path)?.bind(request()).is_err());
        assert_eq!(before.ino(), fs::symlink_metadata(&path)?.ino());
        assert!(UnixStream::connect(&path).is_ok());
        drop(original);
        Ok(())
    }

    #[test]
    fn unsafe_existing_control_paths_are_preserved() -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let file = root.0.join("file");
        fs::write(&file, b"preserved")?;
        let link = root.0.join("link");
        symlink(&file, &link)?;
        let loose_socket = root.0.join("loose.sock");
        stale(&loose_socket)?;
        fs::set_permissions(&loose_socket, fs::Permissions::from_mode(0o666))?;
        for path in [&file, &link, &loose_socket] {
            let before = fs::symlink_metadata(path)?;
            assert!(host(path)?.bind(request()).is_err());
            assert_eq!(before.ino(), fs::symlink_metadata(path)?.ino());
        }
        assert_eq!(fs::read(&file)?, b"preserved");
        let stale_socket = root.0.join("stale.sock");
        stale(&stale_socket)?;
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777))?;
        assert!(host(&stale_socket)?.bind(request()).is_err());
        assert!(stale_socket.exists());
        Ok(())
    }
}
