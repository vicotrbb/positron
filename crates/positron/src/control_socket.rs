//! Owner-local Control socket transport validation.
//!
//! The control bearer is an administrator credential. Callers validate the
//! pathname before and after connecting so a symlink, a non-socket, or a
//! group- or world-accessible endpoint never receives it. The connected peer
//! is verified through the supported Unix credential API on each platform.

#![cfg(unix)]

use std::{
    fs::{self, Metadata},
    io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    time::Duration,
};

/// Connects only to the native owner-only Control endpoint.
pub(crate) fn connect_owner_control(path: &Path, deadline: Duration) -> io::Result<UnixStream> {
    let before = trusted_endpoint(path)?;
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    let stream = runtime.block_on(async {
        let stream = tokio::time::timeout(deadline, tokio::net::UnixStream::connect(path))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        if stream.peer_cred()?.uid() != rustix::process::getuid().as_raw() {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        stream.into_std()
    })?;
    stream.set_nonblocking(false)?;
    let after = trusted_endpoint(path)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(stream)
}

fn trusted_endpoint(path: &Path) -> io::Result<Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || mode != 0o600
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::{fs::PermissionsExt, net::UnixListener},
        panic::{AssertUnwindSafe, catch_unwind},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::connect_owner_control;

    #[test]
    fn owner_control_connect_fails_closed_inside_an_existing_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::path::Path::new("/tmp").join(format!("poc-{}-{nonce}.sock", std::process::id()));
        let _listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let result = runtime.block_on(async {
            catch_unwind(AssertUnwindSafe(|| {
                connect_owner_control(&path, Duration::from_millis(1))
            }))
        });
        std::fs::remove_file(&path)?;
        let result = result.expect("owner control transport must not panic inside a runtime");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn owner_control_connect_enables_timers_in_its_owned_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::path::Path::new("/tmp").join(format!("poc-{}-{nonce}.sock", std::process::id()));
        let _listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            connect_owner_control(&path, Duration::from_millis(100))
        }));
        std::fs::remove_file(&path)?;
        let stream =
            result.expect("owner control transport must not panic in its owned runtime")?;
        drop(stream);
        Ok(())
    }
}
