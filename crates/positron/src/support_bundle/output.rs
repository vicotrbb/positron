use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub(super) fn write_new_owner_only(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    // `exists` follows a symlink and misses a dangling target. Refuse every
    // extant directory entry so output cannot be redirected or overwritten.
    if fs::symlink_metadata(path).is_ok() {
        return Err(());
    }
    let parent = path.parent().ok_or(())?;
    let name = path.file_name().and_then(|name| name.to_str()).ok_or(())?;
    let temporary = parent.join(format!(".{name}.positron-new"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| ())?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ())?;
    // `rename` could replace a path created after the check above. A hard link
    // publishes only if the final name is still absent, atomically on the same
    // filesystem; then the private temporary name is removed.
    fs::hard_link(&temporary, path).map_err(|_| ())?;
    fs::remove_file(temporary).map_err(|_| ())
}
