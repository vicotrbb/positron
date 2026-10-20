//! Archive qualification uses a genuine native release executable.
use std::{path::PathBuf, process::Command};
pub fn executable() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if std::env::var_os("POSITRON_TEST_NATIVE_BINARY").is_some() {
        return Ok(super::native_binary::executable());
    }
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // A separate Cargo target avoids the outer test command's artifact lock.
    let target = workspace.join("target/native-archive-test-release");
    let status = Command::new(env!("CARGO"))
        .current_dir(&workspace)
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "positron",
            "--target-dir",
        ])
        .arg(&target)
        .status()?;
    if !status.success() {
        return Err("bounded native archive test release build failed".into());
    }
    Ok(target.join("release/positron"))
}
