//! Archive qualification uses a genuine native release executable.
use std::{path::PathBuf, process::Command};
pub fn executable() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if std::env::var_os("POSITRON_TEST_NATIVE_BINARY").is_some() {
        return Ok(super::native_binary::executable());
    }
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    build_in(&workspace)
}
pub(super) fn build_in(workspace: &std::path::Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    build_in_at(
        workspace,
        &std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("native-archive-test-release"),
    )
}
pub(super) fn build_in_at(
    workspace: &std::path::Path,
    target: &std::path::Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // A separate Cargo target avoids the outer test command's artifact lock.
    let status = Command::new(env!("CARGO"))
        .current_dir(workspace)
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "positron",
            "--target-dir",
        ])
        .arg(target)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("LLVM_PROFILE_FILE")
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .status()?;
    if !status.success() {
        return Err("bounded native archive test release build failed".into());
    }
    Ok(target.join("release/positron"))
}
