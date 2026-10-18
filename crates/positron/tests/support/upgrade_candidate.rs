//! A private, independently compiled versioned artifact for native upgrade tests.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) struct Candidate {
    pub binary: PathBuf,
    pub source_commit: String,
    pub candidate_commit: String,
}
fn checked(command: &mut Command) -> Result<std::process::Output> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "candidate fixture command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}
pub(crate) fn prepare() -> Result<Candidate> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let commit = String::from_utf8(
        checked(
            Command::new("git")
                .arg("-C")
                .arg(&workspace)
                .args(["rev-parse", "HEAD"]),
        )?
        .stdout,
    )?
    .trim()
    .to_owned();
    let root = workspace
        .join("target/native-upgrade-fixture")
        .join(&commit);
    let binary = root.join("target/release/positron");
    let marker = root.join("candidate-commit");
    if binary.is_file() && marker.is_file() {
        return Ok(Candidate {
            binary,
            source_commit: commit,
            candidate_commit: fs::read_to_string(marker)?.trim().into(),
        });
    }
    fs::create_dir_all(&root)?;
    let source = root.join("source");
    fs::create_dir_all(&source)?;
    let archive = root.join("source.tar");
    checked(
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["archive", "HEAD", "--output"])
            .arg(&archive),
    )?;
    tar::Archive::new(fs::File::open(&archive)?).unpack(&source)?;
    let manifest = source.join("Cargo.toml");
    let text = fs::read_to_string(&manifest)?;
    if text.matches("version = \"0.0.0\"").count() != 1 {
        return Err("fixture expects the unreleased 0.0.0 workspace".into());
    }
    fs::write(
        &manifest,
        text.replacen("version = \"0.0.0\"", "version = \"0.0.1\"", 1),
    )?;
    let lock = source.join("Cargo.lock");
    let blocks = fs::read_to_string(&lock)?
        .split("\n[[package]]\n")
        .map(|block| {
            if block.starts_with("name = \"positron") {
                block.replacen("version = \"0.0.0\"", "version = \"0.0.1\"", 1)
            } else {
                block.to_owned()
            }
        })
        .collect::<Vec<_>>();
    fs::write(lock, blocks.join("\n[[package]]\n"))?;
    checked(Command::new("git").arg("-C").arg(&source).args([
        "init",
        "--quiet",
        "--object-format=sha1",
    ]))?;
    let tracked = checked(Command::new("git").arg("-C").arg(&workspace).args([
        "ls-tree",
        "-rz",
        "--name-only",
        "HEAD",
    ]))?
    .stdout;
    let paths = std::str::from_utf8(&tracked)?
        .split('\0')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>();
    for chunk in paths.chunks(64) {
        checked(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(["add", "--"])
                .args(chunk),
        )?;
    }
    checked(Command::new("git").arg("-C").arg(&source).args([
        "-c",
        "user.name=Positron test fixture",
        "-c",
        "user.email=fixture@positron.invalid",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "Private candidate fixture version 0.0.1",
    ]))?;
    let candidate_commit = String::from_utf8(
        checked(
            Command::new("git")
                .arg("-C")
                .arg(&source)
                .args(["rev-parse", "HEAD"]),
        )?
        .stdout,
    )?
    .trim()
    .to_owned();
    let status = Command::new(env!("CARGO"))
        .current_dir(&source)
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "positron",
            "--target-dir",
        ])
        .arg(root.join("target"))
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("LLVM_PROFILE_FILE")
        .status()?;
    if !status.success() {
        return Err("private candidate fixture build failed".into());
    }
    fs::write(marker, &candidate_commit)?;
    Ok(Candidate {
        binary,
        source_commit: commit,
        candidate_commit,
    })
}
