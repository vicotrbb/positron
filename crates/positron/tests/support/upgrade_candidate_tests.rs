use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn workspace(wrapper: Option<&str>) -> Result<crate::Fixture> {
    let root = std::env::temp_dir().join(format!(
        "positron-candidate-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root)?;
    let fixture = crate::Fixture { root };
    fs::create_dir(fixture.root.join("src"))?;
    fs::write(
        fixture.root.join("Cargo.toml"),
        "[workspace]\nresolver = \"3\"\n[workspace.package]\nversion = \"0.0.0\"\n[package]\nname = \"positron\"\nversion.workspace = true\nedition = \"2024\"\n",
    )?;
    fs::write(
        fixture.root.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"positron\"\nversion = \"0.0.0\"\n",
    )?;
    fs::write(
        fixture.root.join("src/main.rs"),
        "fn main() { println!(\"{}\", env!(\"CARGO_PKG_VERSION\")); }\n",
    )?;
    if let Some(channel) = wrapper {
        let rejected = fixture.root.join("rejected-wrapper");
        fs::write(
            &rejected,
            "#!/bin/sh\nprintf 'candidate wrapper unexpectedly executed\\n' >&2\nexit 97\n",
        )?;
        fs::set_permissions(&rejected, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(fixture.root.join(".cargo"))?;
        fs::write(
            fixture.root.join(".cargo/config.toml"),
            format!("[build]\n{channel} = {:?}\n", rejected),
        )?;
        fs::write(
            fixture.root.join("build.rs"),
            r#"fn main() {
    for name in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"] {
        assert!(std::env::var_os(name).is_some_and(|value| value.is_empty()),
            "independent candidate inherited a compiler wrapper");
    }
}
"#,
        )?;
    }
    checked(Command::new("git").arg("-C").arg(&fixture.root).args([
        "init",
        "--quiet",
        "--object-format=sha1",
    ]))?;
    checked(
        Command::new("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["add", "."]),
    )?;
    checked(Command::new("git").arg("-C").arg(&fixture.root).args([
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
        "-m",
        "Candidate build fixture",
    ]))?;
    Ok(fixture)
}

fn builds_with_wrapper_configuration(channel: &str) -> Result<()> {
    let fixture = workspace(Some(channel))?;
    let candidate = prepare_in(&fixture.root)?;
    let output = checked(&mut Command::new(&candidate.binary))?;
    assert_eq!(output.stdout, b"0.0.1\n");
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn independent_candidate_overrides_the_cargo_rustc_wrapper() -> Result<()> {
    builds_with_wrapper_configuration("rustc-wrapper")
}

#[test]
fn independent_candidate_overrides_the_cargo_workspace_wrapper() -> Result<()> {
    builds_with_wrapper_configuration("rustc-workspace-wrapper")
}

#[test]
fn independent_candidate_does_not_reuse_the_previous_build_contract() -> Result<()> {
    let fixture = workspace(None)?;
    let commit = String::from_utf8(
        checked(
            Command::new("git")
                .arg("-C")
                .arg(&fixture.root)
                .args(["rev-parse", "HEAD"]),
        )?
        .stdout,
    )?;
    let old = fixture
        .root
        .join("target/native-upgrade-fixture")
        .join(commit.trim());
    fs::create_dir_all(old.join("target/release"))?;
    let stale = old.join("target/release/positron");
    let bytes = b"#!/bin/sh\nprintf 'stale-candidate\\n'\n";
    fs::write(&stale, bytes)?;
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o700))?;
    fs::write(old.join("candidate-commit"), "previous-build-contract")?;
    let candidate = prepare_in(&fixture.root)?;
    let output = checked(&mut Command::new(&candidate.binary))?;
    assert_eq!(output.stdout, b"0.0.1\n");
    assert!(output.stderr.is_empty());
    assert_ne!(candidate.candidate_commit, "previous-build-contract");
    assert_eq!(fs::read(stale)?, bytes);
    assert_eq!(
        fs::read_to_string(old.join("candidate-commit"))?,
        "previous-build-contract"
    );
    Ok(())
}
