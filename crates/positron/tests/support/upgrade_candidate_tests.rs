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
    let root = external_root(&fixture);
    let current = archive::build_in_at(&fixture.root, &root.join("archive"))?;
    assert_eq!(checked(&mut Command::new(current))?.stdout, b"0.0.0\n");
    let candidate = candidate::prepare_in_at(&fixture.root, &root.join("upgrade"))?;
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
fn independent_candidate_uses_the_selected_cargo_target_directory() -> Result<()> {
    let fixture = workspace(None)?;
    let candidate = prepare_in(&fixture.root)?;
    assert_eq!(
        checked(&mut Command::new(&candidate.binary))?.stdout,
        b"0.0.1\n"
    );
    assert!(
        candidate.binary.starts_with(env!("CARGO_TARGET_TMPDIR")),
        "independent output must stay under Cargo's selected target, outside the source tree"
    );
    assert!(!fixture.root.join("target").exists());
    Ok(())
}

#[test]
fn current_archive_uses_the_selected_cargo_target_directory() -> Result<()> {
    let fixture = workspace(None)?;
    let binary = archive::build_in(&fixture.root)?;
    assert_eq!(checked(&mut Command::new(&binary))?.stdout, b"0.0.0\n");
    assert!(
        binary.starts_with(env!("CARGO_TARGET_TMPDIR")),
        "current archive output must stay under Cargo's selected target"
    );
    assert!(!fixture.root.join("target").exists());
    Ok(())
}

#[test]
fn nested_fixture_builds_remove_inherited_instrumentation() -> Result<()> {
    const CHILD: &str = "POSITRON_FIXTURE_INSTRUMENTATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let executable = std::env::current_exe()?;
        let profiles = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "fixture-profile-canary-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        assert!(profiles.is_absolute());
        fs::create_dir(&profiles)?;
        let output = Command::new(executable)
            .args([
                "--exact",
                "tests::nested_fixture_builds_remove_inherited_instrumentation",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("RUSTFLAGS", "--cfg inherited_fixture_flags")
            .env(
                "CARGO_ENCODED_RUSTFLAGS",
                "--cfg\u{1f}inherited_fixture_flags",
            )
            .env("LLVM_PROFILE_FILE", profiles.join("child-%p.profraw"))
            .env("RUSTC_WRAPPER", "")
            .env("RUSTC_WORKSPACE_WRAPPER", "")
            .output();
        let emitted_profile = (|| -> std::io::Result<bool> {
            for entry in fs::read_dir(&profiles)? {
                if entry?
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "profraw")
                {
                    return Ok(true);
                }
            }
            Ok(false)
        })();
        let cleanup = fs::remove_dir_all(&profiles);
        // Preserve spawn/child failure as the primary outcome while attempting
        // cleanup on both paths. Unexpected cleanup errors still fail success.
        let output = output.map_err(|error| {
            format!(
                "nested build spawn: {error}; cleanup: {:?}",
                cleanup.as_ref().err().map(std::io::Error::kind),
            )
        })?;
        assert!(
            output.status.success(),
            "nested build hygiene: {}; cleanup: {:?}",
            String::from_utf8_lossy(&output.stderr),
            cleanup.as_ref().err().map(std::io::Error::kind),
        );
        cleanup?;
        let emitted_profile = emitted_profile?;
        if option_env!("CARGO_LLVM_COV").is_some() {
            assert!(
                emitted_profile,
                "instrumented child must write only into its owned absolute directory"
            );
            eprintln!("instrumented child profile emitted in owned target directory and cleaned");
        }
        assert!(!profiles.exists());
        return Ok(());
    }
    let fixture = workspace(None)?;
    fs::write(
        fixture.root.join("build.rs"),
        r#"fn main() {
    for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "LLVM_PROFILE_FILE"] {
        assert!(std::env::var_os(name).is_none_or(|v| v.is_empty()), "inherited instrumentation: {name}");
    }
    for name in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"] {
        assert!(std::env::var_os(name).is_some_and(|v| v.is_empty()), "inherited wrapper: {name}");
    }
}"#,
    )?;
    checked(
        Command::new("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["add", "build.rs"]),
    )?;
    commit_fixture(&fixture.root, "Instrumentation build contract")?;
    let root = external_root(&fixture);
    let current = archive::build_in_at(&fixture.root, &root.join("archive"))?;
    assert_eq!(checked(&mut Command::new(current))?.stdout, b"0.0.0\n");
    let candidate = candidate::prepare_in_at(&fixture.root, &root.join("upgrade"))?;
    assert_eq!(
        checked(&mut Command::new(candidate.binary))?.stdout,
        b"0.0.1\n"
    );
    assert!(!fixture.root.join("target").exists());
    Ok(())
}

fn external_root(fixture: &crate::Fixture) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(
        fixture
            .root
            .file_name()
            .expect("fixture has a private name"),
    )
}

fn commit_fixture(root: &std::path::Path, message: &str) -> Result<()> {
    checked(Command::new("git").arg("-C").arg(root).args([
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
        message,
    ]))?;
    Ok(())
}

#[test]
fn independent_candidate_reuses_exact_source_cache_and_separates_changed_head() -> Result<()> {
    let fixture = workspace(None)?;
    let counter = fixture.root.join("build-count");
    fs::write(
        fixture.root.join("build.rs"),
        format!(
            r#"fn main() {{
    let path = std::path::Path::new({counter:?});
    let previous = std::fs::read_to_string(path).unwrap_or_else(|_| "0".into());
    let count: u64 = previous.parse().expect("fixture counter");
    std::fs::write(path, (count + 1).to_string()).expect("fixture counter write");
}}"#
        ),
    )?;
    checked(
        Command::new("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["add", "build.rs"]),
    )?;
    commit_fixture(&fixture.root, "Count actual candidate builds")?;
    let selected = external_root(&fixture);
    let first = candidate::prepare_in_at(&fixture.root, &selected)?;
    let first_bytes = fs::read(&first.binary)?;
    assert_eq!(fs::read_to_string(&counter)?, "1");
    let cached = candidate::prepare_in_at(&fixture.root, &selected)?;
    assert_eq!(cached.source_commit, first.source_commit);
    assert_eq!(cached.candidate_commit, first.candidate_commit);
    assert_eq!(cached.binary, first.binary);
    assert_eq!(fs::read(&cached.binary)?, first_bytes);
    assert_eq!(
        fs::read_to_string(&counter)?,
        "1",
        "cache hit must not invoke another build script"
    );
    fs::write(
        fixture.root.join("src/main.rs"),
        "fn main() { println!(\"{}\", env!(\"CARGO_PKG_VERSION\")); }\n// different source\n",
    )?;
    checked(
        Command::new("git")
            .arg("-C")
            .arg(&fixture.root)
            .args(["add", "src/main.rs"]),
    )?;
    commit_fixture(&fixture.root, "Changed source identity")?;
    let changed = candidate::prepare_in_at(&fixture.root, &selected)?;
    assert_ne!(changed.source_commit, first.source_commit);
    assert_ne!(changed.candidate_commit, first.candidate_commit);
    assert_ne!(changed.binary, first.binary);
    assert!(changed.binary.starts_with(&selected));
    assert_eq!(
        checked(&mut Command::new(&changed.binary))?.stdout,
        b"0.0.1\n"
    );
    assert_eq!(fs::read_to_string(&counter)?, "2");
    assert!(!fixture.root.join("target").exists());
    Ok(())
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
    let candidate = candidate::prepare_in_at(&fixture.root, &external_root(&fixture))?;
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
