//! Exclusive owner CLI operates the durable root rotation lifecycle.
#![cfg(unix)]
use positron_kernel::{MountQualification, RecoveryRecipients, RecoveryUnlock};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn owner_cli_prepares_cuts_over_and_retires_only_after_verified_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
        "positron-local-rotation-cli-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    let data = root.join("data");
    let secrets = root.join("secrets");
    let recovery = root.join("recovery");
    for directory in [&root, &data, &secrets, &recovery] {
        if directory != &root {
            fs::create_dir(directory)?;
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    for action in ["status", "prepare", "prepare", "activate", "status"] {
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["keys", "local", action, "--data-dir"])
            .arg(&data)
            .arg("--secrets-dir")
            .arg(&secrets)
            .output()?;
        assert!(
            output.status.success(),
            "owner command {action} failed; output retained privately"
        );
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !bytes
                    .windows(claim.secret().len())
                    .any(|value| value == claim.secret().as_bytes())
            );
        }
    }
    let refused = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["keys", "local", "retire", "--data-dir"])
        .arg(&data)
        .arg("--secrets-dir")
        .arg(&secrets)
        .output()?;
    assert!(!refused.status.success());
    assert!(secrets.join("local-root-key.v1").exists());
    let instance = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(instance.local_key_rotation_status()?.active_epoch(), 2);
    let unlock = age::x25519::Identity::generate();
    let bundle = recovery.join("successor.age");
    instance.create_recovery_bundle(
        &bundle,
        &RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(&bundle, RecoveryUnlock::Identity(&unlock))?;
    drop(instance);
    let completed = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["keys", "local", "retire", "--data-dir"])
        .arg(&data)
        .arg("--secrets-dir")
        .arg(&secrets)
        .output()?;
    assert!(completed.status.success());
    assert!(!secrets.join("local-root-key.v1").exists());
    assert_eq!(
        InstanceBootstrap::reopen(&paths)?
            .local_key_rotation_status()?
            .active_epoch(),
        2
    );
    fs::remove_dir_all(root)?;
    Ok(())
}
