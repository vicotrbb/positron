//! Canonical configuration drives the exclusive-owner migration adapter.
#![cfg(unix)]
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn canonical_owner_commands_preserve_cancelled_routes_and_verify_before_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    let root = fs::canonicalize(std::env::temp_dir())?.join(format!(
        "positron-provider-migration-cli-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let data = root.join("data");
    let secrets = root.join("secrets");
    for directory in [&data, &secrets] {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let config = root.join("owner.toml");
    fs::write(
        &config,
        format!(
            "schema_version = 1\n[storage]\ndata_directory = '{}'\nsecrets_directory = '{}'\n[security]\nlocal_key_file = '{}'\n",
            data.display(),
            secrets.display(),
            secrets.join("local-root-key.v1").display()
        ),
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    for action in [
        "status", "prepare", "cancel", "status", "resume", "activate", "status",
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
        command
            .args(["keys", "migrate", action, "--config"])
            .arg(&config);
        if matches!(action, "prepare" | "activate") {
            command.arg("--target-config").arg(&config);
        }
        let output = command.output()?;
        assert!(
            output.status.success(),
            "canonical migration command {action} failed"
        );
        let rendered = String::from_utf8(output.stdout)?;
        assert!(rendered.contains("active_epoch="));
        assert!(!rendered.contains(&secrets.display().to_string()));
    }
    for action in ["verify", "retire"] {
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["keys", "migrate", action, "--config"])
            .arg(&config)
            .output()?;
        assert!(
            !output.status.success(),
            "independent successor recovery is mandatory"
        );
        assert!(secrets.join("local-root-key.v1").exists());
    }
    let instance = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(instance.local_key_rotation_status()?.active_epoch(), 2);
    let recovery = root.join("recovery");
    fs::create_dir(&recovery)?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o700))?;
    let unlock = age::x25519::Identity::generate();
    let bundle = recovery.join("successor.age");
    instance.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    drop(instance);
    for action in ["verify", "verify", "retire", "status"] {
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["keys", "migrate", action, "--config"])
            .arg(&config)
            .output()?;
        assert!(
            output.status.success(),
            "verified canonical migration command {action} failed"
        );
    }
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
