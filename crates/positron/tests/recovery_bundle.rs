//! Owner-controlled native CLI creation, inspection and verification.
#![cfg(unix)]
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::Command,
};
#[test]
fn native_recovery_cli_exports_and_verifies_without_printing_private_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("positron-recovery-cli-{}", std::process::id()));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    let data = root.join("data");
    let secrets = root.join("secrets");
    let export = root.join("export");
    for path in [&data, &secrets, &export] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let identity = age::x25519::Identity::generate();
    let identity_path = export.join("identity.txt");
    use age::secrecy::ExposeSecret;
    let encoded = identity.to_string();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&identity_path)?
        .write_all(encoded.expose_secret().as_bytes())?;
    let bundle = export.join("recovery.age");
    for command in ["create", "inspect", "verify"] {
        let mut process = Command::new(env!("CARGO_BIN_EXE_positron"));
        process
            .args(["keys", "recovery", command, "--data-dir"])
            .arg(&data)
            .arg("--secrets-dir")
            .arg(&secrets)
            .arg("--bundle")
            .arg(&bundle);
        if command == "create" {
            process
                .arg("--recipient")
                .arg(identity.to_public().to_string());
        } else {
            process.arg("--identity-file").arg(&identity_path);
        }
        let output = process.output()?;
        assert!(
            output.status.success(),
            "native {command} should succeed without exposing captured output"
        );
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !bytes
                    .windows(encoded.expose_secret().len())
                    .any(|window| window == encoded.expose_secret().as_bytes()),
                "private recovery identity must never reach output"
            );
        }
    }
    let instance = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(
        instance.backup_key_recovery_readiness()?,
        positron_runtime::RecoveryReadiness::Verified
    );
    let pin = instance.recovery_identity()?;
    drop(instance);
    let replacement = export.join("replacement.age");
    let mut rotate = command(&data, &secrets, "rotate");
    rotate
        .arg("--bundle")
        .arg(&replacement)
        .arg("--recipient")
        .arg(identity.to_public().to_string())
        .arg("--identity-file")
        .arg(&identity_path);
    check(rotate.output()?, encoded.expose_secret())?;
    check(
        command(&data, &secrets, "retire").output()?,
        encoded.expose_secret(),
    )?;
    assert!(!bundle.exists());
    assert!(replacement.exists());
    fs::remove_file(secrets.join("local-root-key.v1"))?;
    let mut import = command(&data, &secrets, "import");
    import
        .arg("--bundle")
        .arg(&replacement)
        .arg("--identity-file")
        .arg(&identity_path)
        .arg("--instance")
        .arg(hex(&pin.instance().to_bytes()))
        .arg("--root-key-id")
        .arg(hex(&pin.root().key_id()))
        .arg("--root-created-at")
        .arg(pin.root().created_at_unix_seconds().to_string())
        .arg("--root-fingerprint")
        .arg(hex(&pin.root().fingerprint()))
        .arg("--integrity-public-key")
        .arg(hex(&pin.integrity().public_key()))
        .arg("--integrity-fingerprint")
        .arg(hex(&pin.integrity().fingerprint()));
    check(import.output()?, encoded.expose_secret())?;
    let restored = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(restored.recovery_identity()?, pin);
    assert_eq!(
        restored.backup_key_recovery_readiness()?,
        positron_runtime::RecoveryReadiness::Verified
    );
    drop(restored);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn command(data: &std::path::Path, secrets: &std::path::Path, operation: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
    command
        .args(["keys", "recovery", operation, "--data-dir"])
        .arg(data)
        .arg("--secrets-dir")
        .arg(secrets);
    command
}
fn check(
    output: std::process::Output,
    private_identity: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !bytes
                .windows(private_identity.len())
                .any(|window| window == private_identity.as_bytes()),
            "private identity must never reach output"
        );
    }
    assert!(
        output.status.success(),
        "native owner workflow must succeed without printing captured output"
    );
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
