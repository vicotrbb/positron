//! Installed archive behavior through the real executable.
use std::{fs, process::Command};

#[test]
fn archive_cli_builds_an_installable_exact_host_payload_and_refuses_replacement() {
    let root = std::env::temp_dir().join(format!(
        "p-archive-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let output = root.join("native.tar.gz");
    let target = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let args = [
        "release",
        "archive",
        "--target",
        &target,
        "--binary",
        env!("CARGO_BIN_EXE_positron"),
        "--out",
        output.to_str().unwrap(),
    ];
    let result = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(
        fs::File::open(&output).unwrap(),
    ));
    archive.unpack(&root).unwrap();
    let installed = root.join("positron/bin/positron");
    assert_eq!(
        fs::read(&installed).unwrap(),
        fs::read(env!("CARGO_BIN_EXE_positron")).unwrap()
    );
    let result = Command::new(&installed)
        .args(["release", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let result = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(args)
        .output()
        .unwrap();
    assert!(!result.status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bootstrap_claim_cli_returns_credentials_once_without_logging_them() {
    use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("p-claim-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir(&data).unwrap();
    fs::create_dir(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    let paths = BootstrapPaths::new(
        &data,
        &secrets,
        positron_kernel::MountQualification::LocalHost,
    )
    .unwrap();
    drop(InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive()).unwrap());
    let config = root.join("positron.toml");
    fs::write(&config, format!("schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n[security]\nlocal_key_file = {:?}\n", data, secrets, secrets.join("local-root-key.v1"))).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["bootstrap", "claim", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("administrator_secret="));
    assert!(output.contains("ingest_secret="));
    assert!(output.contains("query_secret="));
    let retry = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["bootstrap", "claim", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!retry.status.success());
    assert!(retry.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&retry.stderr).contains(&output));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn query_cli_validates_canonical_request_before_credentials_or_network() {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "query",
            "--request",
            "/missing/query-request.json",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--allow-plaintext",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("query request unavailable"));
}
