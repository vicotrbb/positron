//! Prepare mounted roots through the native executable without initializing secrets.
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Command,
};

#[test]
fn prepare_storage_is_explicit_private_idempotent_and_creates_no_instance() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("positron-prepare-cli-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o2775)).unwrap();
    let data = root.join("data");
    let secrets = root.join("secrets");
    let config = root.join("positron.toml");
    std::fs::write(&config, format!("schema_version = 1\n[storage]\ndata_directory = '{}'\nsecrets_directory = '{}'\n[security]\nlocal_key_file = '{}'\n", data.display(), secrets.display(), secrets.join("local-root-key.v1").display())).unwrap();
    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["bootstrap", "prepare-storage", "--config"])
            .arg(&config)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"status=storage_prepared\n");
        for path in [&data, &secrets] {
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o700);
            assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
        }
    }
    let refused = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["bootstrap", "prepare-storage"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    std::fs::remove_dir_all(root).unwrap();
}
