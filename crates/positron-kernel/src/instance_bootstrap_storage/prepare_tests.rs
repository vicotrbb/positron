//! Storage preparation through the public bootstrap storage boundary.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn prepare_creates_private_leaf_roots_under_real_setgid_mount_parents_and_is_idempotent() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("positron-prepare-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o2775)).unwrap();
    let data = root.join("data");
    let secrets = root.join("secrets");
    let storage =
        InstanceBootstrapStorage::prepare(&data, &secrets, MountQualification::LocalHost).unwrap();
    assert!(
        storage
            .inspect()
            .unwrap()
            .layout()
            .unwrap()
            .is_empty_instance()
    );
    let before = [
        std::fs::metadata(&data).unwrap(),
        std::fs::metadata(&secrets).unwrap(),
    ];
    for metadata in &before {
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    }
    drop(
        InstanceBootstrapStorage::prepare(&data, &secrets, MountQualification::LocalHost).unwrap(),
    );
    for (path, metadata) in [(&data, &before[0]), (&secrets, &before[1])] {
        let after = std::fs::metadata(path).unwrap();
        assert_eq!(after.ino(), metadata.ino());
        assert_eq!(after.mode(), metadata.mode());
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn prepare_refuses_unsafe_existing_root_before_creating_the_other_and_never_repairs() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("positron-prepare-unsafe-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let data = root.join("data");
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        InstanceBootstrapStorage::prepare(&data, &secrets, MountQualification::LocalHost).is_err()
    );
    assert!(!data.exists());
    assert_eq!(std::fs::metadata(&secrets).unwrap().mode() & 0o7777, 0o755);
    std::fs::remove_dir(&secrets).unwrap();
    std::os::unix::fs::symlink(&root, &secrets).unwrap();
    assert!(
        InstanceBootstrapStorage::prepare(&data, &secrets, MountQualification::LocalHost).is_err()
    );
    assert!(!data.exists());
    std::fs::remove_file(&secrets).unwrap();
    assert!(
        InstanceBootstrapStorage::prepare(
            &data,
            &data.join("nested"),
            MountQualification::LocalHost
        )
        .is_err()
    );
    assert!(!data.exists());
    assert!(
        InstanceBootstrapStorage::prepare(
            &data,
            &root.join("missing/leaf"),
            MountQualification::LocalHost
        )
        .is_err()
    );
    assert!(!data.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn prepared_roots_refuse_replacement_links_and_foreign_inodes_before_use() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("positron-prepare-replaced-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let data = root.join("data");
    let secrets = root.join("secrets");
    let storage =
        InstanceBootstrapStorage::prepare(&data, &secrets, MountQualification::LocalHost).unwrap();
    let retained = root.join("retained");
    std::fs::rename(&data, &retained).unwrap();
    std::os::unix::fs::symlink(&retained, &data).unwrap();
    assert!(storage.inspect().is_err());
    std::fs::remove_file(&data).unwrap();
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(storage.inspect().is_err());
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
    std::fs::remove_dir(&data).unwrap();
    std::fs::write(&data, b"foreign file").unwrap();
    assert!(
        InstanceBootstrapStorage::prepare(&data, &secrets, MountQualification::LocalHost).is_err()
    );
    assert_eq!(std::fs::read(&data).unwrap(), b"foreign file");
    std::fs::remove_dir_all(root).unwrap();
}
