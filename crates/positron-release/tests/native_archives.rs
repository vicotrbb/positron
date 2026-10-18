use flate2::read::GzDecoder;
use positron_release::{NativeTarget, native_archive};
use std::{collections::BTreeMap, io::Read};

#[test]
fn native_archive_preserves_binary_and_generated_contract_with_safe_permissions() {
    let binary = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0payload";
    let first = native_archive(NativeTarget::LinuxX86_64, binary).unwrap();
    assert_eq!(
        first,
        native_archive(NativeTarget::LinuxX86_64, binary).unwrap()
    );
    let mut archive = tar::Archive::new(GzDecoder::new(first.as_slice()));
    let mut files = BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert_eq!(entry.header().gid().unwrap(), 0);
        assert_eq!(entry.header().mtime().unwrap(), 0);
        assert!(entry.header().entry_type().is_file());
        let mode = entry.header().mode().unwrap();
        let name = entry.path().unwrap().to_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert!(files.insert(name, (mode, bytes)).is_none());
    }
    assert_eq!(files["positron/bin/positron"], (0o755, binary.to_vec()));
    assert_eq!(
        files["positron/etc/positron.toml.example"],
        (0o644, positron_config::generated_example().into_bytes())
    );
    assert_eq!(
        files["positron/share/config.schema.json"].1,
        positron_config::generated_json_schema().into_bytes()
    );
    assert!(files.contains_key("positron/share/positron.service"));
    assert!(!files.contains_key("positron/share/com.guaracloud.positron.plist"));
    assert!(files.contains_key("positron/README.md"));
    assert!(files.contains_key("positron/LICENSE"));
}

#[test]
fn native_targets_reject_mislabelled_objects_and_accept_linux_pie() {
    for (name, header) in [
        (
            "linux-x86_64",
            b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0".as_slice(),
        ),
        (
            "linux-aarch64",
            b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\xb7\0".as_slice(),
        ),
        (
            "macos-x86_64",
            b"\xcf\xfa\xed\xfe\x07\0\0\x01\0\0\0\0\x02\0\0\0".as_slice(),
        ),
        (
            "macos-aarch64",
            b"\xcf\xfa\xed\xfe\x0c\0\0\x01\0\0\0\0\x02\0\0\0".as_slice(),
        ),
    ] {
        let target: NativeTarget = name.parse().unwrap();
        assert!(native_archive(target, header).is_ok(), "{name}");
        for other in [
            "linux-x86_64",
            "linux-aarch64",
            "macos-x86_64",
            "macos-aarch64",
        ] {
            if other != name {
                assert_eq!(
                    native_archive(other.parse().unwrap(), header),
                    Err(positron_release::ReleaseError::IdentityMismatch)
                );
            }
        }
        assert_eq!(
            native_archive(target, b""),
            Err(positron_release::ReleaseError::IdentityMismatch)
        );
    }
    assert_eq!(
        "windows-x86_64".parse::<NativeTarget>(),
        Err(positron_release::ReleaseError::Unsupported)
    );
}

#[path = "support/mod.rs"]
mod support;
#[test]
fn signed_manifest_binds_archive_bytes_to_the_exact_native_target_offline() {
    use positron_release::*;
    let mut fixture = support::Fixture::new();
    let installed = std::env::var_os("POSITRON_TEST_NATIVE_BINARY");
    let target_name = if installed.is_some() {
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    } else {
        "linux-x86_64".into()
    };
    let binary = installed
        .map(std::fs::read)
        .transpose()
        .unwrap()
        .unwrap_or_else(|| b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0payload".to_vec());
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| {
            artifact.surface == Surface::NativeArchive && artifact.target == target_name
        })
        .unwrap();
    let archive = native_archive(target_name.parse().unwrap(), &binary).unwrap();
    fixture.replace_artifact(index, &archive, &archive);
    let (signed, construction) = fixture.published();
    verify_release(
        &signed,
        &construction.inventory_bytes,
        fixture.key(),
        &fixture.trust(),
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        &target_name,
        &[],
    )
    .unwrap();
    let name = fixture.inventory.artifacts[index].file.clone();
    std::fs::write(
        fixture.root.join("bundle").join(name),
        b"substituted archive",
    )
    .unwrap();
    assert_eq!(
        verify_release(
            &signed,
            &construction.inventory_bytes,
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &target_name,
            &[]
        )
        .err(),
        Some(ReleaseError::IdentityMismatch)
    );
}

#[test]
fn compressed_native_archive_is_screened_for_secret_canaries_before_signing() {
    use positron_release::*;
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| {
            artifact.surface == Surface::NativeArchive && artifact.target == "macos-aarch64"
        })
        .unwrap();
    let archive = native_archive(
        NativeTarget::MacosAarch64,
        b"\xcf\xfa\xed\xfe\x0c\0\0\x01\0\0\0\0\x02\0\0\0native-private-canary",
    )
    .unwrap();
    fixture.replace_artifact(index, &archive, &archive);
    assert_eq!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[b"native-private-canary".to_vec()],
            vec![]
        )
        .err(),
        Some(ReleaseError::SecretDetected)
    );
}
