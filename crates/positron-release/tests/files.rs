use positron_release::{FileIdentity, ReleaseError, inspect_file};
#[test]
fn inspection_hashes_exact_bytes_and_refuses_credentials_and_non_files() {
    let root =
        std::env::temp_dir().join(format!("positron-release-inspect-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("good"), b"functional payload").unwrap();
    assert_eq!(
        inspect_file(&root, "good", &[]).unwrap(),
        FileIdentity::of(b"functional payload")
    );
    std::fs::write(
        root.join("secret"),
        format!(
            "ghp_{}",
            (0..36)
                .map(|index| char::from(b'a' + index % 26))
                .collect::<String>()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        inspect_file(&root, "secret", &[]).err(),
        Some(ReleaseError::SecretDetected)
    );
    assert_eq!(
        inspect_file(&root, "../good", &[]).err(),
        Some(ReleaseError::Invalid)
    );
    assert_eq!(
        inspect_file(&root, "missing", &[]).err(),
        Some(ReleaseError::Unavailable)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inspection_refuses_complete_twenty_character_aws_access_key_ids() {
    let root = std::env::temp_dir().join(format!("positron-release-aws-id-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for prefix in ["AKIA", "ASIA"] {
        let value = format!(
            "{prefix}{}",
            (0..16)
                .map(|index| char::from(b'A' + index))
                .collect::<String>()
        );
        std::fs::write(root.join("credential"), value).unwrap();
        assert_eq!(
            inspect_file(&root, "credential", &[]).err(),
            Some(ReleaseError::SecretDetected)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
