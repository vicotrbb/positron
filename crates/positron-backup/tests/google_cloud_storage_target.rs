use positron_backup::{GoogleCloudStorageTarget, RepositoryFailure, RepositoryIdentity};

#[test]
fn exact_google_target_round_trips_without_credentials() {
    fn existing_repository_boundary<T: positron_backup::Repository>() {}
    existing_repository_boundary::<positron_backup::GoogleCloudStorageRepository>();
    let target =
        GoogleCloudStorageTarget::new("positron-backup", "123456789012", "US-CENTRAL1", "owned/")
            .expect("target");
    assert_eq!(
        GoogleCloudStorageTarget::decode_locator(&target.encode_locator()),
        Ok(target.clone())
    );
    let identity = RepositoryIdentity::google_cloud_storage([1; 16], [2; 16], [3; 32], &target)
        .expect("identity");
    assert_eq!(identity.provider_kind(), "googleCloudStorage");
    assert_eq!(identity.prefix_commitment(), target.commitment());
    assert!(!format!("{target:?}").contains("positron-backup"));
    for (bucket, project, location, prefix) in [
        (
            "https://storage.googleapis.com",
            "123456789012",
            "US-CENTRAL1",
            "owned/",
        ),
        ("positron-backup", "Bearer secret", "US-CENTRAL1", "owned/"),
        (
            "positron-backup",
            "123456789012",
            "https://foreign",
            "owned/",
        ),
        (
            "positron-backup",
            "123456789012",
            "US-CENTRAL1",
            "../foreign/",
        ),
    ] {
        assert_eq!(
            GoogleCloudStorageTarget::new(bucket, project, location, prefix),
            Err(RepositoryFailure::InvalidInput)
        );
    }
}
