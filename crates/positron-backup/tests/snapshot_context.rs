use positron_backup::{
    BackupCaptureContext, BackupKeyEnvelope, BackupPublisher, BackupRepositoryRegistration,
    BackupRetention, RepositoryIdentity,
};

#[test]
fn captured_envelopes_and_registered_repository_survive_cold_decoding()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "positron-capture-context-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&root)?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &root)?;
    let first = BackupKeyEnvelope::new([4; 16], 7, [5; 32], vec![6; 128])?;
    let rotated = BackupKeyEnvelope::new([4; 16], 7, [5; 32], vec![8; 128])?;
    let context = BackupCaptureContext::new(
        identity.clone(),
        BackupRetention::new(1000, 2000)?,
        vec![first.clone()],
    )?;
    let bytes = context.encode()?;
    let cold = BackupCaptureContext::decode(&bytes, &identity)?;
    assert_eq!(cold.keys(), &[first]);
    assert_ne!(cold.keys(), std::slice::from_ref(&rotated));
    assert_eq!(
        cold.key_context()?,
        BackupPublisher::key_context(&[rotated])?
    );
    assert_eq!(cold.encode()?, bytes);
    assert!(BackupCaptureContext::decode(&bytes[..bytes.len() - 1], &identity).is_err());
    let wrong = RepositoryIdentity::local([9; 16], [2; 16], [3; 32], &root)?;
    assert!(BackupCaptureContext::decode(&bytes, &wrong).is_err());
    let registration =
        BackupRepositoryRegistration::new(identity.clone(), root.to_str().ok_or("path")?)?;
    let binding = registration.binding_identity()?;
    let anchored = registration.with_registry_generation([42; 32])?;
    assert_eq!(anchored.binding_identity()?, binding);
    assert_eq!(
        BackupRepositoryRegistration::decode(&anchored.encode()?)?
            .ok_or("anchored registration")?
            .registry_generation(),
        Some([42; 32])
    );
    let object = anchored.catalog_object()?;
    let registration = anchored;
    let decoded = BackupRepositoryRegistration::decode(&object_bytes(&registration)?)?
        .ok_or("registration")?;
    assert_eq!(decoded.identity(), &identity);
    assert_eq!(decoded.catalog_object()?.identity(), object.identity());
    assert!(BackupRepositoryRegistration::decode(b"POSBPR01corrupt").is_err());
    assert!(BackupRepositoryRegistration::decode(b"other Catalog owner")?.is_none());
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn object_bytes(
    registration: &BackupRepositoryRegistration,
) -> Result<Vec<u8>, positron_backup::RepositoryFailure> {
    registration.encode()
}

#[test]
fn native_registered_targets_round_trip_canonical_non_secret_locators()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{AwsS3Target, AzureBlobTarget, GoogleCloudStorageTarget};
    let aws = AwsS3Target::new(
        "positron-backup",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789012",
        "owned/",
    )?;
    let google =
        GoogleCloudStorageTarget::new("positron-backup", "123456789012", "US-CENTRAL1", "owned/")?;
    let azure = AzureBlobTarget::new("positronbackup", "backups", "owned/")?;
    for (identity, locator) in [
        (
            RepositoryIdentity::aws_s3([1; 16], [2; 16], [3; 32], &aws)?,
            aws.encode_locator(),
        ),
        (
            RepositoryIdentity::google_cloud_storage([1; 16], [2; 16], [3; 32], &google)?,
            google.encode_locator(),
        ),
        (
            RepositoryIdentity::azure_blob([1; 16], [2; 16], [3; 32], &azure)?,
            azure.encode_locator(),
        ),
    ] {
        assert!(locator.contains('\0'));
        let registration = BackupRepositoryRegistration::new(identity.clone(), &locator)?;
        assert_eq!(
            registration.binding_identity()?,
            registration.catalog_object()?.identity().to_bytes()
        );
        let cold = BackupRepositoryRegistration::decode(&registration.encode()?)?
            .ok_or("native registration")?;
        assert_eq!(cold.identity(), &identity);
        assert_eq!(cold.locator(), locator);
        for invalid in [
            format!("{locator}\0"),
            format!("{locator}\n"),
            format!("{locator}\u{7f}"),
        ] {
            assert!(BackupRepositoryRegistration::new(identity.clone(), &invalid).is_err());
        }
    }
    Ok(())
}
