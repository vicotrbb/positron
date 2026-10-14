use positron_backup::{AwsS3Target, RepositoryFailure};

#[test]
fn aws_s3_target_binds_the_exact_native_service_and_rejects_redirected_credentials() {
    let target = AwsS3Target::new(
        "positron-backup",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789012",
        "instance/backups/",
    )
    .expect("native target");
    assert_eq!(target.api_version(), "2006-03-01");
    let moved = AwsS3Target::new(
        "positron-backup",
        "us-west-2",
        "https://s3.us-west-2.amazonaws.com",
        "123456789012",
        "instance/backups/",
    )
    .expect("other region");
    assert_ne!(target.commitment(), moved.commitment());
    for endpoint in [
        "http://s3.us-east-1.amazonaws.com",
        "https://example.com",
        "https://s3.us-east-1.amazonaws.com@evil.example",
        "https://s3.us-east-1.amazonaws.com/?token=secret",
    ] {
        assert_eq!(
            AwsS3Target::new(
                "positron-backup",
                "us-east-1",
                endpoint,
                "123456789012",
                "instance/backups/"
            ),
            Err(RepositoryFailure::InvalidInput)
        );
    }
    assert_eq!(
        AwsS3Target::new(
            "positron-backup",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "123456789012",
            ""
        ),
        Err(RepositoryFailure::InvalidInput)
    );
    assert_eq!(
        AwsS3Target::new(
            "positron-backup",
            "us-east-1",
            "https://s3.us-east-1.amazonaws.com",
            "secret",
            "instance/backups/"
        ),
        Err(RepositoryFailure::InvalidInput)
    );
    assert!(!format!("{target:?}").contains("instance/backups"));
}

#[test]
fn unknown_regions_do_not_create_credential_destinations() {
    for region in [
        "us-east-0",
        "us-east-99",
        "us-unknown-1",
        "us--east-1",
        "us-east1",
        "US-EAST-1",
    ] {
        let endpoint = format!("https://s3.{region}.amazonaws.com");
        assert_eq!(
            AwsS3Target::new(
                "positron-backup",
                region,
                &endpoint,
                "123456789012",
                "instance/backups/"
            ),
            Err(RepositoryFailure::InvalidInput)
        );
    }
}

#[test]
fn remote_identity_cannot_be_reused_for_another_bucket_owner_or_native_provider() {
    use positron_backup::RepositoryIdentity;
    let target = AwsS3Target::new(
        "positron-backup",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789012",
        "instance/backups/",
    )
    .expect("target");
    let identity =
        RepositoryIdentity::aws_s3([1; 16], [2; 16], [3; 32], &target).expect("identity");
    let other = AwsS3Target::new(
        "positron-backup",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789013",
        "instance/backups/",
    )
    .expect("different owner");
    assert_ne!(
        identity,
        RepositoryIdentity::aws_s3([1; 16], [2; 16], [3; 32], &other).expect("other identity")
    );
    assert_eq!(identity.prefix_commitment(), target.commitment());
    assert_eq!(identity.provider_kind(), "awsS3");
    assert_eq!(
        RepositoryIdentity::aws_s3([0; 16], [2; 16], [3; 32], &target),
        Err(RepositoryFailure::InvalidInput)
    );
}

#[test]
fn aws_s3_uses_the_shared_provider_behavior_repository_interface() {
    fn require_repository<T: positron_backup::Repository>() {}
    require_repository::<positron_backup::AwsS3Repository>();
}

#[test]
fn durable_native_locator_preserves_exact_target_and_rejects_extra_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let target = AwsS3Target::new(
        "positron-backup",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789012",
        "owned/",
    )?;
    let locator = target.encode_locator();
    assert_eq!(AwsS3Target::decode_locator(&locator)?, target);
    let extended = format!("{locator}\0credential-value");
    assert_eq!(
        AwsS3Target::decode_locator(&extended),
        Err(RepositoryFailure::InvalidInput)
    );
    assert_eq!(
        AwsS3Target::decode_locator("incomplete"),
        Err(RepositoryFailure::InvalidInput)
    );
    Ok(())
}
