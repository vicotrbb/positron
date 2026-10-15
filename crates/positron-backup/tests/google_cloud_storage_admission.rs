use positron_backup::{
    GoogleCloudStorageRepository, GoogleCloudStorageTarget, RepositoryFailure, RepositoryIdentity,
};
use positron_kernel::{
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, WorkClaim,
};
use std::{fs, os::unix::fs::PermissionsExt};

#[tokio::test]
async fn native_gcs_requires_admission_before_credential_resolution()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("positron-gcs-admission-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let volume = PrimaryDataVolume::acquire(&path, MountQualification::LocalHost)?;
    let observed =
        ObservedResourceEnvironment::observe(&volume, RegisteredResourceBounds::new([1000; 7])?)?;
    let detected = observed.detected_capacity();
    let capacity =
        ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| detected.amount(dimension)));
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(capacity)?,
        RecoveryReserve::new(ResourceAmounts::new([20; 11]))?,
        InventoryCardinalityLimits::new(1, 8)?,
        DiskPressureThresholds::new(disk / 10, disk / 5, disk / 3, disk / 2)?,
    )?;
    let one = ResourceAmounts::new([1; 11]);
    let two = ResourceAmounts::new([2; 11]);
    let three = ResourceAmounts::new([3; 11]);
    let tenant = positron_domain::identity::TenantId::from_bytes([31; 16])?;
    let policy = GovernorPolicy::new(
        [positron_kernel::TenantQuota::new(
            tenant,
            1,
            ResourceAmounts::new([100; 11]),
        )?],
        OrdinaryPoolPolicy::new(ResourceAmounts::new([100; 11]), two, one, one)?,
    )?;
    let authority = StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(
            inventory,
            policy,
            RecoveryPoolCapacities::new(three, two, three, two, three, one, one)?,
        )?,
    )?;
    let target = GoogleCloudStorageTarget::new(
        "positron-backup",
        "123456789012",
        "US-CENTRAL1",
        "instance/backups/",
    )?;
    let identity = RepositoryIdentity::google_cloud_storage([1; 16], [2; 16], [3; 32], &target)?;
    let governor = authority.governor();
    let grant = governor.reserve(WorkClaim::system_diagnostics(one)?)?;
    assert_eq!(
        GoogleCloudStorageRepository::from_application_default(
            target.clone(),
            identity.clone(),
            grant,
            positron_kernel::RepositoryUploadAuthenticator::new(
                positron_kernel::CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
                positron_kernel::InstanceId::new([2; 16])?
            )
        )
        .await
        .err(),
        Some(RepositoryFailure::LimitExceeded)
    );
    let grant = governor.reserve(WorkClaim::system_diagnostics(one)?)?;
    let resources = positron_kernel::NativeAwsResources::new(grant.transfer());
    assert_eq!(
        GoogleCloudStorageRepository::from_admitted_resources(
            target,
            identity,
            resources,
            positron_kernel::RepositoryUploadAuthenticator::new(
                positron_kernel::CatalogSecret::from_owned(Box::new([31; 32]), Box::new([32; 32])),
                positron_kernel::InstanceId::new([2; 16])?
            )
        )
        .await
        .err(),
        Some(RepositoryFailure::LimitExceeded)
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    drop(authority);
    fs::remove_dir_all(path)?;
    Ok(())
}
