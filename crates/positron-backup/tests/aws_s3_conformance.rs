//! Runs only on an explicitly authorized, disposable real AWS S3 prefix.
#![cfg(feature = "test-support")]
#[path = "shared/provider_behavior.rs"]
mod provider_behavior;
use positron_backup::*;
use positron_kernel::*;
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn input(name: &str) -> TestResult<String> {
    std::env::var(name).map_err(|_| format!("missing non-secret qualification input {name}").into())
}
fn authorize_target(value: Option<&str>) -> Result<(), &'static str> {
    if value == Some("explicitly-authorized-disposable-prefix") {
        Ok(())
    } else {
        Err("real AWS actions have not been explicitly authorized")
    }
}
#[test]
fn native_service_prerequisites_fail_closed_without_authorization() {
    assert!(authorize_target(None).is_err());
    assert!(authorize_target(Some("1")).is_err());
    assert!(authorize_target(Some("emulator")).is_err());
    assert!(authorize_target(Some("explicitly-authorized-disposable-prefix")).is_ok());
}
fn target() -> TestResult<AwsS3Target> {
    let opt_in = std::env::var("POSITRON_RUN_REAL_AWS_S3").ok();
    authorize_target(opt_in.as_deref())?;
    Ok(AwsS3Target::new(
        &input("POSITRON_AWS_S3_BUCKET")?,
        &input("POSITRON_AWS_S3_REGION")?,
        &input("POSITRON_AWS_S3_ENDPOINT")?,
        &input("POSITRON_AWS_S3_EXPECTED_OWNER")?,
        &input("POSITRON_AWS_S3_PREFIX")?,
    )?)
}
fn authority(path: &std::path::Path) -> TestResult<StorageKernelResourceAuthority> {
    let volume = PrimaryDataVolume::acquire(path, MountQualification::LocalHost)?;
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
    let pool = ResourceAmounts::new([
        536_870_912,
        128,
        32,
        100,
        128,
        32,
        128,
        128,
        128,
        128,
        1_048_576,
    ]);
    let tenant = positron_domain::identity::TenantId::from_bytes([201; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(
            tenant,
            1,
            ResourceAmounts::new([100; 11]),
        )?],
        OrdinaryPoolPolicy::new(pool, two, one, one)?,
    )?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(
            inventory,
            policy,
            RecoveryPoolCapacities::new(three, two, three, two, three, one, one)?,
        )?,
    )?)
}
async fn repository(
    target: &AwsS3Target,
    identity: &RepositoryIdentity,
    resources: &Arc<NativeAwsResources>,
) -> TestResult<AwsS3Repository> {
    Ok(AwsS3Repository::from_admitted_resources(
        target.clone(),
        identity.clone(),
        resources.clone(),
    )
    .await?)
}
async fn native_cases(
    target: &AwsS3Target,
    identity: &RepositoryIdentity,
    resources: &Arc<NativeAwsResources>,
    other_resources: &Arc<NativeAwsResources>,
) -> TestResult {
    let native = repository(target, identity, resources).await?;
    native.initialize().await?;
    provider_behavior::conformance(&native, identity.clone(), Duration::from_secs(30)).await?;
    drop(native);
    let reopened = repository(target, identity, resources).await?;
    assert_eq!(reopened.attach().await?, *identity);
    provider_behavior::conformance(&reopened, identity.clone(), Duration::from_secs(30)).await?;
    // Cross-owner native CAS uses direct conditional publication, not listing.
    let other = repository(target, identity, other_resources).await?;
    let slot = HeadSlot::from_checksum([202; 32]);
    let a = RegistryHeadChange::new(None, b"real AWS first opaque-frame fixture".to_vec())?;
    let b = RegistryHeadChange::new(None, b"real AWS second opaque-frame fixture".to_vec())?;
    let (a, b) = tokio::join!(
        reopened.compare_and_swap_head_at(slot, a),
        other.compare_and_swap_head_at(slot, b)
    );
    let winner = match (a?, b?) {
        (CasOutcome::Published(version), CasOutcome::Conflict(_))
        | (CasOutcome::Conflict(_), CasOutcome::Published(version)) => version,
        _ => return Err("native conditional race did not produce exactly one winner".into()),
    };
    reopened.delete_head_if_version(slot, winner).await?;
    assert!(reopened.registry_head_at(slot).await?.is_none());
    // More than 5 MiB forces the native minimum non-final part boundary.
    let object = ImmutableObject::new(vec![203; 6 * 1024 * 1024])?;
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    let state = reopened.begin_upload(plan).await?;
    let part = UploadPart::new(state, object.bytes().to_vec())?;
    assert!(matches!(
        reopened.resume_upload(part).await?,
        UploadOutcome::Complete(_)
    ));
    assert_eq!(
        other.head(object.id()).await?.checksum(),
        object.id().checksum()
    );
    assert!(other.inspect_upload(plan.id()).await?.is_none());
    other.delete(object.id()).await?;
    assert_eq!(
        other.head(object.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    drop(other);
    drop(reopened);
    // Managed interruption hooks operate around real native calls; they do not
    // replace or fabricate an AWS response. Cold owners must reconcile effects.
    for (index, point) in [
        AwsS3FaultPoint::BeforeNativeCreation,
        AwsS3FaultPoint::AfterNativeCreation,
        AwsS3FaultPoint::BeforeNativeCompletion,
        AwsS3FaultPoint::AfterNativeCompletion,
        AwsS3FaultPoint::BeforeObjectPublication,
        AwsS3FaultPoint::AfterObjectPublication,
    ]
    .into_iter()
    .enumerate()
    {
        let byte = u8::try_from(index)?
            .checked_add(210)
            .ok_or("fixture byte")?;
        let object = ImmutableObject::new(vec![byte; 1024])?;
        let plan = UploadPlan::new(object.id(), 1024)?;
        let interrupted = repository(target, identity, resources)
            .await?
            .with_faults(vec![AwsS3Fault::new(
                point,
                AwsS3FaultEffect::Interrupted,
                0,
            )])?;
        let state = interrupted.begin_upload(plan).await?;
        assert_eq!(
            interrupted
                .resume_upload(UploadPart::new(state, object.bytes().to_vec())?)
                .await,
            Err(RepositoryFailure::Interrupted)
        );
        drop(interrupted);
        let cold = repository(target, identity, resources).await?;
        let state = cold.begin_upload(plan).await?;
        if !state.complete() {
            cold.resume_upload(UploadPart::new(state, object.bytes().to_vec())?)
                .await?;
        }
        assert_eq!(
            cold.head(object.id()).await?.checksum(),
            object.id().checksum()
        );
        assert!(cold.inspect_upload(plan.id()).await?.is_none());
        cold.delete(object.id()).await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires explicitly authorized disposable REAL AWS S3 target and native workload identity; never run against emulators"]
async fn real_aws_s3_passes_shared_and_native_recovery_cases() -> TestResult {
    let target = target()?; // The opt-in is checked before any native credentials or service work.
    let path = fs::canonicalize(std::env::temp_dir())?
        .join(format!("positron-real-s3-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let first_path = path.join("first");
    let second_path = path.join("second");
    for directory in [&first_path, &second_path] {
        fs::create_dir(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let authority = authority(&first_path)?;
    let other_authority = self::authority(&second_path)?;
    let instance = InstanceId::new([204; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([205; 32]), Box::new([206; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([207; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                b"real provider resource owner".to_vec(),
            )?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([208; 16], [209; 32]).map_err(|_| "binding")?;
    let peak = ResourceAmounts::new([268_435_456, 1, 4, 0, 1, 1, 2, 4, 1, 8, 16_384]);
    coordinator
        .submit_repository_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .map_err(|_| "preconditions")?,
            peak,
            1,
        )
        .map_err(|_| "submission")?;
    let mut execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            2,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .map_err(|_| "dispatch")?
        .ok_or("native admission")?;
    let resources = execution
        .transfer_repository_resources(binding)
        .map_err(|_| "handoff")?;
    let other_catalog = Catalog::open(&other_authority, instance, secret())?;
    other_catalog.commit(
        other_catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([215; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                b"second real provider resource owner".to_vec(),
            )?],
        )?,
        None,
    )?;
    let other_coordinator = MaintenanceCoordinator::new();
    let other_binding =
        RepositoryOperationBinding::new([216; 16], [217; 32]).map_err(|_| "other binding")?;
    other_coordinator
        .submit_repository_operation_with_resources_and_persist(
            &other_catalog,
            other_binding,
            MaintenancePreconditions::new(other_catalog.pin()?.number(), 1)
                .map_err(|_| "other preconditions")?,
            peak,
            1,
        )
        .map_err(|_| "other submission")?;
    let mut other_execution = other_coordinator
        .start_next_with_reservation_and_persist_for_class(
            &other_catalog,
            &other_authority,
            2,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .map_err(|_| "other dispatch")?
        .ok_or("other native admission")?;
    let other_resources = other_execution
        .transfer_repository_resources(other_binding)
        .map_err(|_| "other handoff")?;
    let identity = RepositoryIdentity::aws_s3([211; 16], instance.to_bytes(), [212; 32], &target)?;
    let result = tokio::time::timeout(
        Duration::from_secs(300),
        native_cases(&target, &identity, &resources, &other_resources),
    )
    .await
    .map_err(|_| "real AWS case budget exhausted; inspect the same owned prefix before retrying")?;
    execution
        .complete_and_persist(&coordinator, &catalog, result.is_ok())
        .map_err(|_| "terminal publication")?;
    other_execution
        .complete_and_persist(&other_coordinator, &other_catalog, result.is_ok())
        .map_err(|_| "other terminal publication")?;
    drop(other_resources);
    drop(other_execution);
    drop(other_catalog);
    drop(other_authority);
    drop(resources);
    drop(execution);
    drop(catalog);
    drop(authority);
    fs::remove_dir_all(path)?;
    result
}
