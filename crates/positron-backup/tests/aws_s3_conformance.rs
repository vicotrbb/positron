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
    let one = ResourceAmounts::new([1; 11]);
    let two = ResourceAmounts::new([2; 11]);
    let three = ResourceAmounts::new([3; 11]);
    // This published Kernel peak covers Catalog open/recovery and replacement
    // publication. One extra unit preserves system and single-tenant recovery
    // progress required by the Governor. Both Repair and DurabilityCompletion
    // use this peak; the other five protected pools total nine units.
    let claim = integrity_scrub_resource_claim();
    let durability = ResourceAmounts::new(
        ResourceDimension::ALL.map(|dimension| claim.get(dimension).max(1) + 1),
    );
    let recovery = ResourceAmounts::new(
        ResourceDimension::ALL.map(|dimension| 2 * durability.get(dimension) + 9),
    );
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
    let maintenance = ResourceAmounts::new([268_435_456, 1, 4, 1, 1, 1, 2, 4, 1, 8, 16_384]);
    let cardinality = InventoryCardinalityLimits::new(1, 8)?;
    let overhead = cardinality.governor_bootstrap_overhead(1)?;
    let registered = [
        ResourceDimension::QueueSlots,
        ResourceDimension::TaskSlots,
        ResourceDimension::BufferCacheBytes,
        ResourceDimension::BatchItems,
        ResourceDimension::LeaseSlots,
        ResourceDimension::RetrySlots,
        ResourceDimension::IoPermits,
    ]
    .map(|dimension| {
        recovery.get(dimension)
            + pool.get(dimension)
            + maintenance.get(dimension)
            + 4
            + overhead.get(dimension)
    });
    let observed =
        ObservedResourceEnvironment::observe(&volume, RegisteredResourceBounds::new(registered)?)?;
    let detected = observed.detected_capacity();
    let capacity =
        ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| detected.amount(dimension)));
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(capacity)?,
        RecoveryReserve::new(recovery)?,
        cardinality,
        DiskPressureThresholds::new(disk / 10, disk / 5, disk / 3, disk / 2)?,
    )
    .map_err(|e| format!("qualification inventory: {e:?}"))?;
    // Qualification executes only instance-owned work; no synthetic tenant
    // partition may consume the Catalog's protected system recovery capacity.
    let policy = GovernorPolicy::system_only(OrdinaryPoolPolicy::new(pool, two, one, maintenance)?);
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(
            inventory,
            policy,
            RecoveryPoolCapacities::new(durability, two, three, two, durability, one, one)
                .map_err(|e| format!("qualification recovery pools: {e:?}"))?,
        )
        .map_err(|e| format!("qualification governor configuration: {e:?}"))?,
    )
    .map_err(|e| format!("qualification authority: {e:?}"))?)
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
async fn complete_fixture(repository: &dyn Repository, object: &ImmutableObject) -> TestResult {
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    let mut state = repository.begin_upload(plan).await?;
    let part_limit = usize::try_from(MAX_RANGE_BYTES)?;
    for _ in 0..object.bytes().len().div_ceil(part_limit) {
        if state.complete() {
            return Ok(());
        }
        let start = usize::try_from(state.uploaded_bytes())?;
        let end = start
            .checked_add(part_limit)
            .ok_or("fixture part boundary")?
            .min(object.bytes().len());
        let bytes = object
            .bytes()
            .get(start..end)
            .ok_or("fixture committed offset")?
            .to_vec();
        match repository
            .resume_upload(UploadPart::new(state, bytes)?)
            .await?
        {
            UploadOutcome::Complete(_) => return Ok(()),
            UploadOutcome::Pending(next) => {
                assert!(next.uploaded_bytes() > state.uploaded_bytes());
                state = next;
            },
        }
    }
    Err("bounded fixture upload did not complete".into())
}
#[tokio::test]
async fn six_mebibyte_fixture_uses_bounded_interface_parts() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = fs::canonicalize(directory.path())?;
    let identity = RepositoryIdentity::local([221; 16], [222; 16], [223; 32], &path)?;
    let local = LocalRepository::initialize(&path, identity).await?;
    let object = ImmutableObject::new(vec![203; 6 * 1024 * 1024])?;
    complete_fixture(&local, &object).await?;
    assert_eq!(
        local.head(object.id()).await?.checksum(),
        object.id().checksum()
    );
    assert!(
        local
            .inspect_upload(UploadPlan::new(object.id(), object.bytes().len() as u64)?.id())
            .await?
            .is_none()
    );
    Ok(())
}
async fn native_cases(
    target: &AwsS3Target,
    foreign_history_target: &AwsS3Target,
    identity: &RepositoryIdentity,
    resources: &Arc<NativeAwsResources>,
    other_resources: &Arc<NativeAwsResources>,
) -> TestResult {
    // The operator separately prepares/authorizes this prefix with only hidden
    // historical versions/delete markers and independently checks preservation.
    let foreign_identity =
        RepositoryIdentity::aws_s3([224; 16], [225; 16], [226; 32], foreign_history_target)?;
    let foreign = repository(foreign_history_target, &foreign_identity, resources).await?;
    let before = foreign.qualification_hidden_history_snapshot().await?;
    assert_eq!(
        foreign.initialize().await,
        Err(RepositoryFailure::ForeignPrefix)
    );
    assert_eq!(foreign.attach().await, Err(RepositoryFailure::NotFound));
    assert_eq!(
        foreign.qualification_hidden_history_snapshot().await?,
        before
    );
    drop(foreign);
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
    complete_fixture(&reopened, &object).await?;
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
    let foreign_history_target = AwsS3Target::new(
        target.bucket(),
        target.region(),
        target.endpoint(),
        target.expected_owner(),
        &input("POSITRON_AWS_S3_FOREIGN_HISTORY_PREFIX")?,
    )?;
    if target.prefix().starts_with(foreign_history_target.prefix())
        || foreign_history_target.prefix().starts_with(target.prefix())
    {
        return Err("qualification prefixes must be distinct and nonoverlapping".into());
    }
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
        .map_err(|failure| format!("submission: {failure:?}"))?;
    let mut execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            2,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .map_err(|failure| format!("dispatch: {failure:?}"))?
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
        native_cases(
            &target,
            &foreign_history_target,
            &identity,
            &resources,
            &other_resources,
        ),
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

#[tokio::test]
#[ignore = "optional loopback simulation; does not qualify AWS"]
async fn local_s3_simulation_checks_objects_cas_and_unverifiable_multipart() -> TestResult {
    let address: std::net::SocketAddr = input("POSITRON_S3_SIMULATOR_ADDRESS")?.parse()?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "simulation prefix entropy unavailable")?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let target = AwsS3Target::new(
        "positron-102-simulation",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789012",
        &format!("simulation-{nonce}/"),
    )?;
    let identity = RepositoryIdentity::aws_s3([240; 16], [241; 16], [242; 32], &target)?;
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let authority = authority(directory.path())?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([243; 16])?,
        CatalogSecret::from_owned(Box::new([244; 32]), Box::new([245; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([239; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"qualification owner".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([246; 16], [247; 32]).map_err(|_| "binding")?;
    coordinator
        .submit_repository_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .map_err(|_| "preconditions")?,
            ResourceAmounts::new([268_435_456, 1, 4, 0, 1, 1, 2, 4, 1, 8, 16_384]),
            1,
        )
        .map_err(|failure| format!("submission: {failure:?}"))?;
    let mut execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            2,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .map_err(|failure| format!("dispatch: {failure:?}"))?
        .ok_or("simulation admission")?;
    let resources = execution
        .transfer_repository_resources(binding)
        .map_err(|_| "handoff")?;
    let repository =
        AwsS3Repository::from_local_simulator(target, identity.clone(), resources, address)?;
    repository
        .initialize()
        .await
        .map_err(|e| format!("simulation initialize: {e:?}"))?;
    provider_behavior::object_conformance(&repository, identity).await?;
    let slot = HeadSlot::from_checksum([238; 32]);
    let CasOutcome::Published(version) = repository
        .compare_and_swap_head_at(
            slot,
            RegistryHeadChange::new(None, b"simulation registry frame".to_vec())?,
        )
        .await?
    else {
        return Err("simulation registry create did not publish".into());
    };
    assert!(matches!(
        repository
            .compare_and_swap_head_at(
                slot,
                RegistryHeadChange::new(None, b"conflicting simulation frame".to_vec())?
            )
            .await?,
        CasOutcome::Conflict(_)
    ));
    repository.delete_head_if_version(slot, version).await?;
    assert!(repository.registry_head_at(slot).await?.is_none());
    let object = ImmutableObject::new(vec![248; 6 * 1024 * 1024])?;
    // Moto 5.1.22 advertises a composite checksum as a full checksum. Native
    // SDK verification must refuse it, preserving the unfinished owned record.
    assert!(matches!(complete_fixture(&repository, &object).await,
        Err(error) if error.downcast_ref::<RepositoryFailure>() == Some(&RepositoryFailure::OutcomeUnknown)));
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    assert!(repository.inspect_upload(plan.id()).await?.is_some());
    // A subsequent read attempt remains unavailable; it cannot invent completion
    // or discard the original owned recovery record after the uncertain mutation.
    assert_eq!(
        repository.begin_upload(plan).await,
        Err(RepositoryFailure::StorageUnavailable)
    );
    assert!(repository.inspect_upload(plan.id()).await?.is_some());
    assert_eq!(
        repository.head(object.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    drop(repository);
    execution
        .complete_and_persist(&coordinator, &catalog, false)
        .map_err(|_| "completion")?;
    Ok(())
}

#[test]
fn qualification_owner_admits_catalog_repair_publication_and_native_handoff() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let authority = authority(directory.path())?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([249; 16])?,
        CatalogSecret::from_owned(Box::new([250; 32]), Box::new([251; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([239; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"qualification owner".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([252; 16], [253; 32]).map_err(|_| "binding")?;
    coordinator
        .submit_repository_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1)
                .map_err(|_| "preconditions")?,
            ResourceAmounts::new([268_435_456, 1, 4, 0, 1, 1, 2, 4, 1, 8, 16_384]),
            1,
        )
        .map_err(|failure| format!("submission: {failure:?}"))?;
    let mut execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            2,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .map_err(|failure| format!("dispatch: {failure:?}"))?
        .ok_or("native admission")?;
    let resources = execution
        .transfer_repository_resources(binding)
        .map_err(|_| "handoff")?;
    assert!(resources.authorizes_repository_transport());
    let target = AwsS3Target::new(
        "positron-102-simulation",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789012",
        "repository/",
    )?;
    let identity = RepositoryIdentity::aws_s3([240; 16], [241; 16], [242; 32], &target)?;
    assert!(matches!(
        AwsS3Repository::from_local_simulator(
            target,
            identity,
            resources.clone(),
            "192.0.2.1:5000".parse()?
        ),
        Err(RepositoryFailure::InvalidInput)
    ));
    drop(resources);
    execution
        .complete_and_persist(&coordinator, &catalog, true)
        .map_err(|_| "completion")?;
    assert_eq!(
        coordinator
            .status(execution.task().identity())
            .map_err(|_| "status")?
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}
