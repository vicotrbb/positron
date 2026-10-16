//! Only an explicitly authorized real GCS JSON API v1 target qualifies GCS.
#![cfg(feature = "test-support")]
#[path = "shared/read_only_repository.rs"]
mod read_only_repository;

#[path = "shared/native_authority.rs"]
mod native_authority;
#[path = "shared/provider_behavior.rs"]
mod provider_behavior;
use positron_backup::*;
use positron_kernel::*;
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn authorize(value: Option<&str>) -> Result<(), &'static str> {
    if value == Some("explicitly-authorized-disposable-prefix") {
        Ok(())
    } else {
        Err("real GCS actions require explicitly authorized disposable target")
    }
}
#[test]
fn real_google_prerequisites_fail_closed() {
    assert!(authorize(None).is_err());
    assert!(authorize(Some("emulator")).is_err());
    assert!(authorize(Some("explicitly-authorized-disposable-prefix")).is_ok());
}
fn input(name: &str) -> TestResult<String> {
    std::env::var(name).map_err(|_| format!("missing non-secret qualification input {name}").into())
}
async fn complete(repository: &dyn Repository, object: &ImmutableObject) -> TestResult {
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    let mut state = repository.begin_upload(plan).await?;
    for _ in 0..16 {
        if state.complete() {
            return Ok(());
        }
        let start = usize::try_from(state.uploaded_bytes())?;
        let end = (start + MAX_RANGE_BYTES as usize).min(object.bytes().len());
        match repository
            .resume_upload(UploadPart::new(
                state,
                object
                    .bytes()
                    .get(start..end)
                    .ok_or("upload extent")?
                    .to_vec(),
            )?)
            .await?
        {
            UploadOutcome::Complete(_) => return Ok(()),
            UploadOutcome::Pending(next) => {
                assert!(next.uploaded_bytes() > state.uploaded_bytes());
                state = next;
            },
        }
    }
    Err("bounded native upload did not finish".into())
}
async fn native_cases(
    target: &GoogleCloudStorageTarget,
    identity: &RepositoryIdentity,
    foreign: &GoogleCloudStorageTarget,
    resources: Arc<NativeAwsResources>,
    marker: [u8; 32],
    wrapping: [u8; 32],
) -> TestResult {
    let repository = GoogleCloudStorageRepository::from_admitted_resources(
        target.clone(),
        identity.clone(),
        resources.clone(),
        RepositoryUploadAuthenticator::new(
            CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
            InstanceId::new(identity.instance_id())?,
        ),
    )
    .await?;
    let foreign_identity = RepositoryIdentity::google_cloud_storage(
        [217; 16],
        identity.instance_id(),
        identity.integrity_fingerprint(),
        foreign,
    )?;
    let fixture = GoogleCloudStorageRepository::from_admitted_resources(
        foreign.clone(),
        foreign_identity,
        resources.clone(),
        RepositoryUploadAuthenticator::new(
            CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
            InstanceId::new(identity.instance_id())?,
        ),
    )
    .await?;
    let before = fixture.qualification_foreign_soft_history_digest().await?;
    assert_eq!(
        fixture.initialize().await,
        Err(RepositoryFailure::ForeignPrefix)
    );
    assert_eq!(
        fixture.attach().await.err(),
        Some(RepositoryFailure::NotFound)
    );
    assert_eq!(
        fixture.qualification_foreign_soft_history_digest().await?,
        before
    );
    repository.initialize().await?;
    assert_eq!(repository.attach().await?, *identity);
    provider_behavior::conformance(&repository, identity.clone(), Duration::from_secs(60)).await?;
    assert_eq!(
        repository.storage_policy().await?.versioning,
        PolicyObservation::Observed(VersioningPolicy::Enabled)
    );
    controlled_cases::concurrent_identity_and_corruption_cases(
        &repository,
        target,
        identity,
        resources.clone(),
        marker,
        wrapping,
    )
    .await?;
    let slot = HeadSlot::from_checksum([218; 32]);
    let first = match repository
        .compare_and_swap_head_at(
            slot,
            RegistryHeadChange::new(None, b"first signed fixture".to_vec())?,
        )
        .await?
    {
        CasOutcome::Published(version) => version,
        _ => return Err("fixture head collision".into()),
    };
    let second = match repository
        .compare_and_swap_head_at(
            slot,
            RegistryHeadChange::new(Some(first), b"second signed fixture".to_vec())?,
        )
        .await?
    {
        CasOutcome::Published(version) => version,
        _ => return Err("fixture CAS conflict".into()),
    };
    let interrupted = GoogleCloudStorageRepository::from_admitted_resources(
        target.clone(),
        identity.clone(),
        resources.clone(),
        RepositoryUploadAuthenticator::new(
            CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
            InstanceId::new(identity.instance_id())?,
        ),
    )
    .await?
    .with_faults(vec![GoogleCloudStorageFault::new(
        GoogleCloudStorageFaultPoint::AfterVersionDeletion,
        GoogleCloudStorageFaultEffect::OutcomeUnknown,
        0,
    )])?;
    assert_eq!(
        interrupted.delete_head_if_version(slot, second).await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert!(repository.registry_head_at(slot).await?.is_none());
    assert_eq!(
        repository.delete_head_if_version(slot, second).await?,
        DeleteOutcome::Deleted
    );
    let sized = ImmutableObject::new(b"size bound regression".to_vec())?;
    let mismatched = repository
        .begin_upload(UploadPlan::new(sized.id(), sized.bytes().len() as u64 + 1)?)
        .await?;
    repository.abort_upload(mismatched.id()).await?;
    repository.put_if_absent(sized.clone()).await?;
    assert_eq!(
        repository
            .resume_upload(UploadPart::new(mismatched, sized.bytes().to_vec())?)
            .await,
        Err(RepositoryFailure::ChecksumMismatch)
    );
    repository.delete(sized.id()).await?;
    let object = ImmutableObject::new(vec![213; 6 * 1024 * 1024])?;
    complete(&repository, &object).await?;
    assert_eq!(
        repository.head(object.id()).await?.checksum(),
        object.id().checksum()
    );
    repository.delete(object.id()).await?;
    for (point, byte) in [
        (GoogleCloudStorageFaultPoint::AfterNativeComplete, 214),
        (GoogleCloudStorageFaultPoint::BeforeFinalPublication, 215),
    ] {
        let interrupted = GoogleCloudStorageRepository::from_admitted_resources(
            target.clone(),
            identity.clone(),
            resources.clone(),
            RepositoryUploadAuthenticator::new(
                CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
                InstanceId::new(identity.instance_id())?,
            ),
        )
        .await?
        .with_faults(vec![GoogleCloudStorageFault::new(
            point,
            GoogleCloudStorageFaultEffect::OutcomeUnknown,
            0,
        )])?;
        let object = ImmutableObject::new(vec![byte; 6 * 1024 * 1024])?;
        assert!(complete(&interrupted, &object).await.is_err());
        complete(&repository, &object).await?;
        assert_eq!(
            repository.head(object.id()).await?.checksum(),
            object.id().checksum()
        );
        repository.delete(object.id()).await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires explicitly authorized disposable real GCS target; UNRUN without inputs"]
async fn real_google_passes_shared_and_native_recovery_cases() -> TestResult {
    authorize(std::env::var("POSITRON_RUN_REAL_GCS").ok().as_deref())?;
    let target = GoogleCloudStorageTarget::new(
        &input("POSITRON_GCS_BUCKET")?,
        &input("POSITRON_GCS_PROJECT_NUMBER")?,
        &input("POSITRON_GCS_LOCATION")?,
        &input("POSITRON_GCS_PREFIX")?,
    )?;
    let foreign = GoogleCloudStorageTarget::new(
        target.bucket(),
        target.project_number(),
        target.location(),
        &input("POSITRON_GCS_FOREIGN_SOFT_PREFIX")?,
    )?;
    if target.prefix().starts_with(foreign.prefix())
        || foreign.prefix().starts_with(target.prefix())
    {
        return Err("qualification prefixes overlap".into());
    }
    admitted(
        target,
        Duration::from_secs(300),
        false,
        move |target, identity, resources, marker, wrapping| async move {
            native_cases(&target, &identity, &foreign, resources, marker, wrapping).await
        },
    )
    .await
}

// Shared fixture admission stays under the existing Kernel/Maintenance owner.
async fn admitted<F, Fut>(
    target: GoogleCloudStorageTarget,
    budget: Duration,
    retain: bool,
    case: F,
) -> TestResult
where
    F: FnOnce(
        GoogleCloudStorageTarget,
        RepositoryIdentity,
        Arc<NativeAwsResources>,
        [u8; 32],
        [u8; 32],
    ) -> Fut,
    Fut: std::future::Future<Output = TestResult>,
{
    // All native selectors are validated before ADC or service contact.
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = fs::canonicalize(directory.path())?;
    let mut amounts =
        ResourceDimension::ALL.map(|d| GoogleCloudStorageRepository::required_resources().get(d));
    if let Some(value) = amounts.get_mut(4) {
        *value = 1;
    }
    if let Some(value) = amounts.get_mut(10) {
        *value = 16384;
    }
    let peak = ResourceAmounts::new(amounts);
    let authority =
        native_authority::authority(&path, peak).map_err(|e| format!("authority: {e}"))?;
    let instance = InstanceId::new([201; 16])?;
    let mut marker = [0; 32];
    let mut wrapping = [0; 32];
    getrandom::fill(&mut marker)?;
    getrandom::fill(&mut wrapping)?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
    )
    .map_err(|e| format!("catalog open: {e}"))?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([202; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"native GCS resource owner".to_vec())?],
        )?,
        None,
    )?;
    let mut keys = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join("fixture-keys"))?;
    fs::set_permissions(path.join("fixture-keys"), fs::Permissions::from_mode(0o600))?;
    use std::io::Write;
    keys.write_all(&marker)?;
    keys.write_all(&wrapping)?;
    keys.sync_all()?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([203; 16], [204; 32]).map_err(|_| "binding")?;
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
        .ok_or("admission")?;
    let resources = execution
        .transfer_repository_resources(binding)
        .map_err(|_| "handoff")?;
    let identity = RepositoryIdentity::google_cloud_storage(
        [205; 16],
        instance.to_bytes(),
        [206; 32],
        &target,
    )?;
    let mut result = tokio::time::timeout(
        budget,
        case(target, identity, resources.clone(), marker, wrapping),
    )
    .await
    .unwrap_or_else(|_| {
        Err("native GCS budget exhausted; inspect same owned prefix before retry".into())
    });
    if execution
        .complete_and_persist(&coordinator, &catalog, result.is_ok())
        .is_err()
    {
        result = Err("fixture terminal publication failed".into());
    }
    drop(resources);
    drop(execution);
    drop(catalog);
    drop(authority);
    if result.is_err() || retain {
        let retained = directory.keep();
        eprintln!(
            "real GCS fixture retains owned artifacts/custody at {}",
            retained.display()
        );
    }
    result
}

#[path = "shared/google_controlled_cases.rs"]
mod controlled_cases;

#[tokio::test]
async fn simulated_native_protocol_conformance() -> TestResult {
    let server = simulator::Server::start()?;
    let address = server.address;
    let replies = server.replies.clone();
    let race = server.race.clone();
    let target = GoogleCloudStorageTarget::new("simulation-bucket", "123", "US", "owned/")?;
    admitted(
        target,
        Duration::from_secs(120),
        false,
        |target, identity, resources, marker, wrapping| async move {
            let instance_id = InstanceId::new(identity.instance_id())?;
            let make = || {
                GoogleCloudStorageRepository::from_local_simulator(
                    target.clone(),
                    identity.clone(),
                    resources.clone(),
                    RepositoryUploadAuthenticator::new(
                        CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
                        instance_id,
                    ),
                    address,
                )
            };
            let repository = make()?;
            let inject_bucket = |status, headers: &str, value| {
                replies.lock().expect("fixture replies").push_back(("GET /storage/v1/b/simulation-bucket".into(),status,headers.into(),value));
            };
            inject_bucket(403,"",serde_json::json!({"error":"private deny reason"}));
            assert_eq!(repository.initialize().await,Err(RepositoryFailure::PermissionDenied));
            inject_bucket(429,"Retry-After: 30\r\n",serde_json::json!({"error":"private throttling reason"}));
            assert_eq!(repository.initialize().await,Err(RepositoryFailure::Throttled {retry_after_millis:30000}));
            inject_bucket(200,"",serde_json::json!({"name":"simulation-bucket","projectNumber":"124","location":"US"}));
            assert_eq!(repository.initialize().await,Err(RepositoryFailure::IdentityMismatch));
            inject_bucket(200,"",serde_json::json!({"name":"simulation-bucket","projectNumber":"123","location":"EU"}));
            assert_eq!(repository.initialize().await,Err(RepositoryFailure::IdentityMismatch));
            let foreign_target=GoogleCloudStorageTarget::new("simulation-bucket","123","US","foreign/")?;
            let foreign_identity=RepositoryIdentity::google_cloud_storage([77;16],identity.instance_id(),identity.integrity_fingerprint(),&foreign_target)?;
            let foreign=GoogleCloudStorageRepository::from_local_simulator(foreign_target,foreign_identity,resources.clone(),RepositoryUploadAuthenticator::new(CatalogSecret::from_owned(Box::new(marker),Box::new(wrapping)),instance_id),address)?;
            replies.lock().expect("fixture replies").extend([
                ("GET /storage/v1/b/simulation-bucket/o".into(),200,String::new(),serde_json::json!({"items":[]})),
                ("GET /storage/v1/b/simulation-bucket/o".into(),200,String::new(),serde_json::json!({"items":[{"name":"foreign/deleted"}]})),
            ]);
            assert_eq!(foreign.initialize().await,Err(RepositoryFailure::ForeignPrefix));
            repository.initialize().await?;
            let read_only = GoogleCloudStorageRepository::read_only_from_local_simulator(target.clone(), identity.clone(), resources.clone(), address)?;
            assert_eq!(read_only.initialize().await, Err(RepositoryFailure::PermissionDenied));
            read_only_repository::conformance(&read_only, &repository).await?;

            provider_behavior::conformance(&repository, identity.clone(), Duration::from_secs(60))
                .await?;
            assert_eq!(
                repository.storage_policy().await?.versioning,
                PolicyObservation::Observed(VersioningPolicy::Enabled)
            );
            let controls=serde_json::json!({"name":"simulation-bucket","projectNumber":"123","location":"US","versioning":{"enabled":true},"retentionPolicy":{"retentionPeriod":"3600","isLocked":true},"defaultEventBasedHold":true,"softDeletePolicy":{"retentionDurationSeconds":"86400"},"lifecycle":{"rule":[{"action":{"type":"Delete"},"condition":{"isLive":true}}]}});
            inject_bucket(200,"",controls.clone()); inject_bucket(200,"",controls);
            let policy=repository.storage_policy().await?;
            assert_eq!(policy.soft_delete,Some(PolicyObservation::Observed(86400)));
            assert_eq!(policy.object_lock,PolicyObservation::Observed(ObjectLockPolicy::Enabled {default_retention:Some(RetentionPolicy {mode:RetentionMode::Compliance,period:RetentionPeriod::Seconds(3600)})}));
            assert!(matches!(policy.lifecycle,PolicyObservation::Observed(LifecyclePolicy {current_expiration:true,..})));
            repository
                .qualification_content_corruption([89; 32])
                .await?;
            let listed = [ImmutableObject::new(b"page one".to_vec())?,
                ImmutableObject::new(b"page two".to_vec())?];
            for object in &listed { repository.put_if_absent(object.clone()).await?; }
            let first_page = repository.list(ListRequest::new(ListKind::Objects, None, 1)?).await?;
            let cursor = first_page.next_cursor().cloned().ok_or("native pagination cursor")?;
            assert_eq!(make()?.list(ListRequest::new(ListKind::Objects, Some(cursor.clone()), 1)?).await,
                Err(RepositoryFailure::InvalidInput));
            let second_page = repository.list(ListRequest::new(ListKind::Objects, Some(cursor.clone()), 1)?).await?;
            assert_eq!(second_page.entries().len(), 1);
            assert!(second_page.next_cursor().is_none());
            assert_eq!(repository.list(ListRequest::new(ListKind::Objects, Some(cursor), 1)?).await,
                Err(RepositoryFailure::InvalidInput));
            for object in &listed { repository.delete(object.id()).await?; }
            let slot = HeadSlot::from_checksum([91; 32]);
            let first = match repository
                .compare_and_swap_head_at(slot, RegistryHeadChange::new(None, b"first".to_vec())?)
                .await?
            {
                CasOutcome::Published(v) => v,
                _ => return Err("create conflict".into()),
            };
            let second = match repository
                .compare_and_swap_head_at(
                    slot,
                    RegistryHeadChange::new(Some(first), b"second".to_vec())?,
                )
                .await?
            {
                CasOutcome::Published(v) => v,
                _ => return Err("update conflict".into()),
            };
            assert!(matches!(
                repository
                    .compare_and_swap_head_at(
                        slot,
                        RegistryHeadChange::new(Some(first), b"stale".to_vec())?
                    )
                    .await?,
                CasOutcome::Conflict(_)
            ));
            let interrupted = make()?.with_faults(vec![GoogleCloudStorageFault::new(
                GoogleCloudStorageFaultPoint::AfterVersionDeletion,
                GoogleCloudStorageFaultEffect::OutcomeUnknown,
                0,
            )])?;
            assert_eq!(
                interrupted.delete_head_if_version(slot, second).await,
                Err(RepositoryFailure::OutcomeUnknown)
            );
            assert!(repository.registry_head_at(slot).await?.is_none());
            assert_eq!(
                repository.delete_head_if_version(slot, second).await?,
                DeleteOutcome::Deleted
            );
            let race_slot = HeadSlot::from_checksum([73; 32]);
            let source_slot = HeadSlot::from_checksum([74; 32]);
            let expected = match repository.compare_and_swap_head_at(
                race_slot, RegistryHeadChange::new(None, b"old head".to_vec())?,
            ).await? {
                CasOutcome::Published(version) => version,
                _ => return Err("race old head".into()),
            };
            let successor = match repository.compare_and_swap_head_at(
                source_slot, RegistryHeadChange::new(None, b"independent successor".to_vec())?,
            ).await? {
                CasOutcome::Published(version) => version,
                _ => return Err("race successor".into()),
            };
            let race_name = "49".repeat(32);
            let source_name = "4a".repeat(32);
            *race.lock().expect("race control") = Some((
                format!("/storage/v1/b/simulation-bucket/o/owned%2Fh-{race_name}"),
                format!("owned/h-{source_name}"),
            ));
            assert_eq!(repository.delete_head_if_version(race_slot, expected).await,
                Err(RepositoryFailure::PreconditionFailed));
            assert_eq!(repository.registry_head_at(race_slot).await?.map(|head| head.version()),
                Some(successor));
            repository.delete_head_if_version(race_slot, successor).await?;
            repository.delete_head_if_version(source_slot, successor).await?;
            let object = ImmutableObject::new(vec![93; 6 * 1024 * 1024])?;
            complete(&repository, &object).await?;
            assert_eq!(
                repository.head(object.id()).await?.checksum(),
                object.id().checksum()
            );
            repository.delete(object.id()).await?;
            for (point, byte) in [
                (GoogleCloudStorageFaultPoint::AfterNativeComplete, 94),
                (GoogleCloudStorageFaultPoint::BeforeFinalPublication, 95),
            ] {
                let interrupted = make()?.with_faults(vec![GoogleCloudStorageFault::new(
                    point,
                    GoogleCloudStorageFaultEffect::OutcomeUnknown,
                    0,
                )])?;
                let object = ImmutableObject::new(vec![byte; 6 * 1024 * 1024])?;
                assert!(complete(&interrupted, &object).await.is_err());
                complete(&make()?, &object).await?;
                assert!(
                    repository
                        .inspect_upload(
                            UploadPlan::new(object.id(), object.bytes().len() as u64)?.id()
                        )
                        .await?
                        .is_none()
                );
                repository.delete(object.id()).await?;
            }
            // Requested Create without durable URI is retained across cold attach.
            let ambiguous = make()?.with_faults(vec![GoogleCloudStorageFault::new(
                GoogleCloudStorageFaultPoint::AfterNativeCreate,
                GoogleCloudStorageFaultEffect::OutcomeUnknown,
                0,
            )])?;
            let object = ImmutableObject::new(b"unknown native session authority".to_vec())?;
            let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
            let state = ambiguous.begin_upload(plan).await?;
            assert_eq!(
                ambiguous
                    .resume_upload(UploadPart::new(state, object.bytes().to_vec())?)
                    .await,
                Err(RepositoryFailure::OutcomeUnknown)
            );
            assert_eq!(
                make()?.begin_upload(plan).await,
                Err(RepositoryFailure::OutcomeUnknown)
            );
            assert_eq!(
                make()?.abort_upload(plan.id()).await,
                Err(RepositoryFailure::OutcomeUnknown)
            );
            assert_eq!(repository.head(object.id()).await,Err(RepositoryFailure::NotFound));
            let wrong_custody=GoogleCloudStorageRepository::from_local_simulator(target.clone(),identity.clone(),resources.clone(),RepositoryUploadAuthenticator::new(CatalogSecret::from_owned(Box::new([1;32]),Box::new(wrapping)),instance_id),address)?;
            assert_eq!(wrong_custody.inspect_upload(plan.id()).await,Err(RepositoryFailure::ChecksumMismatch));
            Ok(())
        },
    )
    .await
}
#[path = "shared/google_simulator.rs"]
mod simulator;

#[tokio::test]
async fn native_google_tenant_key_purge_retains_permanent_fence() -> TestResult {
    let server = simulator::Server::start()?;
    let target = GoogleCloudStorageTarget::new("simulation-bucket", "123", "US", "owned/")?;
    admitted(target,Duration::from_secs(60),false,|target, identity, resources, marker, wrapping| async move {
        let directory=tempfile::tempdir()?;
        fs::set_permissions(directory.path(),fs::Permissions::from_mode(0o700))?;
        let custody=BootstrapKeyCustody::initialize(directory.path())?;
        let instance=InstanceId::new(identity.instance_id())?;
        let protected=custody.protect(instance,BootstrapObjectPurpose::Initialized,&[7;32])?;
        let signer=custody.backup_control_signer(instance,&protected)?;
        let identity=RepositoryIdentity::google_cloud_storage(identity.repository_id(),identity.instance_id(),signer.identity().fingerprint(),&target)?;
        let make=|| GoogleCloudStorageRepository::from_local_simulator(target.clone(),identity.clone(),resources.clone(),
            RepositoryUploadAuthenticator::new(CatalogSecret::from_owned(Box::new(marker),Box::new(wrapping)),instance),server.address);
        let repository=make()?;
        repository.initialize().await?;
        let ordinary=ImmutableObject::new(b"POSBKF01ordinary checksum-addressed content".to_vec())?;
        repository.put_if_absent(ordinary.clone()).await?;
        assert_eq!(repository.head(ordinary.id()).await?.size(),ordinary.bytes().len() as u64);
        repository.delete(ordinary.id()).await?;
        let object=ImmutableObject::new(vec![45;64])?;
        let key=format!("owned/o-{}",object.id().checksum().iter().map(|b|format!("{b:02x}")).collect::<String>());
        *server.delayed.target.lock().map_err(|_|"delay lock")?=Some(format!("/upload/storage/v1/b/simulation-bucket/o?uploadType=media&name={}&ifGenerationMatch=0",key.replace('/',"%2F")));
        let late_repository=make()?;
        let late_object=object.clone();
        let late=tokio::spawn(async move { late_repository.put_if_absent(late_object).await });
        tokio::time::timeout(Duration::from_secs(5),async {
            while !server.delayed.waiting.load(std::sync::atomic::Ordering::Acquire) { tokio::task::yield_now().await; }
        }).await?;
        repository.put_if_absent(object.clone()).await?;
        let tombstone=BackupPurgeTombstone::new([3;16],"default",[9;16],10)?;
        let fence=TenantKeyPurgeFence::new(object.id(),&tombstone,&identity,&signer)?;
        server.replies.lock().map_err(|_|"replies lock")?.push_back(("POST /upload/storage/v1/b/simulation-bucket/o".into(),503,String::new(),serde_json::json!({})));
        assert!(Repository::delete_tenant_key(&repository,object.id(),&fence).await.is_err());
        let interrupted=make()?.with_faults(vec![GoogleCloudStorageFault::new(GoogleCloudStorageFaultPoint::AfterVersionDeletion,GoogleCloudStorageFaultEffect::OutcomeUnknown,0)])?;
        assert_eq!(Repository::delete_tenant_key(&interrupted,object.id(),&fence).await,Err(RepositoryFailure::OutcomeUnknown));
        assert_eq!(repository.head(object.id()).await,Err(RepositoryFailure::NotFound));
        assert_eq!(Repository::delete_tenant_key(&repository,object.id(),&fence).await?,DeleteOutcome::AlreadyAbsent);
        server.delayed.release.store(true,std::sync::atomic::Ordering::Release);
        assert!(late.await?.is_err());
        assert_eq!(server.delayed.status.load(std::sync::atomic::Ordering::Acquire),412);
        assert_eq!(repository.head(object.id()).await,Err(RepositoryFailure::NotFound));
        assert_eq!(repository.read_range(ObjectRange::new(object.id(),0,1)?).await?.bytes(),b"P");
        assert_eq!(repository.read_range(ObjectRange::new(object.id(),0,fence.bytes().len() as u64)?).await,Err(RepositoryFailure::NotFound));
        assert!(repository.put_if_absent(object.clone()).await.is_err());
        assert!(repository.delete(object.id()).await.is_err());
        assert_eq!(Repository::delete_tenant_key(&repository,object.id(),&fence).await?,DeleteOutcome::AlreadyAbsent);
        // The native inventory independently proves secret history was removed.
        use std::io::{Read, Write};
        let mut inventory=std::net::TcpStream::connect(server.address)?;
        inventory.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(inventory,"GET /storage/v1/b/simulation-bucket/o?prefix={key}&maxResults=64&versions=true HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut raw=String::new();
        inventory.read_to_string(&mut raw)?;
        assert!(raw.starts_with("HTTP/1.1 200 "));
        let (_,body)=raw.split_once("\r\n\r\n").ok_or("native inventory body")?;
        let inventory:serde_json::Value=serde_json::from_str(body)?;
        assert_eq!(inventory["items"].as_array().ok_or("native items")?.len(),1);
        assert_eq!(inventory["items"][0]["name"],key);
        assert!(inventory.get("nextPageToken").is_none());
        let other_tombstone=BackupPurgeTombstone::new([3;16],"default",[10;16],11)?;
        let other_fence=TenantKeyPurgeFence::new(object.id(),&other_tombstone,&identity,&signer)?;
        assert!(Repository::delete_tenant_key(&repository,object.id(),&other_fence).await.is_err());
        assert_eq!(Repository::delete_tenant_key(&repository,object.id(),&fence).await?,DeleteOutcome::AlreadyAbsent);
        let absent=ImmutableObject::new(vec![46;64])?;
        let absent_fence=TenantKeyPurgeFence::new(absent.id(),&tombstone,&identity,&signer)?;
        assert!(Repository::delete_tenant_key(&repository,absent.id(),&fence).await.is_err());
        assert_eq!(Repository::delete_tenant_key(&repository,absent.id(),&absent_fence).await?,DeleteOutcome::Deleted);
        assert_eq!(repository.object_size_hint(absent.id()).await?,absent_fence.bytes().len() as u64);
        assert!(repository.put_if_absent(absent.clone()).await.is_err());
        assert!(repository.delete(absent.id()).await.is_err());
        assert_eq!(Repository::delete_tenant_key(&repository,absent.id(),&absent_fence).await?,DeleteOutcome::AlreadyAbsent);
        Ok(())
    }).await
}
