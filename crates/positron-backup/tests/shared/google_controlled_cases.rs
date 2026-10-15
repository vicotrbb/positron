//! Each ignored case requires its own explicitly authorized real fixture.
use super::*;
#[derive(Clone, Copy)]
enum Case {
    Denial,
    Throttle,
    Renewal,
    Retention,
    EventHold,
    LifecycleConflict,
    SoftDelete,
    TemporaryHold,
    PrepareHold,
    AmbiguousCreate,
}
impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::Denial => "denial",
            Self::Throttle => "throttle",
            Self::Renewal => "renewal",
            Self::Retention => "retention",
            Self::EventHold => "event-hold",
            Self::LifecycleConflict => "lifecycle-conflict",
            Self::SoftDelete => "soft-delete",
            Self::TemporaryHold => "temporary-hold",
            Self::PrepareHold => "prepare-hold",
            Self::AmbiguousCreate => "ambiguous-create",
        }
    }
}
fn authorize_case(case: Case, value: Option<&str>) -> TestResult {
    if value == Some(case.name()) {
        Ok(())
    } else {
        Err("exact independently authorized native GCS fixture case required".into())
    }
}
#[test]
fn controlled_fixtures_require_exact_case_authorization() {
    assert!(authorize_case(Case::Denial, None).is_err());
    assert!(
        authorize_case(
            Case::Denial,
            Some("explicitly-authorized-disposable-prefix")
        )
        .is_err()
    );
    assert!(authorize_case(Case::Denial, Some("throttle")).is_err());
    assert!(authorize_case(Case::Denial, Some("denial")).is_ok());
}
fn checksum_input() -> TestResult<ObjectId> {
    let text = input("POSITRON_GCS_HELD_OBJECT_CHECKSUM")?;
    if text.len() != 64 {
        return Err("held object checksum must be 64 hex digits".into());
    }
    let mut bytes = [0; 32];
    for (out, chunk) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *out = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(ObjectId::from_checksum(bytes))
}
async fn controlled(case: Case) -> TestResult {
    // An environment marker is a prerequisite, never a grant of authority.
    authorize_case(
        case,
        std::env::var("POSITRON_RUN_REAL_GCS_NATIVE_CASE")
            .ok()
            .as_deref(),
    )?;
    let target = GoogleCloudStorageTarget::new(
        &input("POSITRON_GCS_BUCKET")?,
        &input("POSITRON_GCS_PROJECT_NUMBER")?,
        &input("POSITRON_GCS_LOCATION")?,
        &input("POSITRON_GCS_PREFIX")?,
    )?;
    let renewal = if matches!(case, Case::Renewal) {
        let initial: u64 = input("POSITRON_GCS_INITIAL_TOKEN_EXPIRES_IN_SECONDS")?.parse()?;
        let wait: u64 = input("POSITRON_GCS_RENEWAL_DELAY_SECONDS")?.parse()?;
        if initial == 0 || wait <= initial || wait > 7200 {
            return Err(
                "renewal fixture must outwait recorded initial token expiry within two hours"
                    .into(),
            );
        }
        Some(wait)
    } else {
        None
    };
    let held = if matches!(case, Case::TemporaryHold) {
        Some(checksum_input()?)
    } else {
        None
    };
    let retain = matches!(
        case,
        Case::Retention
            | Case::EventHold
            | Case::LifecycleConflict
            | Case::SoftDelete
            | Case::TemporaryHold
            | Case::PrepareHold
            | Case::AmbiguousCreate
    );
    admitted(target, Duration::from_secs(renewal.unwrap_or(0) + 300), retain, move |target, identity, resources, marker, wrapping| async move {
        let repository = GoogleCloudStorageRepository::from_admitted_resources(target.clone(), identity.clone(), resources,
            RepositoryUploadAuthenticator::new(CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)), InstanceId::new(identity.instance_id())?)).await?;
        match case {
            Case::Denial => {
                assert_eq!(repository.qualification_bucket_identity().await, Err(RepositoryFailure::PermissionDenied));
            },
            Case::Throttle => {
                let mut observed = false;
                for _ in 0..16 {
                    match repository.qualification_bucket_identity().await {
                        Err(RepositoryFailure::Throttled { retry_after_millis }) => { assert!(retry_after_millis <= 60000); observed = true; break; },
                        Ok(()) => {},
                        Err(e) => return Err(format!("native throttle fixture failed with {e:?}").into()),
                    }
                }
                assert!(observed, "designated native fixture did not throttle; not qualified");
            },
            Case::Renewal => {
                repository.qualification_bucket_identity().await?;
                tokio::time::sleep(Duration::from_secs(renewal.ok_or("renewal fixture")?)).await;
                repository.qualification_bucket_identity().await?;
            },
            Case::Retention | Case::EventHold | Case::LifecycleConflict | Case::SoftDelete | Case::PrepareHold => {
                repository.initialize().await?;
                let mut bytes = vec![211;128];
                getrandom::fill(&mut bytes)?;
                let object = ImmutableObject::new(bytes)?;
                repository.put_if_absent(object.clone()).await?;
                let metadata = repository.head(object.id()).await?;
                match case {
                    Case::Retention | Case::LifecycleConflict => {
                        let PolicyObservation::Observed(retention) = metadata.protection().retention else { return Err("native retention fixture has no observed deadline".into()); };
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                        assert!(retention.retain_until_unix_seconds > now + 60);
                        if matches!(case, Case::LifecycleConflict) {
                            let PolicyObservation::Observed(lifecycle) = repository.storage_policy().await?.lifecycle else { return Err("native lifecycle conflict fixture is not observable".into()); };
                            assert!(lifecycle.current_expiration || lifecycle.noncurrent_expiration);
                        }
                    },
                    Case::SoftDelete => {
                        assert!(matches!(repository.storage_policy().await?.soft_delete, Some(PolicyObservation::Observed(seconds)) if seconds > 0));
                        assert_eq!(repository.delete(object.id()).await, Err(RepositoryFailure::OutcomeUnknown));
                        assert_eq!(repository.delete(object.id()).await, Err(RepositoryFailure::OutcomeUnknown));
                        assert_eq!(repository.head(object.id()).await, Err(RepositoryFailure::NotFound));
                        return Ok(());
                    },
                    Case::EventHold => assert_eq!(metadata.protection().event_hold, PolicyObservation::Observed(Some(RetentionPeriod::UntilRelease))),
                    Case::PrepareHold => {
                        let checksum = object.id().checksum().iter().map(|b| format!("{b:02x}")).collect::<String>();
                        eprintln!("prepared non-secret managed hold probe checksum {checksum}; retain fixture before applying authorized native temporary hold");
                        return Ok(());
                    },
                    _ => return Err("fixture case".into()),
                }
                assert_eq!(repository.delete(object.id()).await, Err(RepositoryFailure::PermissionDenied));
                assert_eq!(repository.head(object.id()).await?.checksum(), object.id().checksum());
            },
            Case::TemporaryHold => {
                repository.attach().await?;
                let id = held.ok_or("held fixture id")?;
                assert_eq!(repository.head(id).await?.protection().legal_hold, PolicyObservation::Observed(true));
                assert_eq!(repository.delete(id).await, Err(RepositoryFailure::PermissionDenied));
                assert_eq!(repository.head(id).await?.checksum(), id.checksum());
            },
            Case::AmbiguousCreate => {
                repository.initialize().await?;
                let object = ImmutableObject::new(vec![209;64])?;
                let state = repository.begin_upload(UploadPlan::new(object.id(), 64)?).await?;
                let interrupted = repository.with_faults(vec![GoogleCloudStorageFault::new(GoogleCloudStorageFaultPoint::AfterNativeCreate, GoogleCloudStorageFaultEffect::OutcomeUnknown, 0)])?;
                assert_eq!(interrupted.resume_upload(UploadPart::new(state, object.bytes().to_vec())?).await, Err(RepositoryFailure::OutcomeUnknown));
                let retry = interrupted.inspect_upload(state.id()).await?.ok_or("requested checkpoint")?;
                assert_eq!(interrupted.resume_upload(UploadPart::new(state, object.bytes().to_vec())?).await, Err(RepositoryFailure::OutcomeUnknown));
                assert_eq!(retry.uploaded_bytes(), 64);
                assert_eq!(interrupted.abort_upload(state.id()).await, Err(RepositoryFailure::OutcomeUnknown));
                assert_eq!(interrupted.head(object.id()).await, Err(RepositoryFailure::NotFound));
            },
        }
        Ok(())
    }).await
}
macro_rules! native_case {
    ($name:ident, $case:ident) => {
        #[tokio::test]
        #[ignore = "requires independently authorized exact real GCS fixture; UNRUN without inputs"]
        async fn $name() -> TestResult {
            controlled(Case::$case).await
        }
    };
}
native_case!(real_google_native_denial, Denial);
native_case!(real_google_native_throttle, Throttle);
native_case!(real_google_native_credential_renewal, Renewal);
native_case!(real_google_native_retention, Retention);
native_case!(real_google_native_event_hold, EventHold);
native_case!(real_google_native_lifecycle_conflict, LifecycleConflict);
native_case!(real_google_native_soft_delete, SoftDelete);
native_case!(real_google_native_prepare_temporary_hold, PrepareHold);
native_case!(real_google_native_temporary_hold, TemporaryHold);
native_case!(real_google_native_ambiguous_creation, AmbiguousCreate);

pub(super) async fn concurrent_identity_and_corruption_cases(
    repository: &GoogleCloudStorageRepository,
    target: &GoogleCloudStorageTarget,
    identity: &RepositoryIdentity,
    resources: Arc<NativeAwsResources>,
    marker: [u8; 32],
    wrapping: [u8; 32],
) -> TestResult {
    for wrong in [
        GoogleCloudStorageTarget::new(
            target.bucket(),
            if target.project_number() == "1" {
                "2"
            } else {
                "1"
            },
            target.location(),
            target.prefix(),
        )?,
        GoogleCloudStorageTarget::new(
            target.bucket(),
            target.project_number(),
            if target.location() == "US" {
                "EU"
            } else {
                "US"
            },
            target.prefix(),
        )?,
    ] {
        let expected = RepositoryIdentity::google_cloud_storage(
            identity.repository_id(),
            identity.instance_id(),
            identity.integrity_fingerprint(),
            &wrong,
        )?;
        let wrong = GoogleCloudStorageRepository::from_admitted_resources(
            wrong,
            expected,
            resources.clone(),
            RepositoryUploadAuthenticator::new(
                CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
                InstanceId::new(identity.instance_id())?,
            ),
        )
        .await?;
        assert_eq!(
            wrong.attach().await,
            Err(RepositoryFailure::IdentityMismatch)
        );
    }
    let rival = GoogleCloudStorageRepository::from_admitted_resources(
        target.clone(),
        identity.clone(),
        resources,
        RepositoryUploadAuthenticator::new(
            CatalogSecret::from_owned(Box::new(marker), Box::new(wrapping)),
            InstanceId::new(identity.instance_id())?,
        ),
    )
    .await?;
    let slot = HeadSlot::from_checksum([239; 32]);
    let (left, right) = tokio::join!(
        repository.compare_and_swap_head_at(
            slot,
            RegistryHeadChange::new(None, b"native race left".to_vec())?
        ),
        rival.compare_and_swap_head_at(
            slot,
            RegistryHeadChange::new(None, b"native race right".to_vec())?
        ),
    );
    let version = match (left?, right?) {
        (CasOutcome::Published(version), CasOutcome::Conflict(Some(other)))
        | (CasOutcome::Conflict(Some(other)), CasOutcome::Published(version))
            if version == other =>
        {
            version
        },
        _ => return Err("native CAS race did not publish exactly one successor".into()),
    };
    assert_eq!(
        repository
            .registry_head_at(slot)
            .await?
            .ok_or("race head")?
            .version(),
        version
    );
    repository.delete_head_if_version(slot, version).await?;
    let objects = [
        ImmutableObject::new(vec![231; 32])?,
        ImmutableObject::new(vec![232; 32])?,
        ImmutableObject::new(vec![233; 32])?,
    ];
    for object in &objects {
        repository.put_if_absent(object.clone()).await?;
    }
    let first = repository
        .list(ListRequest::new(ListKind::Objects, None, 1)?)
        .await?;
    let cursor = first
        .next_cursor()
        .cloned()
        .ok_or("native pagination fixture")?;
    assert_eq!(
        rival
            .list(ListRequest::new(
                ListKind::Objects,
                Some(cursor.clone()),
                1
            )?)
            .await,
        Err(RepositoryFailure::InvalidInput)
    );
    // Native pagination is advisory across mutation. Direct lookup is authority.
    repository
        .delete(objects.first().ok_or("pagination object")?.id())
        .await?;
    let second = repository
        .list(ListRequest::new(
            ListKind::Objects,
            Some(cursor.clone()),
            1,
        )?)
        .await?;
    for entry in second.entries() {
        let ListEntry::Object(id) = entry else {
            return Err("pagination kind".into());
        };
        assert!(objects.iter().any(|object| object.id() == *id));
        match repository.head(*id).await {
            Ok(_) | Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e.into()),
        }
    }
    assert_eq!(
        repository
            .list(ListRequest::new(ListKind::Objects, Some(cursor), 1)?)
            .await,
        Err(RepositoryFailure::InvalidInput)
    );
    for object in &objects {
        repository.delete(object.id()).await?;
    }
    let mut probe = [0; 32];
    getrandom::fill(&mut probe)?;
    repository.qualification_content_corruption(probe).await?;
    Ok(())
}
