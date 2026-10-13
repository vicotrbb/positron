#![cfg(feature = "test-support")]
use positron_backup::{
    ImmutableObject, LocalFault, LocalFaultEffect, LocalFaultPoint, LocalRepository, Repository,
    RepositoryFailure, RepositoryIdentity, UploadPart, UploadPlan,
};
use std::{fs, os::unix::fs::PermissionsExt};
#[tokio::test]
async fn interrupted_final_multipart_publication_recovers_without_incomplete_object()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        std::env::temp_dir().join(format!("positron-repository-fault-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone())
        .await?
        .with_faults(vec![LocalFault::new(
            LocalFaultPoint::AfterUploadPublication,
            LocalFaultEffect::Interrupted,
            0,
        )])?;
    let object = ImmutableObject::new(b"complete encrypted upload".to_vec())?;
    let plan = UploadPlan::new(object.id(), 25)?;
    let state = repository.begin_upload(plan).await?;
    assert_eq!(
        repository
            .resume_upload(UploadPart::new(state, object.bytes().to_vec())?)
            .await,
        Err(RepositoryFailure::Interrupted)
    );
    assert_eq!(
        repository.head(object.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    drop(repository);
    let reopened = LocalRepository::attach(&path, &identity).await?;
    let recovered = reopened.begin_upload(plan).await?;
    assert!(recovered.complete());
    assert_eq!(reopened.head(object.id()).await?.size(), 25);
    assert_eq!(reopened.inspect_upload(recovered.id()).await?, None);
    assert_eq!(
        reopened
            .resume_upload(UploadPart::new(state, object.bytes().to_vec())?)
            .await?,
        positron_backup::UploadOutcome::Complete(positron_backup::PutOutcome::AlreadyPresent)
    );
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn ambiguous_publication_and_deletion_are_resolved_by_authoritative_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-repository-ambiguous-{}",
        std::process::id()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([4; 16], [5; 16], [6; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone())
        .await?
        .with_faults(vec![
            LocalFault::new(
                LocalFaultPoint::BeforeObjectPublication,
                LocalFaultEffect::Throttled {
                    retry_after_millis: 25,
                },
                0,
            ),
            LocalFault::new(
                LocalFaultPoint::AfterObjectPublication,
                LocalFaultEffect::OutcomeUnknown,
                0,
            ),
            LocalFault::new(
                LocalFaultPoint::AfterRegistryPublication,
                LocalFaultEffect::OutcomeUnknown,
                0,
            ),
            LocalFault::new(
                LocalFaultPoint::AfterDeletion,
                LocalFaultEffect::OutcomeUnknown,
                0,
            ),
        ])?;
    let object = ImmutableObject::new(b"opaque encrypted bytes".to_vec())?;
    assert_eq!(
        repository.put_if_absent(object.clone()).await,
        Err(RepositoryFailure::Throttled {
            retry_after_millis: 25
        })
    );
    assert_eq!(
        repository.head(object.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    assert_eq!(
        repository.put_if_absent(object.clone()).await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert_eq!(
        repository.head(object.id()).await?.checksum(),
        object.id().checksum()
    );
    assert_eq!(
        repository.put_if_absent(object.clone()).await?,
        positron_backup::PutOutcome::AlreadyPresent
    );
    let change = positron_backup::RegistryHeadChange::new(None, b"signed registry".to_vec())?;
    assert_eq!(
        repository
            .compare_and_swap_head_at(positron_backup::HeadSlot::registry(), change.clone())
            .await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    let current = repository
        .registry_head_at(positron_backup::HeadSlot::registry())
        .await?
        .ok_or("missing published head")?;
    assert_eq!(current.bytes(), b"signed registry");
    assert_eq!(
        repository
            .compare_and_swap_head_at(positron_backup::HeadSlot::registry(), change)
            .await?,
        positron_backup::CasOutcome::Conflict(Some(current.version()))
    );
    assert_eq!(
        repository.delete(object.id()).await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert_eq!(
        repository.head(object.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    assert_eq!(
        repository.delete(object.id()).await?,
        positron_backup::DeleteOutcome::AlreadyAbsent
    );
    drop(repository);
    let reopened = LocalRepository::attach(&path, &identity).await?;
    assert_eq!(
        reopened
            .registry_head_at(positron_backup::HeadSlot::registry())
            .await?
            .ok_or("missing durable head")?
            .version(),
        current.version()
    );
    fs::remove_dir_all(path)?;
    Ok(())
}
