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

#[tokio::test]
async fn existing_verified_object_reconciles_its_partial_upload_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{PutOutcome, UploadOutcome};
    for resume in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "positron-repository-completed-upload-{}-{resume}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
        let repository = LocalRepository::initialize(&path, identity.clone()).await?;
        let object = ImmutableObject::new(b"same complete encrypted content".to_vec())?;
        let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
        let state = repository.begin_upload(plan).await?;
        repository.put_if_absent(object.clone()).await?;
        drop(repository);
        let reopened = LocalRepository::attach(&path, &identity).await?;
        if resume {
            assert_eq!(
                reopened
                    .resume_upload(UploadPart::new(state, object.bytes().to_vec())?)
                    .await?,
                UploadOutcome::Complete(PutOutcome::AlreadyPresent)
            );
        } else {
            assert!(reopened.begin_upload(plan).await?.complete());
        }
        assert_eq!(reopened.inspect_upload(plan.id()).await?, None);
        assert_eq!(
            reopened.head(object.id()).await?.size(),
            object.bytes().len() as u64
        );
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[tokio::test]
async fn abort_removes_owned_staging_after_initial_and_resumed_publication_interruptions()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::DeleteOutcome;
    for resumed in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "positron-repository-abort-staging-{}-{resumed}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
        let repository = LocalRepository::initialize(&path, identity.clone()).await?;
        let object = ImmutableObject::new(b"encrypted upload staging".to_vec())?;
        let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
        let state = if resumed {
            Some(repository.begin_upload(plan).await?)
        } else {
            None
        };
        let faulty = repository.with_faults(vec![LocalFault::new(
            LocalFaultPoint::BeforeUploadPublication,
            LocalFaultEffect::Interrupted,
            0,
        )])?;
        if let Some(state) = state {
            assert_eq!(
                faulty
                    .resume_upload(UploadPart::new(state, b"encrypted".to_vec())?)
                    .await,
                Err(RepositoryFailure::Interrupted)
            );
        } else {
            assert_eq!(
                faulty.begin_upload(plan).await,
                Err(RepositoryFailure::Interrupted)
            );
        }
        drop(faulty);
        fs::write(path.join("foreign"), b"preserve")?;
        let reopened = LocalRepository::attach(&path, &identity).await?;
        assert_eq!(
            reopened.abort_upload(plan.id()).await?,
            DeleteOutcome::Deleted
        );
        assert_eq!(reopened.inspect_upload(plan.id()).await?, None);
        assert_eq!(
            reopened.abort_upload(plan.id()).await?,
            DeleteOutcome::AlreadyAbsent
        );
        assert_eq!(fs::read(path.join("foreign"))?, b"preserve");
        assert!(!fs::read_dir(&path)?.any(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with("p-u-")
        }));
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[tokio::test]
async fn upload_cleanup_preserves_malformed_staging_and_unrelated_uploads()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::DeleteOutcome;
    let path = std::env::temp_dir().join(format!(
        "positron-repository-abort-malformed-{}",
        std::process::id()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    let object = ImmutableObject::new(b"owned upload".to_vec())?;
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    let state = repository.begin_upload(plan).await?;
    let other = ImmutableObject::new(b"unrelated upload".to_vec())?;
    let other_state = repository
        .begin_upload(UploadPlan::new(other.id(), other.bytes().len() as u64)?)
        .await?;
    let faulty = repository.with_faults(vec![LocalFault::new(
        LocalFaultPoint::BeforeUploadPublication,
        LocalFaultEffect::Interrupted,
        0,
    )])?;
    assert_eq!(
        faulty
            .resume_upload(UploadPart::new(state, b"owned".to_vec())?)
            .await,
        Err(RepositoryFailure::Interrupted)
    );
    let pending = fs::read_dir(&path)?
        .find_map(|entry| {
            entry
                .ok()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("p-u-"))
        })
        .ok_or("staging")?
        .path();
    let original = fs::read(&pending)?;
    fs::write(&pending, b"malformed retained evidence")?;
    faulty.put_if_absent(object.clone()).await?;
    assert_eq!(
        faulty.abort_upload(plan.id()).await,
        Err(RepositoryFailure::CorruptState)
    );
    assert_eq!(
        faulty.begin_upload(plan).await,
        Err(RepositoryFailure::CorruptState)
    );
    assert_eq!(faulty.inspect_upload(plan.id()).await?, Some(state));
    assert_eq!(
        faulty.inspect_upload(other_state.id()).await?,
        Some(other_state)
    );
    assert_eq!(fs::read(&pending)?, b"malformed retained evidence");
    fs::write(&pending, original)?;
    assert_eq!(
        faulty.abort_upload(plan.id()).await?,
        DeleteOutcome::Deleted
    );
    assert_eq!(
        faulty.inspect_upload(other_state.id()).await?,
        Some(other_state)
    );
    assert_eq!(
        faulty.head(object.id()).await?.size(),
        object.bytes().len() as u64
    );
    fs::remove_dir_all(path)?;
    Ok(())
}
