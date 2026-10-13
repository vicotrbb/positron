use positron_backup::{LocalRepository, Repository, RepositoryFailure, RepositoryIdentity};
use std::{fs, os::unix::fs::PermissionsExt};

#[tokio::test]
async fn repository_initialization_is_immutable_and_refuses_foreign_contents()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("positron-repository-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone()).await?;
    assert_eq!(repository.identify().await?, identity);
    drop(repository);
    let attached = LocalRepository::attach(&path, &identity).await?;
    assert_eq!(attached.identify().await?, identity);
    let different = RepositoryIdentity::local([4; 16], [2; 16], [3; 32], &path)?;
    assert!(matches!(
        LocalRepository::attach(&path, &different).await,
        Err(RepositoryFailure::IdentityMismatch)
    ));
    drop(attached);
    fs::remove_dir_all(&path)?;
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    fs::write(path.join("foreign"), b"untouched")?;
    assert!(matches!(
        LocalRepository::initialize(&path, identity).await,
        Err(RepositoryFailure::ForeignPrefix)
    ));
    assert_eq!(fs::read(path.join("foreign"))?, b"untouched");
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn repository_identity_cannot_initialize_a_different_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let left =
        std::env::temp_dir().join(format!("positron-repository-left-{}", std::process::id()));
    let right =
        std::env::temp_dir().join(format!("positron-repository-right-{}", std::process::id()));
    for path in [&left, &right] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &left)?;
    assert!(matches!(
        LocalRepository::initialize(&right, identity).await,
        Err(RepositoryFailure::IdentityMismatch)
    ));
    assert_eq!(fs::read_dir(&right)?.count(), 0);
    for path in [&left, &right] {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[tokio::test]
async fn immutable_objects_verify_checksums_and_bounded_ranges()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{DeleteOutcome, ImmutableObject, ObjectRange, PutOutcome};
    let path = std::env::temp_dir().join(format!(
        "positron-repository-objects-{}",
        std::process::id()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    let object = ImmutableObject::new(b"verified encrypted bytes".to_vec())?;
    let id = object.id();
    assert_eq!(
        repository.put_if_absent(object.clone()).await?,
        PutOutcome::Created
    );
    assert_eq!(
        repository.put_if_absent(object).await?,
        PutOutcome::AlreadyPresent
    );
    assert_eq!(repository.head(id).await?.size(), 24);
    assert_eq!(
        repository
            .read_range(ObjectRange::new(id, 9, 9)?)
            .await?
            .bytes(),
        b"encrypted"
    );
    assert_eq!(
        repository.read_range(ObjectRange::new(id, 23, 2)?).await,
        Err(RepositoryFailure::InvalidInput)
    );
    assert_eq!(repository.delete(id).await?, DeleteOutcome::Deleted);
    assert_eq!(repository.head(id).await, Err(RepositoryFailure::NotFound));
    assert_eq!(repository.delete(id).await?, DeleteOutcome::AlreadyAbsent);
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn registry_head_cas_has_one_winner_and_survives_reattach()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{CasOutcome, RegistryHeadChange};
    let path = std::env::temp_dir().join(format!("positron-repository-cas-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let first = LocalRepository::initialize(&path, identity.clone()).await?;
    let second = LocalRepository::attach(&path, &identity).await?;
    assert_eq!(
        first
            .registry_head_at(positron_backup::HeadSlot::registry())
            .await?,
        None
    );
    let initial = RegistryHeadChange::new(None, b"signed generation one".to_vec())?;
    assert!(matches!(
        first
            .compare_and_swap_head_at(positron_backup::HeadSlot::registry(), initial)
            .await?,
        CasOutcome::Published(_)
    ));
    let before = first
        .registry_head_at(positron_backup::HeadSlot::registry())
        .await?
        .ok_or("initial head")?;
    let change =
        RegistryHeadChange::new(Some(before.version()), b"signed generation two".to_vec())?;
    let (left, right) = tokio::join!(
        first.compare_and_swap_head_at(positron_backup::HeadSlot::registry(), change.clone()),
        second.compare_and_swap_head_at(positron_backup::HeadSlot::registry(), change)
    );
    let outcomes = [left, right];
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Ok(CasOutcome::Published(_))))
            .count(),
        1
    );
    assert!(outcomes.iter().all(|result| matches!(
        result,
        Ok(CasOutcome::Published(_) | CasOutcome::Conflict(_)) | Err(RepositoryFailure::Busy)
    )));
    drop(first);
    drop(second);
    let reopened = LocalRepository::attach(&path, &identity).await?;
    assert_eq!(
        reopened
            .registry_head_at(positron_backup::HeadSlot::registry())
            .await?
            .ok_or("successor head")?
            .bytes(),
        b"signed generation two"
    );
    assert!(matches!(
        reopened
            .compare_and_swap_head_at(
                positron_backup::HeadSlot::registry(),
                RegistryHeadChange::new(Some(before.version()), b"stale".to_vec())?
            )
            .await?,
        CasOutcome::Conflict(_)
    ));
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn multipart_upload_resumes_after_reopen_and_aborts_only_owned_upload()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{DeleteOutcome, ImmutableObject, UploadOutcome, UploadPart, UploadPlan};
    let path =
        std::env::temp_dir().join(format!("positron-repository-upload-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone()).await?;
    let object = ImmutableObject::new(b"firstsecond".to_vec())?;
    let plan = UploadPlan::new(object.id(), 11)?;
    let initial = repository.begin_upload(plan).await?;
    let first = UploadPart::new(initial, b"first".to_vec())?;
    let pending = match repository.resume_upload(first.clone()).await? {
        UploadOutcome::Pending(state) => state,
        _ => return Err("premature object".into()),
    };
    assert_eq!(
        repository.head(object.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    assert_eq!(
        repository.resume_upload(first).await,
        Err(RepositoryFailure::PreconditionFailed)
    );
    drop(repository);
    let reopened = LocalRepository::attach(&path, &identity).await?;
    assert_eq!(reopened.inspect_upload(pending.id()).await?, Some(pending));
    assert!(matches!(
        reopened
            .resume_upload(UploadPart::new(pending, b"second".to_vec())?)
            .await?,
        UploadOutcome::Complete(_)
    ));
    assert_eq!(reopened.head(object.id()).await?.size(), 11);
    assert_eq!(reopened.inspect_upload(pending.id()).await?, None);
    let abandoned = reopened
        .begin_upload(UploadPlan::new(
            ImmutableObject::new(b"abandon".to_vec())?.id(),
            7,
        )?)
        .await?;
    assert_eq!(
        reopened.abort_upload(abandoned.id()).await?,
        DeleteOutcome::Deleted
    );
    assert_eq!(
        reopened.abort_upload(abandoned.id()).await?,
        DeleteOutcome::AlreadyAbsent
    );
    assert_eq!(reopened.head(object.id()).await?.size(), 11);
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn listing_is_bounded_and_authoritative_metadata_survives_stale_pages()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{ImmutableObject, ListEntry, ListKind, ListRequest};
    let path =
        std::env::temp_dir().join(format!("positron-repository-list-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    let left = ImmutableObject::new(b"left".to_vec())?;
    let right = ImmutableObject::new(b"right".to_vec())?;
    let ids = [left.id(), right.id()];
    repository.put_if_absent(left).await?;
    repository.put_if_absent(right).await?;
    let mut cursor = None;
    let mut listed = Vec::new();
    for _ in 0..8 {
        let page = repository
            .list(ListRequest::new(ListKind::Objects, cursor, 1)?)
            .await?;
        assert!(page.entries().len() <= 1);
        listed.extend_from_slice(page.entries());
        cursor = page.next_cursor().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert!(cursor.is_none());
    assert_eq!(listed.len(), 2);
    for id in ids {
        assert!(listed.contains(&ListEntry::Object(id)));
        assert!(repository.head(id).await.is_ok());
    }
    assert_eq!(
        ListRequest::new(ListKind::Objects, None, 0),
        Err(RepositoryFailure::InvalidInput)
    );
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn stale_or_foreign_listing_cursor_is_rejected_without_losing_objects()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{ImmutableObject, ListCursor, ListKind, ListRequest};
    let path =
        std::env::temp_dir().join(format!("positron-repository-cursor-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    let object = ImmutableObject::new(b"listed".to_vec())?;
    let id = object.id();
    repository.put_if_absent(object).await?;
    let first = repository
        .list(ListRequest::new(ListKind::Objects, None, 1)?)
        .await?;
    let cursor = first.next_cursor().cloned().ok_or("cursor")?;
    repository
        .list(ListRequest::new(
            ListKind::Objects,
            Some(cursor.clone()),
            1,
        )?)
        .await?;
    assert_eq!(
        repository
            .list(ListRequest::new(ListKind::Objects, Some(cursor), 1)?)
            .await,
        Err(RepositoryFailure::InvalidInput)
    );
    assert_eq!(
        repository
            .list(ListRequest::new(
                ListKind::Objects,
                Some(ListCursor::from_bytes(vec![7; 33])?),
                1
            )?)
            .await,
        Err(RepositoryFailure::InvalidInput)
    );
    assert_eq!(repository.head(id).await?.size(), 6);
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn conditional_probe_head_cleanup_preserves_registry_and_conflicting_successor()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{CasOutcome, DeleteOutcome, HeadSlot, ObjectVersion, RegistryHeadChange};
    let path =
        std::env::temp_dir().join(format!("positron-repository-probe-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([11; 16], [12; 16], [13; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    let registry = HeadSlot::registry();
    let probe = HeadSlot::from_checksum([42; 32]);
    let original = RegistryHeadChange::new(None, b"signed current registry".to_vec())?;
    repository
        .compare_and_swap_head_at(registry, original)
        .await?;
    let change = RegistryHeadChange::new(None, b"dedicated probe".to_vec())?;
    let version = match repository.compare_and_swap_head_at(probe, change).await? {
        CasOutcome::Published(version) => version,
        _ => return Err("probe publication conflict".into()),
    };
    assert_eq!(
        repository
            .delete_head_if_version(probe, ObjectVersion::from_checksum([1; 32]))
            .await,
        Err(RepositoryFailure::PreconditionFailed)
    );
    assert_eq!(
        repository
            .registry_head_at(probe)
            .await?
            .ok_or("missing probe")?
            .version(),
        version
    );
    assert_eq!(
        repository.delete_head_if_version(probe, version).await?,
        DeleteOutcome::Deleted
    );
    assert_eq!(repository.registry_head_at(probe).await?, None);
    assert_eq!(
        repository
            .registry_head_at(registry)
            .await?
            .ok_or("missing registry")?
            .bytes(),
        b"signed current registry"
    );
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn listing_cursor_cannot_select_another_attached_owners_stream()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{ImmutableObject, ListKind, ListRequest};
    let path = std::env::temp_dir().join(format!("positron-cursor-owner-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([111; 16], [112; 16], [113; 32], &path)?;
    let first = LocalRepository::initialize(&path, identity.clone()).await?;
    for byte in 0..3 {
        first
            .put_if_absent(ImmutableObject::new(vec![byte; 8])?)
            .await?;
    }
    let second = LocalRepository::attach(&path, &identity).await?;
    let foreign = first
        .list(ListRequest::new(ListKind::Objects, None, 1)?)
        .await?;
    let own = second
        .list(ListRequest::new(ListKind::Objects, None, 1)?)
        .await?;
    assert!(own.next_cursor().is_some());
    assert_eq!(
        second
            .list(ListRequest::new(
                ListKind::Objects,
                foreign.next_cursor().cloned(),
                1
            )?)
            .await,
        Err(RepositoryFailure::InvalidInput)
    );
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn native_credentials_are_rechecked_after_directory_or_identity_access_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-native-credentials-{}",
        std::process::id()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([121; 16], [122; 16], [123; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        repository.identify().await,
        Err(RepositoryFailure::PermissionDenied)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(path.join("identity"), fs::Permissions::from_mode(0o644))?;
    assert_eq!(
        repository.identify().await,
        Err(RepositoryFailure::PermissionDenied)
    );
    fs::set_permissions(path.join("identity"), fs::Permissions::from_mode(0o600))?;
    assert!(repository.identify().await.is_ok());
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn native_corruption_and_oversize_fail_closed_without_republishing_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{ImmutableObject, MAX_OBJECT_BYTES};
    let path = std::env::temp_dir().join(format!(
        "positron-repository-corrupt-{}",
        std::process::id()
    ));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([141; 16], [142; 16], [143; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    let object =
        ImmutableObject::new(b"encrypted frame with independently committed checksum".to_vec())?;
    repository.put_if_absent(object.clone()).await?;
    let mut name = String::from("o-");
    for byte in object.id().checksum() {
        use std::fmt::Write;
        write!(name, "{byte:02x}")?;
    }
    let object_path = path.join(name);
    fs::write(&object_path, b"tampered frame")?;
    assert_eq!(
        repository.head(object.id()).await,
        Err(RepositoryFailure::ChecksumMismatch)
    );
    assert_eq!(
        repository.put_if_absent(object.clone()).await,
        Err(RepositoryFailure::ChecksumMismatch)
    );
    assert_eq!(
        repository.delete(object.id()).await,
        Err(RepositoryFailure::ChecksumMismatch)
    );
    assert_eq!(fs::read(&object_path)?, b"tampered frame");
    fs::OpenOptions::new()
        .write(true)
        .open(&object_path)?
        .set_len(MAX_OBJECT_BYTES + 1)?;
    assert_eq!(
        repository.head(object.id()).await,
        Err(RepositoryFailure::LimitExceeded)
    );
    assert_eq!(
        repository.delete(object.id()).await,
        Err(RepositoryFailure::LimitExceeded)
    );
    fs::remove_dir_all(path)?;
    Ok(())
}

#[tokio::test]
async fn active_listing_streams_are_bounded_without_capping_repository_objects()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{ImmutableObject, ListKind, ListRequest};
    let path = std::env::temp_dir().join(format!("positron-listing-bound-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([151; 16], [152; 16], [153; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity).await?;
    for byte in 0..4 {
        repository
            .put_if_absent(ImmutableObject::new(vec![byte; 8])?)
            .await?;
    }
    let mut cursors = Vec::new();
    for _ in 0..8 {
        cursors.push(
            repository
                .list(ListRequest::new(ListKind::Objects, None, 1)?)
                .await?
                .next_cursor()
                .cloned()
                .ok_or("live cursor")?,
        );
    }
    assert_eq!(
        repository
            .list(ListRequest::new(ListKind::Objects, None, 1)?)
            .await,
        Err(RepositoryFailure::LimitExceeded)
    );
    let mut cursor = cursors.pop();
    while let Some(current) = cursor {
        cursor = repository
            .list(ListRequest::new(ListKind::Objects, Some(current), 128)?)
            .await?
            .next_cursor()
            .cloned();
    }
    assert!(
        repository
            .list(ListRequest::new(ListKind::Objects, None, 1)?)
            .await
            .is_ok()
    );
    fs::remove_dir_all(path)?;
    Ok(())
}
