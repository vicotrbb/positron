use super::*;
use crate::{CasOutcome, RegistryHeadChange};
use std::sync::{Mutex, mpsc};
type Pause = (mpsc::Sender<()>, mpsc::Receiver<()>);
static PAUSE: Mutex<std::collections::BTreeMap<u64, Pause>> =
    Mutex::new(std::collections::BTreeMap::new());
pub(super) fn after_open(root: &File) -> Result<(), RepositoryFailure> {
    let inode = root.metadata().map_err(io_failure)?.ino();
    let pause = {
        let mut current = PAUSE.lock().map_err(|_| RepositoryFailure::Interrupted)?;
        current.remove(&inode)
    };
    if let Some((entered, release)) = pause {
        entered
            .send(())
            .map_err(|_| RepositoryFailure::Interrupted)?;
        release
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| RepositoryFailure::Interrupted)?;
    }
    Ok(())
}
#[tokio::test]
async fn head_read_serializes_a_legitimate_replacement_without_claiming_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{LocalRepository, Repository};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], directory.path())?;
    let repository = Arc::new(LocalRepository::initialize(directory.path(), identity).await?);
    let slot = crate::HeadSlot::registry();
    repository
        .compare_and_swap_head_at(slot, RegistryHeadChange::new(None, b"first".to_vec())?)
        .await?;
    let original = repository
        .registry_head_at(slot)
        .await?
        .ok_or("original head")?;
    let (entered, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    assert!(
        PAUSE
            .lock()
            .map_err(|_| "pause lock")?
            .insert(repository.root.metadata()?.ino(), (entered, waiting))
            .is_none()
    );
    let reader = Arc::clone(&repository);
    let read = tokio::spawn(async move { reader.registry_head_at(slot).await });
    tokio::task::spawn_blocking(move || observed.recv_timeout(std::time::Duration::from_secs(5)))
        .await??;
    let change = RegistryHeadChange::new(Some(original.version()), b"second".to_vec())?;
    let publication = repository
        .compare_and_swap_head_at(slot, change.clone())
        .await;
    release.send(())?;
    let observed = read.await?;
    assert_eq!(observed, Ok(Some(original)));
    assert_eq!(publication, Err(RepositoryFailure::Busy));
    assert!(matches!(
        repository.compare_and_swap_head_at(slot, change).await?,
        CasOutcome::Published(_)
    ));
    Ok(())
}

#[tokio::test]
async fn upload_inspection_serializes_a_legitimate_replacement_without_claiming_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{UploadOutcome, UploadPart, UploadPlan};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], directory.path())?;
    let repository = Arc::new(LocalRepository::initialize(directory.path(), identity).await?);
    let object = ImmutableObject::new(b"firstsecond".to_vec())?;
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    let initial = repository.begin_upload(plan).await?;
    let UploadOutcome::Pending(original) = repository
        .resume_upload(UploadPart::new(initial, b"first".to_vec())?)
        .await?
    else {
        return Err("partial upload must remain pending".into());
    };
    let (entered, observed) = mpsc::channel();
    let (release, waiting) = mpsc::channel();
    assert!(
        PAUSE
            .lock()
            .map_err(|_| "pause lock")?
            .insert(repository.root.metadata()?.ino(), (entered, waiting))
            .is_none()
    );
    let reader = Arc::clone(&repository);
    let read = tokio::spawn(async move { reader.inspect_upload(plan.id()).await });
    tokio::task::spawn_blocking(move || observed.recv_timeout(std::time::Duration::from_secs(5)))
        .await??;
    let publication = repository
        .resume_upload(UploadPart::new(original, b"second".to_vec())?)
        .await;
    release.send(())?;
    assert_eq!(read.await?, Ok(Some(original)));
    assert_eq!(publication, Err(RepositoryFailure::Busy));
    assert!(matches!(
        repository
            .resume_upload(UploadPart::new(original, b"second".to_vec())?)
            .await?,
        UploadOutcome::Complete(_)
    ));
    Ok(())
}

#[tokio::test]
async fn serialized_control_reads_still_refuse_hard_linked_records()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::UploadPlan;
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], directory.path())?;
    let repository = LocalRepository::initialize(directory.path(), identity).await?;
    let slot = crate::HeadSlot::registry();
    repository
        .compare_and_swap_head_at(slot, RegistryHeadChange::new(None, b"head".to_vec())?)
        .await?;
    let link = directory.path().join("head-link");
    std::fs::hard_link(directory.path().join(slot.name()), &link)?;
    assert_eq!(
        repository.registry_head_at(slot).await,
        Err(RepositoryFailure::CorruptState)
    );
    std::fs::remove_file(link)?;
    assert!(repository.registry_head_at(slot).await?.is_some());
    let object = ImmutableObject::new(b"upload".to_vec())?;
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    repository.begin_upload(plan).await?;
    let link = directory.path().join("upload-link");
    std::fs::hard_link(directory.path().join(plan.id().name()), &link)?;
    assert_eq!(
        repository.inspect_upload(plan.id()).await,
        Err(RepositoryFailure::CorruptState)
    );
    std::fs::remove_file(link)?;
    assert!(repository.inspect_upload(plan.id()).await?.is_some());
    Ok(())
}
