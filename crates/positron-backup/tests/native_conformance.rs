#[path = "shared/provider_behavior.rs"]
mod provider_behavior;
use positron_backup::{LocalRepository, RepositoryIdentity};
use std::{fs, os::unix::fs::PermissionsExt};
#[tokio::test]
async fn native_local_adapter_passes_the_shared_repository_behavior_cases()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        std::env::temp_dir().join(format!("positron-local-conformance-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([81; 16], [82; 16], [83; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone()).await?;
    provider_behavior::conformance(
        &repository,
        identity.clone(),
        std::time::Duration::from_secs(5),
    )
    .await?;
    drop(repository);
    let reopened = LocalRepository::attach(&path, &identity).await?;
    provider_behavior::conformance(&reopened, identity, std::time::Duration::from_secs(5)).await?;
    assert_eq!(fs::read_dir(&path)?.count(), 1);
    fs::remove_dir_all(path)?;
    Ok(())
}
