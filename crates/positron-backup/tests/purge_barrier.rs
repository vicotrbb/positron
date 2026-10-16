#![cfg(feature = "test-support")]
#[path = "support/snapshot_resources.rs"]
mod resources;
use positron_backup::*;
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
#[tokio::test]
async fn fresh_candidate_accepts_exact_purge_barrier_and_rejects_dirty_candidates()
-> Result<(), Box<dyn std::error::Error>> {
    resources::admitted(96 * 1024 * 1024, |resources| async move {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let secrets = dir.path().join("secrets");
        let path = dir.path().join("repo");
        for p in [&secrets, &path] {
            std::fs::create_dir(p)?;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
        }
        let custody = BootstrapKeyCustody::initialize(&secrets)?;
        let instance = InstanceId::new([2; 16])?;
        let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
        let signer = custody.backup_control_signer(instance, &protected)?;
        let identity =
            RepositoryIdentity::local([1; 16], [2; 16], signer.identity().fingerprint(), &path)?;
        let repository = LocalRepository::initialize(&path, identity.clone()).await?;
        let publisher = BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, 0)?;
        let tombstone = BackupPurgeTombstone::new([3; 16], "excluded", [4; 16], 5)?;
        let foreign = ImmutableObject::new(vec![99; 64])?;
        repository.put_if_absent(foreign.clone()).await?;
        assert_eq!(
            publisher
                .prepare_purge_barrier(std::slice::from_ref(&tombstone))
                .await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        assert!(
            repository
                .registry_head_at(HeadSlot::registry())
                .await?
                .is_none()
        );
        assert!(repository.head(foreign.id()).await.is_ok());
        repository.delete(foreign.id()).await?;
        let anchor = publisher
            .prepare_purge_barrier(std::slice::from_ref(&tombstone))
            .await?
            .ok_or("barrier anchor")?;
        assert_eq!(publisher.purge_tombstones().await?, vec![tombstone.clone()]);
        assert_eq!(
            publisher
                .prepare_purge_barrier(std::slice::from_ref(&tombstone))
                .await?,
            Some(anchor)
        );
        let orphan = ImmutableObject::new(vec![42; 64])?;
        repository.put_if_absent(orphan.clone()).await?;
        assert_eq!(
            publisher
                .prepare_purge_barrier(std::slice::from_ref(&tombstone))
                .await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        assert!(repository.head(orphan.id()).await.is_ok());
        repository.delete(orphan.id()).await?;
        let other = BackupPurgeTombstone::new([5; 16], "second", [6; 16], 7)?;
        let advancing = BackupPublisher::new(&repository, &identity, &signer)
            .with_trusted_generation(anchor)?
            .with_control_resources(&resources, 0)?;
        advancing.record_purge_tombstone(&other).await?;
        let complete = [tombstone.clone(), other];
        assert_eq!(
            publisher.prepare_purge_barrier(&complete).await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        assert_eq!(
            advancing.prepare_purge_barrier(&complete).await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn interrupted_exact_barrier_installation_recovers_partial_control_staging()
-> Result<(), Box<dyn std::error::Error>> {
    resources::admitted(96 * 1024 * 1024, |resources| async move {
        use std::os::unix::fs::PermissionsExt;
        for point in [
            LocalFaultPoint::BeforeObjectPublication,
            LocalFaultPoint::BeforeRegistryPublication,
        ] {
            let dir = tempfile::tempdir()?;
            let secrets = dir.path().join("secrets");
            let path = dir.path().join("repo");
            for p in [&secrets, &path] {
                std::fs::create_dir(p)?;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
            }
            let custody = BootstrapKeyCustody::initialize(&secrets)?;
            let instance = InstanceId::new([2; 16])?;
            let protected =
                custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
            let signer = custody.backup_control_signer(instance, &protected)?;
            let identity = RepositoryIdentity::local(
                [1; 16],
                [2; 16],
                signer.identity().fingerprint(),
                &path,
            )?;
            let repository = LocalRepository::initialize(&path, identity.clone())
                .await?
                .with_faults(vec![LocalFault::new(
                    point,
                    LocalFaultEffect::Interrupted,
                    0,
                )])?;
            let publisher = BackupPublisher::new(&repository, &identity, &signer)
                .with_control_resources(&resources, 0)?;
            let tombstone = BackupPurgeTombstone::new([3; 16], "excluded", [4; 16], 5)?;
            assert_eq!(
                publisher
                    .prepare_purge_barrier(std::slice::from_ref(&tombstone))
                    .await,
                Err(RepositoryFailure::Interrupted)
            );
            let staged = std::fs::read_dir(&path)?
                .filter_map(Result::ok)
                .find(|entry| entry.file_name().as_encoded_bytes().starts_with(b"p-"))
                .ok_or("owned control staging")?
                .path();
            let length = std::fs::metadata(&staged)?.len();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&staged)?
                .set_len(length / 2)?;
            let prefix = std::fs::read(&staged)?;
            let mut corrupt = prefix.clone();
            *corrupt.first_mut().ok_or("nonempty partial control")? ^= 1;
            std::fs::write(&staged, corrupt)?;
            assert_eq!(
                publisher
                    .prepare_purge_barrier(std::slice::from_ref(&tombstone))
                    .await,
                Err(RepositoryFailure::PreconditionFailed)
            );
            assert!(staged.exists());
            std::fs::write(&staged, prefix)?;
            let anchor = publisher
                .prepare_purge_barrier(std::slice::from_ref(&tombstone))
                .await?
                .ok_or("recovered barrier")?;
            assert_eq!(
                publisher
                    .prepare_purge_barrier(std::slice::from_ref(&tombstone))
                    .await?,
                Some(anchor)
            );
            assert_eq!(publisher.purge_tombstones().await?, vec![tombstone]);
            assert!(!staged.exists());
        }
        Ok(())
    })
    .await
}
