#![cfg(feature = "test-support")]
#[path = "support/snapshot_resources.rs"]
mod resources;
use positron_backup::*;
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
#[tokio::test]
async fn purge_tombstone_is_signed_permanent_and_exactly_retryable()
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
            .with_control_resources(&resources, 64 * 1024)?;
        let tombstone = BackupPurgeTombstone::new([3; 16], "default", [9; 16], 10)?;
        let bytes = tombstone.signed_bytes(&identity, &signer)?;
        assert_eq!(
            BackupPurgeTombstone::verify(&bytes, &identity, signer.identity())?,
            tombstone
        );
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().ok_or("signature")? ^= 1;
        assert!(BackupPurgeTombstone::verify(&corrupt, &identity, signer.identity()).is_err());
        assert!(BackupPurgeTombstone::new([0; 16], "default", [9; 16], 10).is_err());
        assert!(BackupPurgeTombstone::new([3; 16], "Not Canonical", [9; 16], 10).is_err());
        assert!(BackupPurgeTombstone::new([3; 16], "default", [0; 16], 10).is_err());
        assert!(BackupPurgeTombstone::new([3; 16], "default", [9; 16], 0).is_err());
        assert_eq!(
            BackupPurgeTombstone::verify(&vec![0; 289], &identity, signer.identity()),
            Err(RepositoryFailure::LimitExceeded)
        );
        let wrong =
            RepositoryIdentity::local([99; 16], [2; 16], signer.identity().fingerprint(), &path)?;
        assert!(BackupPurgeTombstone::verify(&bytes, &wrong, signer.identity()).is_err());
        use sha2::Digest;
        let payload = bytes.get(..bytes.len() - 64).ok_or("payload")?;
        for offset in [0, 156, 157] {
            let mut forged = payload.to_vec();
            *forged.get_mut(offset).ok_or("field")? = 0xff;
            let signature = signer.sign(&sha2::Sha256::digest(&forged))?;
            forged.extend_from_slice(&signature.bytes());
            assert!(BackupPurgeTombstone::verify(&forged, &identity, signer.identity()).is_err());
        }
        let generation = publisher.record_purge_tombstone(&tombstone).await?;
        assert_eq!(
            publisher.record_purge_tombstone(&tombstone).await?,
            generation
        );
        assert_eq!(publisher.purge_tombstones().await?, vec![tombstone.clone()]);
        let conflict = BackupPurgeTombstone::new([3; 16], "other", [10; 16], 11)?;
        assert_eq!(
            publisher.record_purge_tombstone(&conflict).await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        let keys = vec![BackupKeyEnvelope::new([4; 16], 1, [4; 32], vec![5; 64])?];
        let object = ImmutableObject::new(vec![6; 64])?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity.clone(),
            BackupCatalogIdentity::new(1, [6; 32], 2, 1, [7; 32])?,
            BackupRetention::new(1, 2)?,
            BackupPublisher::key_context(&keys)?,
            vec![BackupObject::new(
                [7; 32],
                64,
                0,
                object.id().checksum(),
                64,
            )?],
        )?;
        repository.put_if_absent(object).await?;
        publisher.reserve(&manifest, &keys).await?;
        let publication = publisher.publish(&manifest, &keys).await?;
        assert_eq!(publisher.purge_tombstones().await?, vec![tombstone.clone()]);
        let generation = publication.registry_generation();
        let reopened = LocalRepository::attach(&path, &identity).await?;
        let cold = BackupPublisher::new(&reopened, &identity, &signer)
            .with_trusted_generation(generation)?
            .with_control_resources(&resources, 64 * 1024)?;
        assert_eq!(cold.purge_tombstones().await?, vec![tombstone]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn legacy_registry_heads_upgrade_without_inventing_purge_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    resources::admitted(96 * 1024 * 1024, |resources| async move {
        use sha2::Digest;
        use std::os::unix::fs::PermissionsExt;
        for magic in [b"POSBKG04", b"POSBKG05"] {
            let dir = tempfile::tempdir()?;
            let secrets = dir.path().join("secrets");
            let path = dir.path().join("repo");
            for root in [&secrets, &path] {
                std::fs::create_dir(root)?;
                std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
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
            let repository = LocalRepository::initialize(&path, identity.clone()).await?;
            let mut generation = magic.to_vec();
            generation.extend_from_slice(&1_u64.to_be_bytes());
            generation.extend_from_slice(&[0; 32]);
            let fixture = BackupPurgeTombstone::new([3; 16], "default", [9; 16], 10)?
                .signed_bytes(&identity, &signer)?;
            generation.extend_from_slice(fixture.get(8..116).ok_or("repository identity fixture")?);
            for _ in 0..if magic == b"POSBKG04" { 4 } else { 5 } {
                generation.extend_from_slice(&0_u32.to_be_bytes());
            }
            generation.extend_from_slice(&signer.sign(&sha2::Sha256::digest(&generation))?.bytes());
            let object = ImmutableObject::new(generation)?;
            let original = object.id();
            repository.put_if_absent(object).await?;
            let mut head = b"POSBKH01".to_vec();
            head.extend_from_slice(&original.checksum());
            head.extend_from_slice(&signer.sign(&sha2::Sha256::digest(&head))?.bytes());
            repository
                .compare_and_swap_head_at(
                    HeadSlot::registry(),
                    RegistryHeadChange::new(None, head)?,
                )
                .await?;
            let publisher = BackupPublisher::new(&repository, &identity, &signer)
                .with_trusted_generation(original.checksum())?
                .with_control_resources(&resources, 64 * 1024)?;
            assert!(publisher.purge_tombstones().await?.is_empty());
            let tombstone = BackupPurgeTombstone::new([3; 16], "default", [9; 16], 10)?;
            let upgraded = publisher.record_purge_tombstone(&tombstone).await?;
            assert_ne!(upgraded, original.checksum());
            assert_eq!(publisher.purge_tombstones().await?, vec![tombstone]);
        }
        Ok(())
    })
    .await
}
