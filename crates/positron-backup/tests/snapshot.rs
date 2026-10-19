#[path = "support/snapshot_repository.rs"]
mod snapshot_repository;
#[path = "support/snapshot_resources.rs"]
mod snapshot_resources;
use positron_backup::{
    BackupCatalogIdentity, BackupManifest, BackupObject, BackupRetention, RepositoryIdentity,
};
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};

#[test]
fn snapshot_manifest_binds_catalog_objects_repository_and_integrity_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "positron-backup-manifest-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&root)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let keys = BootstrapKeyCustody::initialize(&root)?;
    let instance = InstanceId::new([2; 16])?;
    let protected = keys.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
    let signer = keys.backup_control_signer(instance, &protected)?;
    let identity = RepositoryIdentity::local(
        [1; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        &root,
    )?;
    let object = BackupObject::new([3; 32], 4096, 0, [4; 32], 4096)?;
    let manifest = BackupManifest::new(
        [5; 16],
        identity.clone(),
        BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?,
        BackupRetention::new(1000, 2000)?,
        [8; 32],
        vec![object],
    )?;
    assert_eq!(manifest.capture_index(), [3; 32]);
    let encoded = manifest.signed_bytes(&signer)?;
    assert_eq!(
        BackupManifest::verify(&encoded, &identity, signer.identity())?,
        manifest
    );
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().ok_or("signature")? ^= 1;
    assert!(BackupManifest::verify(&corrupt, &identity, signer.identity()).is_err());
    let wrong = RepositoryIdentity::local(
        [9; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        &root,
    )?;
    assert!(BackupManifest::verify(&encoded, &wrong, signer.identity()).is_err());
    assert!(
        BackupManifest::verify(&encoded[..encoded.len() - 1], &identity, signer.identity())
            .is_err()
    );
    drop(keys);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn signed_registry_and_snapshot_objects_survive_reopen_and_reuse()
-> Result<(), Box<dyn std::error::Error>> {
    snapshot_resources::admitted(96 * 1024 * 1024, |resources| async move {
        use positron_backup::{
            BackupKeyEnvelope, BackupPublisher, BackupSource, BackupTransfer, LocalRepository,
            Repository,
        };
        struct Source(Vec<u8>);
        impl BackupSource for Source {
            fn read(
                &self,
                _: [u8; 32],
                offset: u64,
                length: u64,
            ) -> Result<Vec<u8>, positron_backup::RepositoryFailure> {
                self.0
                    .get(offset as usize..(offset + length) as usize)
                    .map(<[u8]>::to_vec)
                    .ok_or(positron_backup::RepositoryFailure::InvalidInput)
            }
        }
        let root = std::env::temp_dir().join(format!(
            "positron-backup-publish-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir(&root)?;
        let secrets = root.join("secrets");
        std::fs::create_dir(&secrets)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
        let repository_root = root.join("repository");
        std::fs::create_dir(&repository_root)?;
        std::fs::set_permissions(&repository_root, std::fs::Permissions::from_mode(0o700))?;
        let keys = BootstrapKeyCustody::initialize(&secrets)?;
        let instance = InstanceId::new([2; 16])?;
        let protected = keys.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
        let signer = keys.backup_control_signer(instance, &protected)?;
        let identity = RepositoryIdentity::local(
            [1; 16],
            [2; 16],
            signer.identity().fingerprint(),
            &repository_root,
        )?;
        let repository = LocalRepository::initialize(&repository_root, identity.clone()).await?;
        let object_length = positron_backup::MAX_RANGE_BYTES + 8192;
        let source = Source(vec![0x41; object_length as usize]);
        let object = positron_backup::ImmutableObject::new(source.0.clone())?;
        let envelope = BackupKeyEnvelope::new([9; 16], 1, [10; 32], vec![0x62; 128])?;
        // Source, immutable source object and the later partial-upload pair remain
        // owned by this fixture while controls execute. Context envelope storage is
        // external to the Publisher's own manifest/publication/cleanup inputs.
        let external_memory = object_length
            .checked_mul(4)
            .and_then(|n| n.checked_add(envelope.retained_memory_bytes()))
            .and_then(|n| n.checked_add(std::mem::size_of::<BackupKeyEnvelope>() as u64))
            .ok_or("fixture memory")?;
        let key_context = BackupPublisher::key_context(std::slice::from_ref(&envelope))?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                object_length,
                0,
                object.id().checksum(),
                object_length,
            )?],
        )?;
        let publisher = BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, external_memory)?;
        assert_eq!(
            publisher
                .transfer_step(&manifest, &source, BackupTransfer::start(&manifest)?)
                .await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        publisher
            .reserve(&manifest, std::slice::from_ref(&envelope))
            .await?;
        assert!(publisher.verify(manifest.snapshot_id()).await.is_err());
        let pending_repository = LocalRepository::attach(&repository_root, &identity).await?;
        let pending_publisher = BackupPublisher::new(&pending_repository, &identity, &signer)
            .with_control_resources(&resources, external_memory)?;
        pending_publisher
            .reserve(&manifest, std::slice::from_ref(&envelope))
            .await?;
        assert!(
            pending_publisher
                .verify(manifest.snapshot_id())
                .await
                .is_err()
        );
        assert!(
            pending_publisher
                .list(None, 1)
                .await?
                .snapshots()
                .is_empty()
        );
        let conflicting = BackupManifest::new(
            manifest.snapshot_id(),
            identity.clone(),
            BackupCatalogIdentity::new(18, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                object_length,
                0,
                object.id().checksum(),
                object_length,
            )?],
        )?;
        assert_eq!(
            pending_publisher
                .reserve(&conflicting, std::slice::from_ref(&envelope))
                .await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        drop(pending_repository);
        let reserved_head = repository
            .registry_head_at(positron_backup::HeadSlot::registry())
            .await?
            .ok_or("reserved head")?;
        let mut checkpoint = BackupTransfer::start(&manifest)?;
        while !checkpoint.complete() {
            checkpoint = publisher
                .transfer_step(&manifest, &source, checkpoint)
                .await?;
        }
        assert_eq!(checkpoint.uploaded_bytes(), object_length);
        let preparation_keys = std::slice::from_ref(&envelope);
        let mut next_key = 0;
        while usize::try_from(next_key)? < preparation_keys.len() {
            next_key = publisher
                .prepare_key_step(&manifest, preparation_keys, next_key)
                .await?;
        }
        let mut verification = publisher.prepare_publication(&manifest).await?;
        let rendered = format!("{verification:?}");
        assert!(!rendered.contains(&format!("{reserved_head:?}")));
        assert!(!rendered.contains(&format!("{:?}", envelope.tenant())));
        assert!(!rendered.contains(&format!("{:?}", envelope.protected())));
        assert!(rendered.len() <= 256);
        assert!(!verification.complete());
        assert_eq!(
            publisher.commit_publication(&manifest, &verification).await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        assert!(
            !publisher
                .verify_publication_step(&manifest, &mut verification)
                .await?
        );
        let saved = publisher.publication_checkpoint(&verification)?;
        let mut corrupt_checkpoint = saved.clone();
        *corrupt_checkpoint
            .last_mut()
            .ok_or("checkpoint signature")? ^= 1;
        assert!(
            publisher
                .resume_publication(&manifest, &corrupt_checkpoint)
                .await
                .is_err()
        );
        let mut verification = publisher.resume_publication(&manifest, &saved).await?;
        while !publisher
            .verify_publication_step(&manifest, &mut verification)
            .await?
        {}
        let receipt = publisher
            .commit_publication(&manifest, &verification)
            .await?;
        assert_eq!(
            publisher.reconcile_publication(&manifest).await?,
            Some(receipt)
        );
        let reader = positron_backup::BackupSnapshotReader::open(
            &repository,
            &identity,
            signer.identity(),
            receipt.manifest(),
            &resources,
            external_memory,
        )
        .await?;
        assert_eq!(reader.manifest(), &manifest);
        assert_eq!(reader.read_file([3; 32], 8 * 1024 * 1024).await?, source.0);
        assert!(reader.read_file([3; 32], 1).await.is_err());
        assert!(reader.read_file([99; 32], 8 * 1024 * 1024).await.is_err());
        let wrong = RepositoryIdentity::local(
            [99; 16],
            [2; 16],
            signer.identity().fingerprint(),
            &repository_root,
        )?;
        assert!(
            positron_backup::BackupSnapshotReader::open(
                &repository,
                &wrong,
                signer.identity(),
                receipt.manifest(),
                &resources,
                external_memory,
            )
            .await
            .is_err()
        );
        drop(reader);
        let different = BackupManifest::new(
            manifest.snapshot_id(),
            identity.clone(),
            BackupCatalogIdentity::new(18, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            manifest.objects().to_vec(),
        )?;
        assert_eq!(
            publisher.reconcile_publication(&different).await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        assert_eq!(receipt.snapshot_id(), [5; 16]);
        assert_ne!(receipt.registry_generation(), [0; 32]);
        let other_manifest = BackupManifest::new(
            [6; 16],
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                object_length,
                0,
                object.id().checksum(),
                object_length,
            )?],
        )?;
        publisher
            .reserve(&other_manifest, std::slice::from_ref(&envelope))
            .await?;
        publisher
            .publish(&other_manifest, std::slice::from_ref(&envelope))
            .await?;
        let page = publisher.list(None, 1).await?;
        assert_eq!(page.snapshots().len(), 1);
        assert_eq!(
            page.snapshots()
                .first()
                .ok_or("first snapshot")?
                .snapshot_id(),
            [5; 16]
        );
        let cursor = page.next_cursor().ok_or("next cursor")?;
        let mut unknown_key = cursor.encode();
        unknown_key.get_mut(72..).ok_or("cursor key")?.fill(0xaa);
        let unknown_key = positron_backup::BackupListCursor::decode(&unknown_key)?;
        assert_eq!(
            publisher.list(Some(unknown_key), 1).await,
            Err(positron_backup::RepositoryFailure::InvalidInput)
        );
        let next = publisher.list(Some(cursor), 1).await?;
        assert_eq!(
            next.snapshots()
                .first()
                .ok_or("second snapshot")?
                .snapshot_id(),
            [6; 16]
        );
        assert!(next.next_cursor().is_none());
        let later_manifest = BackupManifest::new(
            [7; 16],
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                object_length,
                0,
                object.id().checksum(),
                object_length,
            )?],
        )?;
        publisher
            .reserve(&later_manifest, std::slice::from_ref(&envelope))
            .await?;
        assert_eq!(
            publisher.list(Some(cursor), 1).await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        drop(repository);
        let repository = LocalRepository::attach(&repository_root, &identity).await?;
        let publisher = BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, external_memory)?;
        let proof = complete_fixture_registry(&publisher).await?;
        let publisher = publisher.with_registry_verification(&proof)?;
        let verified = publisher.verify([5; 16]).await?;
        assert_eq!(verified, manifest);
        let mut object_verification = None;
        let bounded = publisher
            .transfer_step_bounded(
                &manifest,
                &source,
                BackupTransfer::start(&manifest)?,
                &mut object_verification,
            )
            .await?;
        assert!(!bounded.complete());
        assert_eq!(
            object_verification
                .as_ref()
                .ok_or("range verification")?
                .verified_bytes(),
            positron_backup::MAX_RANGE_BYTES
        );
        // A cold restart keeps completed-object counts and redoes the partial hash.
        let restarted = BackupTransfer::decode(&bounded.encode(), &manifest)?;
        let mut object_verification = None;
        let restarted = publisher
            .transfer_step_bounded(&manifest, &source, restarted, &mut object_verification)
            .await?;
        assert!(!restarted.complete());
        let restarted = publisher
            .transfer_step_bounded(&manifest, &source, restarted, &mut object_verification)
            .await?;
        assert!(restarted.complete());
        let reused = publisher
            .transfer_step(&manifest, &source, BackupTransfer::start(&manifest)?)
            .await?;
        assert!(reused.complete());
        assert_eq!(reused.reused_bytes(), object_length);
        assert_eq!(
            publisher
                .publish(&manifest, std::slice::from_ref(&envelope))
                .await?
                .manifest(),
            receipt.manifest()
        );
        let current_head = repository
            .registry_head_at(positron_backup::HeadSlot::registry())
            .await?
            .ok_or("current head")?;
        let anchored = BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, external_memory)?
            .with_trusted_generation(receipt.registry_generation())?;
        let anchored_proof = complete_fixture_registry(&anchored).await?;
        let anchored = anchored.with_registry_verification(&anchored_proof)?;
        repository
            .compare_and_swap_head_at(
                positron_backup::HeadSlot::registry(),
                positron_backup::RegistryHeadChange::new(
                    Some(current_head.version()),
                    reserved_head.bytes().to_vec(),
                )?,
            )
            .await?;
        assert_eq!(
            anchored.list(None, 128).await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        let replayed = repository
            .registry_head_at(positron_backup::HeadSlot::registry())
            .await?
            .ok_or("replayed head")?;
        repository
            .compare_and_swap_head_at(
                positron_backup::HeadSlot::registry(),
                positron_backup::RegistryHeadChange::new(
                    Some(replayed.version()),
                    current_head.bytes().to_vec(),
                )?,
            )
            .await?;
        assert_eq!(anchored.list(None, 128).await?.snapshots().len(), 2);
        let mut expiry = anchored
            .prepare_expiry([91; 16], [5; 16], receipt.manifest().checksum())
            .await?;
        while !anchored.scan_expiry_step(&mut expiry).await? {}
        let early = positron_kernel::RetentionTimeAuthority::establish_with_source(
            positron_kernel::FixedLifecycleClockSource::new(
                positron_domain::time::UnixNanoseconds::new(1_999_000_000_000),
            ),
            positron_kernel::LifecycleClockPolicy::default(),
        )?;
        assert_eq!(
            anchored.claim_expiry(&expiry, &early).await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        let due = positron_kernel::RetentionTimeAuthority::establish_with_source(
            positron_kernel::FixedLifecycleClockSource::new(
                positron_domain::time::UnixNanoseconds::new(2_000_000_000_000),
            ),
            positron_kernel::LifecycleClockPolicy::default(),
        )?;
        let protected_manifest = BackupManifest::new(
            [9; 16],
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                object_length,
                0,
                object.id().checksum(),
                object_length,
            )?],
        )?;
        let competing_repository = LocalRepository::attach(&repository_root, &identity).await?;
        let competing = BackupPublisher::new(&competing_repository, &identity, &signer)
            .with_control_resources(&resources, external_memory)?
            .with_trusted_generation(receipt.registry_generation())?;
        let competing_proof = complete_fixture_registry(&competing).await?;
        let competing = competing.with_registry_verification(&competing_proof)?;
        competing
            .reserve(&protected_manifest, std::slice::from_ref(&envelope))
            .await?;
        assert_eq!(
            anchored.claim_expiry(&expiry, &due).await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        competing
            .publish(&protected_manifest, std::slice::from_ref(&envelope))
            .await?;
        let refreshed_proof = complete_fixture_registry(&anchored).await?;
        let anchored = anchored.with_registry_verification(&refreshed_proof)?;
        let mut expiry = anchored
            .prepare_expiry([91; 16], [5; 16], receipt.manifest().checksum())
            .await?;
        while !anchored.scan_expiry_step(&mut expiry).await? {}
        #[cfg(feature = "test-support")]
        {
            let replay = positron_kernel::RetentionTimeAuthority::for_test_ingest_time(
                positron_domain::time::UnixNanoseconds::new(2_000_000_000_000),
            );
            assert_eq!(
                anchored.claim_expiry(&expiry, &replay).await,
                Err(positron_backup::RepositoryFailure::PreconditionFailed)
            );
        }
        struct JumpClock(std::sync::Arc<std::sync::atomic::AtomicI64>);
        impl positron_kernel::LifecycleClockSource for JumpClock {
            fn read(
                &self,
            ) -> Result<
                positron_domain::time::UnixNanoseconds,
                positron_kernel::LifecycleClockFailure,
            > {
                Ok(positron_domain::time::UnixNanoseconds::new(
                    self.0.load(std::sync::atomic::Ordering::Acquire),
                ))
            }
        }
        let wall = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(1_999_000_000_000));
        let uncertain_clock = positron_kernel::RetentionTimeAuthority::establish_with_source(
            JumpClock(std::sync::Arc::clone(&wall)),
            positron_kernel::LifecycleClockPolicy::default(),
        )?;
        wall.store(2_999_000_000_000, std::sync::atomic::Ordering::Release);
        assert_eq!(
            anchored.claim_expiry(&expiry, &uncertain_clock).await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        let claim = anchored.claim_expiry(&expiry, &due).await?;
        assert!(!claim.complete());
        assert!(anchored.verify([5; 16]).await.is_err());
        assert_eq!(anchored.verify([6; 16]).await?, other_manifest);
        let manifest_length = manifest.signed_bytes(&signer)?.len() as u64;
        let claimed_object_candidate = BackupManifest::new(
            [8; 16],
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                manifest_length,
                0,
                receipt.manifest().checksum(),
                manifest_length,
            )?],
        )?;
        assert_eq!(
            anchored
                .reserve(&claimed_object_candidate, std::slice::from_ref(&envelope))
                .await,
            Err(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        let lost_ack = snapshot_repository::LostDeleteAcknowledgement::new(&repository);
        let uncertain = BackupPublisher::new(&lost_ack, &identity, &signer)
            .with_control_resources(&resources, external_memory)?
            .with_trusted_generation(receipt.registry_generation())?;
        let uncertain_proof = complete_fixture_registry(&uncertain).await?;
        let uncertain = uncertain.with_registry_verification(&uncertain_proof)?;
        assert_eq!(
            uncertain
                .delete_expired_step([91; 16], receipt.manifest().checksum())
                .await,
            Err(positron_backup::RepositoryFailure::OutcomeUnknown)
        );
        let competing_cleanup_proof = complete_fixture_registry(&competing).await?;
        let competing = competing.with_registry_verification(&competing_cleanup_proof)?;
        let pending = competing
            .expiry_progress([91; 16], receipt.manifest().checksum())
            .await?;
        assert!(!pending.complete());
        assert_eq!(pending.deleted_objects(), 0);
        let reclaimed = competing
            .delete_expired_step([91; 16], receipt.manifest().checksum())
            .await?;
        assert!(reclaimed.complete());
        assert_eq!(reclaimed.deleted_objects(), 0);
        assert_eq!(reclaimed.already_absent_objects(), 1);
        assert!(reclaimed.retained_shared_objects() > 0);
        assert_eq!(
            repository.head(receipt.manifest()).await,
            Err(positron_backup::RepositoryFailure::NotFound)
        );
        assert!(repository.head(object.id()).await.is_ok());
        let after_crash = BackupPublisher::new(&repository, &identity, &signer)
            .with_control_resources(&resources, external_memory)?
            .with_trusted_generation(receipt.registry_generation())?;
        let after_crash_proof = complete_fixture_registry(&after_crash).await?;
        let after_crash = after_crash.with_registry_verification(&after_crash_proof)?;
        assert!(
            after_crash
                .expiry_progress([91; 16], receipt.manifest().checksum())
                .await?
                .complete()
        );
        after_crash
            .acknowledge_expiry([91; 16], receipt.manifest().checksum())
            .await?;
        assert_eq!(
            after_crash
                .expiry_progress([91; 16], receipt.manifest().checksum())
                .await,
            Err(positron_backup::RepositoryFailure::NotFound)
        );
        assert_eq!(
            after_crash
                .prepare_expiry([91; 16], [5; 16], receipt.manifest().checksum())
                .await
                .err(),
            Some(positron_backup::RepositoryFailure::NotFound)
        );
        let second_receipt = after_crash
            .list(None, 128)
            .await?
            .snapshots()
            .iter()
            .find(|entry| entry.snapshot_id() == [6; 16])
            .copied()
            .ok_or("second receipt")?;
        let mut second_expiry = after_crash
            .prepare_expiry([92; 16], [6; 16], second_receipt.manifest().checksum())
            .await?;
        while !after_crash.scan_expiry_step(&mut second_expiry).await? {}
        after_crash.claim_expiry(&second_expiry, &due).await?;
        let deleted = after_crash
            .delete_expired_step([92; 16], second_receipt.manifest().checksum())
            .await?;
        assert!(deleted.complete());
        assert_eq!(deleted.deleted_objects(), 1);
        assert_eq!(after_crash.verify([9; 16]).await?, protected_manifest);

        assert_eq!(
            after_crash
                .prepare_cancellation(
                    [9; 16],
                    protected_manifest.signed_bytes(&signer).map(|bytes| {
                        positron_backup::ImmutableObject::new(bytes)
                            .expect("manifest")
                            .id()
                            .checksum()
                    })?
                )
                .await
                .err(),
            Some(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        let partial_bytes = vec![0x71; object_length as usize];
        let partial_object = positron_backup::ImmutableObject::new(partial_bytes.clone())?;
        let cancelled_manifest = BackupManifest::new(
            [10; 16],
            identity.clone(),
            BackupCatalogIdentity::new(17, [6; 32], 2, 9, [3; 32])?,
            BackupRetention::new(1000, 2000)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                object_length,
                0,
                partial_object.id().checksum(),
                object_length,
            )?],
        )?;
        after_crash
            .reserve(&cancelled_manifest, std::slice::from_ref(&envelope))
            .await?;
        let upload = positron_backup::UploadPlan::new(partial_object.id(), object_length)?;
        let state = repository.begin_upload(upload).await?;
        assert!(matches!(
            repository
                .resume_upload(positron_backup::UploadPart::new(
                    state,
                    partial_bytes
                        .get(..positron_backup::MAX_RANGE_BYTES as usize)
                        .ok_or("part")?
                        .to_vec()
                )?)
                .await?,
            positron_backup::UploadOutcome::Pending(_)
        ));
        let cancelled_id =
            positron_backup::ImmutableObject::new(cancelled_manifest.signed_bytes(&signer)?)?.id();
        let mut cancellation = after_crash
            .prepare_cancellation([10; 16], cancelled_id.checksum())
            .await?;
        assert_eq!(cancellation.pending_upload_reconciliations(), 1);
        assert_eq!(
            cancellation.next_upload_reconciliation_bytes(),
            Some(object_length)
        );
        assert_eq!(
            after_crash.claim_cancellation(&cancellation).await.err(),
            Some(positron_backup::RepositoryFailure::PreconditionFailed)
        );
        while !after_crash
            .scan_cancellation_step(&mut cancellation)
            .await?
        {}
        assert!(repository.inspect_upload(upload.id()).await?.is_none());
        let mut cleanup = after_crash.claim_cancellation(&cancellation).await?;
        assert!(after_crash.cleanup_checkpoint(cleanup).is_err());
        let competing_cancellation_proof = complete_fixture_registry(&competing).await?;
        let competing = competing.with_registry_verification(&competing_cancellation_proof)?;
        while !cleanup.complete() {
            cleanup = competing
                .delete_expired_step([10; 16], cancelled_id.checksum())
                .await?;
        }
        assert_eq!(cleanup.deleted_objects(), 1);
        assert_eq!(cleanup.already_absent_objects(), 1);
        let after_cleanup_proof = complete_fixture_registry(&after_crash).await?;
        let after_crash = after_crash.with_registry_verification(&after_cleanup_proof)?;
        assert_eq!(
            after_crash.cleanup_for_owner([10; 16]).await?,
            Some(cleanup)
        );
        let completed = after_crash.cleanup_checkpoint(cleanup)?;
        after_crash
            .acknowledge_expiry([10; 16], cancelled_id.checksum())
            .await?;
        assert_eq!(after_crash.cleanup_for_owner([10; 16]).await?, None);
        let acknowledged_proof = complete_fixture_registry(&competing).await?;
        let competing = competing.with_registry_verification(&acknowledged_proof)?;
        assert_eq!(
            competing.verify_cleanup_checkpoint(&completed).await?,
            cleanup
        );
        let mut corrupted = completed.clone();
        *corrupted.last_mut().ok_or("cleanup signature")? ^= 1;
        assert!(
            competing
                .verify_cleanup_checkpoint(&corrupted)
                .await
                .is_err()
        );
        assert!(
            competing
                .verify_cleanup_checkpoint(&completed[..completed.len() - 1])
                .await
                .is_err()
        );
        assert_eq!(after_crash.verify([9; 16]).await?, protected_manifest);
        repository.delete(object.id()).await?;
        assert!(publisher.verify([9; 16]).await.is_err());
        drop(repository);
        drop(keys);
        std::fs::remove_dir_all(root)?;
        Ok(())
    })
    .await
}

async fn complete_fixture_registry(
    publisher: &positron_backup::BackupPublisher<'_>,
) -> Result<positron_backup::BackupRegistryVerification, Box<dyn std::error::Error>> {
    let mut proof = publisher
        .begin_registry_verification([0x7b; 16], [0x7c; 32])
        .await?;
    for _ in 0..4096 {
        if proof.complete()? {
            return Ok(proof);
        }
        publisher.registry_verification_step(&mut proof).await?;
    }
    if !proof.complete()? {
        return Err("bounded fixture ancestry exceeded".into());
    }
    Ok(proof)
}
