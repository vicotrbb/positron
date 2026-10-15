#![cfg(feature = "test-support")]
#[path = "support/snapshot_resources.rs"]
mod resources;
use positron_backup::*;
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct NoHead<'a> {
    inner: &'a LocalRepository,
    heads: AtomicUsize,
    corrupt: AtomicBool,
    good: ObjectId,
    bad: ObjectId,
    length: u64,
}
#[async_trait::async_trait]
impl Repository for NoHead<'_> {
    async fn storage_policy(&self) -> Result<RepositoryPolicy, RepositoryFailure> {
        self.inner.storage_policy().await
    }
    async fn list(&self, request: ListRequest) -> Result<ListPage, RepositoryFailure> {
        self.inner.list(request).await
    }
    async fn begin_upload(&self, plan: UploadPlan) -> Result<UploadState, RepositoryFailure> {
        self.inner.begin_upload(plan).await
    }
    async fn inspect_upload(&self, id: UploadId) -> Result<Option<UploadState>, RepositoryFailure> {
        self.inner.inspect_upload(id).await
    }
    async fn resume_upload(&self, part: UploadPart) -> Result<UploadOutcome, RepositoryFailure> {
        self.inner.resume_upload(part).await
    }
    async fn abort_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        self.inner.abort_upload(id).await
    }
    async fn identify(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        self.inner.identify().await
    }
    async fn object_size_hint(&self, object: ObjectId) -> Result<u64, RepositoryFailure> {
        self.inner.object_size_hint(object).await
    }
    async fn head(&self, _: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        self.heads.fetch_add(1, Ordering::Relaxed);
        Err(RepositoryFailure::PermissionDenied)
    }
    async fn read_range(&self, range: ObjectRange) -> Result<ChecksummedBytes, RepositoryFailure> {
        let expected =
            ObjectRange::new(self.good, 0, self.length)?.with_expected_size(self.length)?;
        if self.corrupt.load(Ordering::Relaxed) && range == expected {
            // The alternate backend object is valid under its own checksum;
            // only the engine's expected complete-object hash can reject it.
            self.inner
                .read_range(
                    ObjectRange::new(self.bad, 0, self.length)?.with_expected_size(self.length)?,
                )
                .await
        } else {
            self.inner.read_range(range).await
        }
    }
    async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        self.inner.put_if_absent(object).await
    }
    async fn delete(&self, object: ObjectId) -> Result<DeleteOutcome, RepositoryFailure> {
        self.inner.delete(object).await
    }
    async fn registry_head_at(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<RegistryHead>, RepositoryFailure> {
        self.inner.registry_head_at(slot).await
    }
    async fn delete_head_if_version(
        &self,
        slot: HeadSlot,
        expected: ObjectVersion,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        self.inner.delete_head_if_version(slot, expected).await
    }
    async fn compare_and_swap_head_at(
        &self,
        slot: HeadSlot,
        change: RegistryHeadChange,
    ) -> Result<CasOutcome, RepositoryFailure> {
        self.inner.compare_and_swap_head_at(slot, change).await
    }
}
struct Source(Vec<u8>);
impl BackupSource for Source {
    fn read(&self, _: [u8; 32], offset: u64, length: u64) -> Result<Vec<u8>, RepositoryFailure> {
        let end = offset
            .checked_add(length)
            .ok_or(RepositoryFailure::InvalidInput)?;
        self.0
            .get(offset as usize..end as usize)
            .map(<[u8]>::to_vec)
            .ok_or(RepositoryFailure::InvalidInput)
    }
}
#[tokio::test]
async fn snapshot_data_uses_only_size_hints_and_rejects_wrong_final_hash_before_publication()
-> Result<(), Box<dyn std::error::Error>> {
    resources::admitted(96 * 1024 * 1024, |resources| async move {
        let directory = tempfile::tempdir()?;
        let secrets = directory.path().join("secrets");
        let path = directory.path().join("repository");
        use std::os::unix::fs::PermissionsExt;
        for path in [&secrets, &path] {
            std::fs::create_dir(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        let keys = BootstrapKeyCustody::initialize(&secrets)?;
        let instance = InstanceId::new([2; 16])?;
        let protected = keys.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
        let signer = keys.backup_control_signer(instance, &protected)?;
        let identity = RepositoryIdentity::local(
            [1; 16],
            instance.to_bytes(),
            signer.identity().fingerprint(),
            &path,
        )?;
        let repository = LocalRepository::initialize(&path, identity.clone()).await?;
        let source = Source(vec![7; 1024]);
        let good = ImmutableObject::new(source.0.clone())?;
        let good_id = good.id();
        repository.put_if_absent(good).await?;
        let wrong = ImmutableObject::new(vec![8; 1024])?;
        let bad_id = wrong.id();
        repository.put_if_absent(wrong).await?;
        let envelope = BackupKeyEnvelope::new([9; 16], 1, [10; 32], vec![11; 128])?;
        let external = source.0.capacity() as u64
            + envelope.retained_memory_bytes()
            + std::mem::size_of::<BackupKeyEnvelope>() as u64;
        let key_context = BackupPublisher::key_context(std::slice::from_ref(&envelope))?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity.clone(),
            BackupCatalogIdentity::new(1, [6; 32], 1, 0, [3; 32])?,
            BackupRetention::new(1, 2)?,
            key_context,
            vec![BackupObject::new(
                [3; 32],
                1024,
                0,
                good_id.checksum(),
                1024,
            )?],
        )?;
        let observed = NoHead {
            inner: &repository,
            heads: AtomicUsize::new(0),
            corrupt: AtomicBool::new(true),
            good: good_id,
            bad: bad_id,
            length: 1024,
        };
        let publisher = BackupPublisher::new(&observed, &identity, &signer)
            .with_control_resources(&resources, external)?;
        publisher
            .reserve(&manifest, std::slice::from_ref(&envelope))
            .await?;
        let before = repository.registry_head_at(HeadSlot::registry()).await?;
        let mut verification = None;
        assert_eq!(
            publisher
                .transfer_step_bounded(
                    &manifest,
                    &source,
                    BackupTransfer::start(&manifest)?,
                    &mut verification
                )
                .await,
            Err(RepositoryFailure::ChecksumMismatch)
        );
        assert_eq!(
            publisher
                .publish(&manifest, std::slice::from_ref(&envelope))
                .await,
            Err(RepositoryFailure::ChecksumMismatch)
        );
        assert_eq!(
            repository.registry_head_at(HeadSlot::registry()).await?,
            before
        );
        assert!(publisher.list(None, 1).await?.snapshots().is_empty());
        observed.corrupt.store(false, Ordering::Relaxed);
        let mut verification = None;
        let transfer = publisher
            .transfer_step_bounded(
                &manifest,
                &source,
                BackupTransfer::start(&manifest)?,
                &mut verification,
            )
            .await?;
        assert!(transfer.complete());
        assert_eq!(transfer.reused_bytes(), 1024);
        let publication = publisher
            .publish(&manifest, std::slice::from_ref(&envelope))
            .await?;
        assert_eq!(publication.snapshot_id(), manifest.snapshot_id());
        assert_eq!(publisher.verify(manifest.snapshot_id()).await?, manifest);
        observed.corrupt.store(true, Ordering::Relaxed);
        let before = repository.registry_head_at(HeadSlot::registry()).await?;
        assert_eq!(
            publisher.verify(manifest.snapshot_id()).await,
            Err(RepositoryFailure::ChecksumMismatch)
        );
        assert_eq!(
            repository.registry_head_at(HeadSlot::registry()).await?,
            before
        );
        assert_eq!(observed.heads.load(Ordering::Relaxed), 0);
        Ok(())
    })
    .await
}
