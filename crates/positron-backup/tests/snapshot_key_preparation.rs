#![cfg(feature = "test-support")]
#[path = "support/snapshot_resources.rs"]
mod resources;
use positron_backup::*;
use positron_kernel::{BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct Observed<'a> {
    inner: &'a LocalRepository,
    key_puts: AtomicUsize,
    unknown: AtomicBool,
}
#[async_trait::async_trait]
impl Repository for Observed<'_> {
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
    async fn head(&self, object: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        self.inner.head(object).await
    }
    async fn read_range(&self, range: ObjectRange) -> Result<ChecksummedBytes, RepositoryFailure> {
        self.inner.read_range(range).await
    }
    async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let key = object.bytes().starts_with(b"POSBKE01");
        if key {
            self.key_puts.fetch_add(1, Ordering::Relaxed);
        }
        let result = self.inner.put_if_absent(object).await?;
        if key && self.unknown.swap(false, Ordering::Relaxed) {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        Ok(result)
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
#[tokio::test]
async fn signed_reservation_precedes_bounded_key_preparation()
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
        let custody = BootstrapKeyCustody::initialize(&secrets)?;
        let instance = InstanceId::new([2; 16])?;
        let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
        let signer = custody.backup_control_signer(instance, &protected)?;
        let identity = RepositoryIdentity::local(
            [1; 16],
            instance.to_bytes(),
            signer.identity().fingerprint(),
            &path,
        )?;
        let repository = LocalRepository::initialize(&path, identity.clone()).await?;
        let observed = Observed {
            inner: &repository,
            key_puts: AtomicUsize::new(0),
            unknown: AtomicBool::new(false),
        };
        let keys = (1u128..=64)
            .map(|tenant| BackupKeyEnvelope::new(tenant.to_be_bytes(), 1, [3; 32], vec![4; 64]))
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = BackupManifest::new(
            [5; 16],
            identity.clone(),
            BackupCatalogIdentity::new(1, [6; 32], 2, 1, [7; 32])?,
            BackupRetention::new(1, 2)?,
            BackupPublisher::key_context(&keys)?,
            vec![BackupObject::new([7; 32], 1, 0, [8; 32], 1)?],
        )?;
        let publisher = BackupPublisher::new(&observed, &identity, &signer)
            .with_control_resources(&resources, 64 * 1024)?;
        publisher.reserve(&manifest, &keys).await?;
        assert_eq!(
            observed.key_puts.load(Ordering::Relaxed),
            0,
            "reservation must not perform all-key I/O before its pending Registry commit"
        );
        assert!(publisher.list(None, 1).await?.snapshots().is_empty());
        assert!(publisher.verify(manifest.snapshot_id()).await.is_err());
        assert_eq!(
            publisher.prepare_key_step(&manifest, &keys, 65).await,
            Err(RepositoryFailure::InvalidInput)
        );
        assert_eq!(
            publisher.prepare_key_step(&manifest, &keys[..1], 0).await,
            Err(RepositoryFailure::IdentityMismatch)
        );
        assert_eq!(publisher.prepare_key_step(&manifest, &keys, 64).await?, 64);
        assert_eq!(observed.key_puts.load(Ordering::Relaxed), 0);
        assert_eq!(publisher.prepare_key_step(&manifest, &keys, 0).await?, 1);
        assert_eq!(observed.key_puts.load(Ordering::Relaxed), 1);
        observed.unknown.store(true, Ordering::Relaxed);
        assert_eq!(
            publisher.prepare_key_step(&manifest, &keys, 1).await,
            Err(RepositoryFailure::OutcomeUnknown)
        );
        assert_eq!(observed.key_puts.load(Ordering::Relaxed), 2);
        drop(publisher);
        // Reopen the actual Repository and recover bounded signed ancestry;
        // retry the same persisted index after its Put committed without an ack.
        let reopened = LocalRepository::attach(&path, &identity).await?;
        let observed = Observed {
            inner: &reopened,
            key_puts: AtomicUsize::new(0),
            unknown: AtomicBool::new(false),
        };
        let publisher = BackupPublisher::new(&observed, &identity, &signer)
            .with_control_resources(&resources, 64 * 1024)?;
        let mut proof = publisher
            .begin_registry_verification([5; 16], [9; 32])
            .await?;
        for _ in 0..8 {
            if proof.complete()? {
                break;
            }
            publisher.registry_verification_step(&mut proof).await?;
        }
        assert!(proof.complete()?);
        let publisher = publisher.with_registry_verification(&proof)?;
        assert_eq!(publisher.prepare_key_step(&manifest, &keys, 1).await?, 2);
        assert_eq!(observed.key_puts.load(Ordering::Relaxed), 1);
        let receipt = publisher
            .cancellation_candidate([5; 16])
            .await?
            .ok_or("candidate")?;
        let mut plan = publisher
            .prepare_cancellation([5; 16], receipt.manifest().checksum())
            .await?;
        while !publisher.scan_cancellation_step(&mut plan).await? {}
        let mut progress = publisher.claim_cancellation(&plan).await?;
        for _ in 0..67 {
            if progress.complete() {
                break;
            }
            progress = publisher
                .delete_expired_step([5; 16], receipt.manifest().checksum())
                .await?;
        }
        assert!(progress.complete());
        assert_eq!(progress.deleted_objects(), 3); // two prepared keys + manifest
        assert_eq!(progress.already_absent_objects(), 63); // data + remaining keys
        publisher
            .acknowledge_expiry([5; 16], receipt.manifest().checksum())
            .await?;
        assert_eq!(
            publisher.prepare_key_step(&manifest, &keys, 2).await,
            Err(RepositoryFailure::PreconditionFailed)
        );
        assert_eq!(observed.key_puts.load(Ordering::Relaxed), 1);

        // Two pending candidates sharing the same key context keep both prepared
        // and still-absent references live when one partial preparation cancels.
        let candidate = |snapshot| {
            BackupManifest::new(
                snapshot,
                identity.clone(),
                BackupCatalogIdentity::new(1, [6; 32], 2, 1, [7; 32])?,
                BackupRetention::new(1, 2)?,
                BackupPublisher::key_context(&keys)?,
                vec![BackupObject::new([7; 32], 1, 0, [8; 32], 1)?],
            )
        };
        let cancelled = candidate([10; 16])?;
        let shared = candidate([11; 16])?;
        publisher.reserve(&cancelled, &keys).await?;
        publisher.prepare_key_step(&cancelled, &keys, 0).await?;
        publisher.reserve(&shared, &keys).await?;
        let receipt = publisher
            .cancellation_candidate([10; 16])
            .await?
            .ok_or("shared candidate")?;
        let mut plan = publisher
            .prepare_cancellation([10; 16], receipt.manifest().checksum())
            .await?;
        while !publisher.scan_cancellation_step(&mut plan).await? {}
        let mut progress = publisher.claim_cancellation(&plan).await?;
        for _ in 0..67 {
            if progress.complete() {
                break;
            }
            progress = publisher
                .delete_expired_step([10; 16], receipt.manifest().checksum())
                .await?;
        }
        assert!(progress.complete());
        assert_eq!(progress.retained_shared_objects(), 65);
        assert_eq!(progress.deleted_objects(), 1); // cancelled manifest only
        assert!(publisher.cancellation_candidate([11; 16]).await?.is_some());
        assert_eq!(publisher.prepare_key_step(&shared, &keys, 0).await?, 1);
        assert!(publisher.list(None, 1).await?.snapshots().is_empty());
        Ok(())
    })
    .await
}
