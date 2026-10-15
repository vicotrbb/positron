#![cfg(feature = "test-support")]
#[path = "support/snapshot_resources.rs"]
mod resources;
use positron_backup::*;
use positron_kernel::{
    BackupControlSigner, BootstrapKeyCustody, BootstrapObjectPurpose, InstanceId,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct Observed<'a> {
    inner: &'a LocalRepository,
    reads: AtomicUsize,
    truncate: AtomicBool,
    malformed: ObjectId,
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
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.truncate.load(Ordering::Relaxed) {
            self.inner
                .read_range(ObjectRange::new(self.malformed, 0, 1)?)
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
fn signed(
    mut bytes: Vec<u8>,
    signer: &BackupControlSigner,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    bytes.extend_from_slice(&signer.sign(&Sha256::digest(&bytes))?.bytes());
    Ok(bytes)
}
async fn install(
    repository: &LocalRepository,
    signer: &BackupControlSigner,
    payload: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let object = ImmutableObject::new(signed(payload, signer)?)?;
    let mut head = b"POSBKH01".to_vec();
    head.extend_from_slice(&object.id().checksum());
    repository.put_if_absent(object).await?;
    let expected = repository
        .registry_head_at(HeadSlot::registry())
        .await?
        .map(|head| head.version());
    assert!(matches!(
        repository
            .compare_and_swap_head_at(
                HeadSlot::registry(),
                RegistryHeadChange::new(expected, signed(head, signer)?)?
            )
            .await?,
        CasOutcome::Published(_)
    ));
    Ok(())
}
fn generation(identity_frame: &[u8], count: u32) -> Vec<u8> {
    let mut bytes = b"POSBKG04".to_vec();
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(identity_frame);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for index in 1..=count.min(4096) {
        bytes.extend_from_slice(&[1; 32]);
        let mut tenant = [0; 16];
        tenant[12..].copy_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(&tenant);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&[3; 32]);
    }
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes
}
#[tokio::test]
async fn control_reads_require_admitted_peak_before_body_and_reject_malformed_controls()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let secrets = root.path().join("secrets");
    std::fs::create_dir(&secrets)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
    let custody = BootstrapKeyCustody::initialize(&secrets)?;
    let instance = InstanceId::new([2; 16])?;
    let protected = custody.protect(instance, BootstrapObjectPurpose::Initialized, &[7; 32])?;
    let signer = custody.backup_control_signer(instance, &protected)?;
    let path = root.path().join("repository");
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [1; 16],
        instance.to_bytes(),
        signer.identity().fingerprint(),
        &path,
    )?;
    let repository = LocalRepository::initialize(&path, identity.clone()).await?;
    let identity_frame = std::fs::read(path.join("identity"))?;
    let identity_frame = identity_frame.as_slice();
    let malformed = ImmutableObject::new(vec![1])?;
    let malformed_id = malformed.id();
    repository.put_if_absent(malformed).await?;
    let observed = &Observed {
        inner: &repository,
        reads: AtomicUsize::new(0),
        truncate: AtomicBool::new(false),
        malformed: malformed_id,
    };
    let identity = &identity;
    let signer = &signer;
    let repository = &repository;
    resources::diagnostics(|resources| {
        assert!(matches!(
            BackupPublisher::new(observed, identity, signer).with_control_resources(resources, 0),
            Err(RepositoryFailure::PermissionDenied)
        ));
        Ok(())
    })?;
    install(repository, signer, generation(identity_frame, 1000)).await?;
    assert!(matches!(
        BackupPublisher::new(observed, identity, signer)
            .list(None, 1)
            .await,
        Err(RepositoryFailure::ControlMemoryRequired { .. })
    ));
    resources::admitted(8 * 1024 * 1024, |resources| async move {
        let publisher = BackupPublisher::new(observed, identity, signer).with_control_resources(&resources, 0)?;
        assert!(matches!(publisher.list(None, 1).await, Err(RepositoryFailure::ControlMemoryRequired { memory_bytes }) if memory_bytes > 8 * 1024 * 1024));
        assert_eq!(observed.reads.load(Ordering::Relaxed), 0);
        Ok(())
    }).await?;
    resources::admitted(16 * 1024 * 1024, |resources| async move {
        let publisher = BackupPublisher::new(observed, identity, signer)
            .with_control_resources(&resources, 0)?;
        assert!(publisher.list(None, 1).await?.snapshots().is_empty());
        assert!(observed.reads.load(Ordering::Relaxed) > 0);
        let wrong_identity = RepositoryIdentity::local(
            [9; 16],
            instance.to_bytes(),
            signer.identity().fingerprint(),
            &path,
        )?;
        let before_identity = observed.reads.load(Ordering::Relaxed);
        assert!(matches!(
            BackupPublisher::new(observed, &wrong_identity, signer)
                .with_control_resources(&resources, 0)?
                .list(None, 1)
                .await,
            Err(RepositoryFailure::IdentityMismatch)
        ));
        assert_eq!(observed.reads.load(Ordering::Relaxed), before_identity);
        observed.truncate.store(true, Ordering::Relaxed);
        assert!(matches!(
            publisher.list(None, 1).await,
            Err(RepositoryFailure::CorruptState)
        ));
        observed.truncate.store(false, Ordering::Relaxed);
        install(repository, signer, generation(identity_frame, 4096)).await?;
        let publisher = BackupPublisher::new(observed, identity, signer)
            .with_control_resources(&resources, 0)?;
        assert!(publisher.list(None, 1).await?.snapshots().is_empty());
        install(repository, signer, generation(identity_frame, 4097)).await?;
        let publisher = BackupPublisher::new(observed, identity, signer)
            .with_control_resources(&resources, 0)?;
        assert!(matches!(
            publisher.list(None, 1).await,
            Err(RepositoryFailure::LimitExceeded)
        ));
        install(repository, signer, vec![0; 8 * 1024 * 1024 + 1]).await?;
        let publisher = BackupPublisher::new(observed, identity, signer)
            .with_control_resources(&resources, 0)?;
        let before = observed.reads.load(Ordering::Relaxed);
        // Registry frames have a stricter encoded extent bound than generic
        // manifest controls. Oversized Registry metadata is refused before I/O.
        assert_eq!(
            publisher.list(None, 1).await,
            Err(RepositoryFailure::LimitExceeded)
        );
        assert_eq!(observed.reads.load(Ordering::Relaxed), before);
        install(repository, signer, generation(identity_frame, 0)).await?;
        Ok(())
    })
    .await?;
    resources::admitted(8 * 1024 * 1024 + 8192, |resources| async move {
        assert!(matches!(BackupPublisher::new(observed, identity, signer).with_control_resources(&resources, 16384), Err(RepositoryFailure::ControlMemoryRequired { memory_bytes }) if memory_bytes == 8 * 1024 * 1024 + 16384));
        assert!(BackupPublisher::new(observed, identity, signer).with_control_resources(&resources, 0)?.list(None, 1).await?.snapshots().is_empty());
        let target = AzureBlobTarget::new("positronbackup", "backups", "owned/")?;
        let native = RepositoryIdentity::azure_blob([1;16], instance.to_bytes(), signer.identity().fingerprint(), &target)?;
        assert!(matches!(BackupPublisher::new(observed, &native, signer).with_control_resources(&resources, 0), Err(RepositoryFailure::ControlMemoryRequired { memory_bytes }) if memory_bytes > AzureBlobRepository::required_resources().get(positron_kernel::ResourceDimension::MemoryBytes)));
        Ok(())
    }).await?;
    Ok(())
}
