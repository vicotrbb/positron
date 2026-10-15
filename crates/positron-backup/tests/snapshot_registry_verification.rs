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
    bytes: AtomicUsize,
    lose_cas: AtomicBool,
    fail_readback: AtomicBool,
    append_after_hint: Option<std::path::PathBuf>,
    append_once: AtomicBool,
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
        let size = self.inner.object_size_hint(object).await?;
        if self.append_once.swap(false, Ordering::Relaxed) {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(
                    self.append_after_hint
                        .as_ref()
                        .ok_or(RepositoryFailure::CorruptState)?,
                )
                .map_err(|_| RepositoryFailure::StorageUnavailable)?
                .write_all(&[0])
                .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        }
        Ok(size)
    }
    async fn head(&self, object: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        self.inner.head(object).await
    }
    async fn read_range(&self, range: ObjectRange) -> Result<ChecksummedBytes, RepositoryFailure> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let part = self.inner.read_range(range).await?;
        self.bytes.fetch_add(part.bytes().len(), Ordering::Relaxed);
        Ok(part)
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
        if self.fail_readback.swap(false, Ordering::Relaxed) {
            return Err(RepositoryFailure::StorageUnavailable);
        }
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
        let outcome = self.inner.compare_and_swap_head_at(slot, change).await?;
        if self.lose_cas.swap(false, Ordering::Relaxed) {
            self.fail_readback.store(true, Ordering::Relaxed);
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        Ok(outcome)
    }
}
fn signed(
    mut bytes: Vec<u8>,
    signer: &BackupControlSigner,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    bytes.extend_from_slice(&signer.sign(&Sha256::digest(&bytes))?.bytes());
    Ok(bytes)
}
fn generation(identity: &[u8], number: u64, previous: [u8; 32]) -> Vec<u8> {
    let mut bytes = b"POSBKG04".to_vec();
    bytes.extend_from_slice(&number.to_be_bytes());
    bytes.extend_from_slice(&previous);
    bytes.extend_from_slice(identity);
    for _ in 0..4 {
        bytes.extend_from_slice(&0u32.to_be_bytes());
    }
    bytes
}
async fn install(
    repository: &LocalRepository,
    signer: &BackupControlSigner,
    payload: Vec<u8>,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let object = ImmutableObject::new(signed(payload, signer)?)?;
    let id = object.id();
    repository.put_if_absent(object).await?;
    let mut head = b"POSBKH01".to_vec();
    head.extend_from_slice(&id.checksum());
    let expected = repository
        .registry_head_at(HeadSlot::registry())
        .await?
        .map(|h| h.version());
    assert!(matches!(
        repository
            .compare_and_swap_head_at(
                HeadSlot::registry(),
                RegistryHeadChange::new(expected, signed(head, signer)?)?
            )
            .await?,
        CasOutcome::Published(_)
    ));
    Ok(id.checksum())
}
#[tokio::test]
async fn registry_ancestry_is_bounded_authenticated_and_resumes_after_external_advance()
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
        let identity_bytes = std::fs::read(path.join("identity"))?;
        let first = install(
            &repository,
            &signer,
            generation(&identity_bytes, 1, [0; 32]),
        )
        .await?;
        let mut previous = first;
        for number in 2..=48 {
            previous = install(
                &repository,
                &signer,
                generation(&identity_bytes, number, previous),
            )
            .await?;
        }
        let observed = Observed {
            inner: &repository,
            reads: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            lose_cas: AtomicBool::new(false),
            fail_readback: AtomicBool::new(false),
            append_after_hint: None,
            append_once: AtomicBool::new(false),
        };
        let publisher = BackupPublisher::new(&observed, &identity, &signer)
            .with_control_resources(&resources, 0)?
            .with_trusted_generation(first)?;
        assert!(matches!(
            publisher.list(None, 1).await,
            Err(RepositoryFailure::LimitExceeded)
        ));
        let owner = [11; 16];
        let request = [12; 32];
        let mut state = publisher
            .begin_registry_verification(owner, request)
            .await?;
        let mut turns = 0;
        while !state.complete()? {
            let reads = observed.reads.load(Ordering::Relaxed);
            let bytes = observed.bytes.load(Ordering::Relaxed);
            publisher.registry_verification_step(&mut state).await?;
            assert!(observed.reads.load(Ordering::Relaxed) - reads <= 1);
            assert!(observed.bytes.load(Ordering::Relaxed) - bytes <= 2_852_076);
            let checkpoint = publisher.registry_verification_checkpoint(&state)?;
            assert!(checkpoint.len() <= 1024);
            let mut corrupt = checkpoint.clone();
            *corrupt.last_mut().ok_or("signature")? ^= 1;
            assert!(
                publisher
                    .resume_registry_verification(&corrupt, owner, request)
                    .is_err()
            );
            assert!(
                publisher
                    .resume_registry_verification(&checkpoint, [13; 16], request)
                    .is_err()
            );
            assert!(
                publisher
                    .resume_registry_verification(&checkpoint, owner, [14; 32])
                    .is_err()
            );
            let other = BackupPublisher::new(&observed, &identity, &signer)
                .with_control_resources(&resources, 0)?
                .with_trusted_generation([15; 32])?;
            assert!(matches!(
                other.resume_registry_verification(&checkpoint, owner, request),
                Err(RepositoryFailure::PreconditionFailed)
            ));
            state = publisher.resume_registry_verification(&checkpoint, owner, request)?;
            turns += 1;
            assert!(turns <= 52);
        }
        assert!(turns >= 47);
        assert!(
            BackupPublisher::new(&observed, &identity, &signer)
                .with_control_resources(&resources, 0)?
                .with_trusted_generation(first)?
                .with_registry_verification(&state)?
                .list(None, 1)
                .await?
                .snapshots()
                .is_empty()
        );
        previous = install(
            &repository,
            &signer,
            generation(&identity_bytes, 49, previous),
        )
        .await?;
        assert!(matches!(
            BackupPublisher::new(&observed, &identity, &signer)
                .with_control_resources(&resources, 0)?
                .with_trusted_generation(first)?
                .with_registry_verification(&state)?
                .list(None, 1)
                .await,
            Err(RepositoryFailure::PreconditionFailed)
        ));
        let mut turns = 0;
        while !publisher.registry_verification_step(&mut state).await? {
            turns += 1;
            assert!(turns <= 3);
        }
        let checkpoint = publisher.registry_verification_checkpoint(&state)?;
        state = publisher.resume_registry_verification(&checkpoint, owner, request)?;
        assert!(state.complete()?);
        assert!(
            BackupPublisher::new(&observed, &identity, &signer)
                .with_control_resources(&resources, 0)?
                .with_trusted_generation(first)?
                .with_registry_verification(&state)?
                .list(None, 1)
                .await?
                .snapshots()
                .is_empty()
        );
        // A signed skip in generation numbering is still invalid ancestry.
        install(
            &repository,
            &signer,
            generation(&identity_bytes, 51, previous),
        )
        .await?;
        let mut bad = publisher
            .begin_registry_verification(owner, request)
            .await?;
        let mut rejected = false;
        for _ in 0..3 {
            if publisher
                .registry_verification_step(&mut bad)
                .await
                .is_err()
            {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        // Oversized hostile generations are refused before a body range read.
        install(&repository, &signer, vec![0; 3 * 1024 * 1024]).await?;
        let mut oversized = publisher
            .begin_registry_verification(owner, request)
            .await?;
        let before = observed.reads.load(Ordering::Relaxed);
        assert!(matches!(
            publisher.registry_verification_step(&mut oversized).await,
            Err(RepositoryFailure::LimitExceeded)
        ));
        assert_eq!(observed.reads.load(Ordering::Relaxed), before);
        // A valid signed generation prefix must not qualify an appended native
        // object when the metadata hint went stale before the ranged read.
        let append_path = directory.path().join("append");
        std::fs::create_dir(&append_path)?;
        std::fs::set_permissions(&append_path, std::fs::Permissions::from_mode(0o700))?;
        let append_identity = RepositoryIdentity::local(
            [29; 16],
            instance.to_bytes(),
            signer.identity().fingerprint(),
            &append_path,
        )?;
        let append_repository =
            LocalRepository::initialize(&append_path, append_identity.clone()).await?;
        let frame = std::fs::read(append_path.join("identity"))?;
        let id = install(&append_repository, &signer, generation(&frame, 1, [0; 32])).await?;
        let name = format!(
            "o-{}",
            id.into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let object_path = append_path.join(name);
        let authentic = std::fs::read(&object_path)?;
        let observed_append = Observed {
            inner: &append_repository,
            reads: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            lose_cas: AtomicBool::new(false),
            fail_readback: AtomicBool::new(false),
            append_after_hint: Some(object_path.clone()),
            append_once: AtomicBool::new(false),
        };
        let append_publisher = BackupPublisher::new(&observed_append, &append_identity, &signer)
            .with_control_resources(&resources, 0)?;
        let mut appended = append_publisher
            .begin_registry_verification(owner, request)
            .await?;
        observed_append.append_once.store(true, Ordering::Relaxed);
        assert!(matches!(
            append_publisher
                .registry_verification_step(&mut appended)
                .await,
            Err(RepositoryFailure::PreconditionFailed)
        ));
        std::fs::write(&object_path, authentic)?;
        while !append_publisher
            .registry_verification_step(&mut appended)
            .await?
        {}
        for uncertain in [false, true] {
            let claim_path = directory
                .path()
                .join(if uncertain { "uncertain" } else { "known" });
            std::fs::create_dir(&claim_path)?;
            std::fs::set_permissions(&claim_path, std::fs::Permissions::from_mode(0o700))?;
            let claim_identity = RepositoryIdentity::local(
                [21; 16],
                instance.to_bytes(),
                signer.identity().fingerprint(),
                &claim_path,
            )?;
            let claim_repository =
                LocalRepository::initialize(&claim_path, claim_identity.clone()).await?;
            let frame = std::fs::read(claim_path.join("identity"))?;
            let object = ImmutableObject::new(vec![42; 32])?;
            let object_id = object.id();
            claim_repository.put_if_absent(object).await?;
            let mut payload = generation(&frame, 1, [0; 32]);
            let end = payload.len();
            payload
                .get_mut(end - 4..)
                .ok_or("claim count")?
                .copy_from_slice(&1u32.to_be_bytes());
            payload.extend_from_slice(&owner);
            payload.push(1);
            payload.extend_from_slice(&[19; 16]);
            payload.extend_from_slice(&[20; 32]);
            payload.extend_from_slice(&1u64.to_be_bytes());
            payload.extend_from_slice(&2u64.to_be_bytes());
            for value in [0u32, 0, 0, 1] {
                payload.extend_from_slice(&value.to_be_bytes());
            }
            payload.extend_from_slice(&object_id.checksum());
            install(&claim_repository, &signer, payload).await?;
            let observed = Observed {
                inner: &claim_repository,
                reads: AtomicUsize::new(0),
                bytes: AtomicUsize::new(0),
                lose_cas: AtomicBool::new(false),
                fail_readback: AtomicBool::new(false),
                append_after_hint: None,
                append_once: AtomicBool::new(false),
            };
            let base = BackupPublisher::new(&observed, &claim_identity, &signer)
                .with_control_resources(&resources, 0)?;
            let mut state = base.begin_registry_verification(owner, request).await?;
            while !base.registry_verification_step(&mut state).await? {}
            let before = base.registry_verification_checkpoint(&state)?;
            let reads = observed.reads.load(Ordering::Relaxed);
            {
                let publisher = BackupPublisher::new(&observed, &claim_identity, &signer)
                    .with_control_resources(&resources, 0)?
                    .with_registry_verification(&state)?;
                observed.lose_cas.store(uncertain, Ordering::Relaxed);
                let result = publisher.delete_expired_step(owner, [20; 32]).await;
                if uncertain {
                    assert!(matches!(result, Err(RepositoryFailure::StorageUnavailable)));
                } else {
                    let progress = result?;
                    assert!(progress.complete());
                    assert_eq!(progress.deleted_objects(), 1);
                }
            }
            assert!(
                observed.reads.load(Ordering::Relaxed) - reads <= 1,
                "post-CAS progress fetched another full generation"
            );
            let after = base.registry_verification_checkpoint(&state)?;
            if uncertain {
                assert_eq!(after, before, "unreconciled CAS advanced trusted proof");
                // Cold recovery authenticates the actual successor, not the
                // failed local acknowledgement or a fabricated deleted count.
                state = base.resume_registry_verification(&after, owner, request)?;
                let mut turns = 0;
                while !base.registry_verification_step(&mut state).await? {
                    turns += 1;
                    assert!(turns <= 4);
                }
            } else {
                assert_ne!(
                    after, before,
                    "successful CAS did not advance operation proof"
                );
            }
            let checkpoint = base.registry_verification_checkpoint(&state)?;
            let cold = base.resume_registry_verification(&checkpoint, owner, request)?;
            let publisher = BackupPublisher::new(&observed, &claim_identity, &signer)
                .with_control_resources(&resources, 0)?
                .with_registry_verification(&cold)?;
            let progress = publisher.cleanup_for_owner(owner).await?.ok_or("claim")?;
            assert!(progress.complete());
            assert_eq!(progress.deleted_objects(), 1);
            assert_eq!(progress.already_absent_objects(), 0);
            assert_eq!(
                claim_repository.object_size_hint(object_id).await,
                Err(RepositoryFailure::NotFound)
            );
        }
        Ok(())
    })
    .await
}
