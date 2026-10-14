//! Bounded real filesystem sequences; no named-provider substitute.
use crate::*;
use std::{fs, os::unix::fs::PermissionsExt};

pub fn fuzz_repository_stateful(data: &[u8]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("fuzz runtime");
    runtime.block_on(async {
        let directory = tempfile::tempdir().expect("native fuzz directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("protected prefix");
        let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], directory.path())
            .expect("identity");
        let mut repository = LocalRepository::initialize(directory.path(), identity.clone())
            .await
            .expect("native initialization");
        let payload = ImmutableObject::new(data.iter().copied().take(64).chain([1; 16]).collect())
            .expect("bounded payload");
        let mut present = false;
        let mut upload = None;
        for action in data.iter().copied().take(12) {
            match action % 11 {
                0 => {
                    let outcome = repository
                        .put_if_absent(payload.clone())
                        .await
                        .expect("immutable put");
                    assert_eq!(
                        outcome,
                        if present {
                            PutOutcome::AlreadyPresent
                        } else {
                            PutOutcome::Created
                        }
                    );
                    present = true;
                },
                1 => {
                    assert_eq!(
                        repository.delete(payload.id()).await.expect("delete"),
                        if present {
                            DeleteOutcome::Deleted
                        } else {
                            DeleteOutcome::AlreadyAbsent
                        }
                    );
                    present = false;
                },
                2 => {
                    assert_eq!(repository.head(payload.id()).await.is_ok(), present);
                },
                3 => {
                    let range = ObjectRange::new(payload.id(), 0, 4).expect("bounded range");
                    if present {
                        assert_eq!(
                            repository.read_range(range).await.expect("range").bytes(),
                            payload.bytes().get(..4).expect("payload prefix")
                        );
                    } else {
                        assert_eq!(
                            repository.read_range(range).await,
                            Err(RepositoryFailure::NotFound)
                        );
                    }
                },
                4 => {
                    let plan = UploadPlan::new(payload.id(), payload.bytes().len() as u64)
                        .expect("upload plan");
                    let state = repository
                        .begin_upload(plan)
                        .await
                        .expect("begin or resume");
                    upload = Some(plan.id());
                    if !state.complete() {
                        let start =
                            usize::try_from(state.uploaded_bytes()).expect("bounded offset");
                        let bytes = payload
                            .bytes()
                            .get(start..)
                            .expect("remaining payload")
                            .to_vec();
                        repository
                            .resume_upload(UploadPart::new(state, bytes).expect("upload part"))
                            .await
                            .expect("complete upload");
                    }
                    present = true;
                },
                5 => {
                    let slot = HeadSlot::registry();
                    let prior = repository.registry_head_at(slot).await.expect("head");
                    let change = RegistryHeadChange::new(
                        prior.as_ref().map(RegistryHead::version),
                        vec![action; 8],
                    )
                    .expect("CAS change");
                    assert!(matches!(
                        repository
                            .compare_and_swap_head_at(slot, change)
                            .await
                            .expect("CAS"),
                        CasOutcome::Published(_)
                    ));
                },
                6 => {
                    drop(repository);
                    repository = LocalRepository::attach(directory.path(), &identity)
                        .await
                        .expect("cold reopen");
                },
                7 => {
                    if let Some(id) = upload.take() {
                        repository.abort_upload(id).await.expect("idempotent abort");
                    }
                    let cursor = ListCursor::from_bytes(data.iter().copied().take(128).collect());
                    if let Ok(cursor) = cursor {
                        assert!(
                            repository
                                .list(
                                    ListRequest::new(ListKind::Objects, Some(cursor), 1)
                                        .expect("bounded request")
                                )
                                .await
                                .is_err()
                        );
                    }
                },
                8 => {
                    if !present {
                        let plan = UploadPlan::new(payload.id(), payload.bytes().len() as u64)
                            .expect("plan");
                        repository = repository
                            .with_faults(vec![LocalFault::new(
                                LocalFaultPoint::BeforeUploadPublication,
                                LocalFaultEffect::Interrupted,
                                0,
                            )])
                            .expect("fault");
                        assert_eq!(
                            repository.begin_upload(plan).await,
                            Err(RepositoryFailure::Interrupted)
                        );
                        drop(repository);
                        repository = LocalRepository::attach(directory.path(), &identity)
                            .await
                            .expect("reopen staging");
                        repository
                            .abort_upload(plan.id())
                            .await
                            .expect("abort staging");
                        assert_eq!(
                            repository.inspect_upload(plan.id()).await.expect("upload"),
                            None
                        );
                        assert!(
                            !std::fs::read_dir(directory.path())
                                .expect("directory")
                                .any(|entry| entry
                                    .expect("entry")
                                    .file_name()
                                    .to_string_lossy()
                                    .starts_with("p-u-"))
                        );
                    }
                },
                9 => {
                    if !present {
                        let plan = UploadPlan::new(payload.id(), payload.bytes().len() as u64)
                            .expect("plan");
                        let state = repository.begin_upload(plan).await.expect("begin");
                        if action & 16 == 0 {
                            repository
                                .put_if_absent(payload.clone())
                                .await
                                .expect("same content publication");
                        } else {
                            repository = repository
                                .with_faults(vec![LocalFault::new(
                                    LocalFaultPoint::AfterObjectPublication,
                                    LocalFaultEffect::OutcomeUnknown,
                                    0,
                                )])
                                .expect("fault");
                            assert_eq!(
                                repository
                                    .resume_upload(
                                        UploadPart::new(state, payload.bytes().to_vec())
                                            .expect("part")
                                    )
                                    .await,
                                Err(RepositoryFailure::OutcomeUnknown)
                            );
                        }
                        drop(repository);
                        repository = LocalRepository::attach(directory.path(), &identity)
                            .await
                            .expect("reopen completed object");
                        assert!(
                            repository
                                .begin_upload(plan)
                                .await
                                .expect("reconcile completed upload")
                                .complete()
                        );
                        assert_eq!(
                            repository.inspect_upload(plan.id()).await.expect("upload"),
                            None
                        );
                        present = true;
                    }
                },
                _ => {
                    // Mutation acknowledgements may be uncertain. Reconcile through
                    // authoritative HEAD before updating the independent model.
                    repository = repository
                        .with_faults(vec![LocalFault::new(
                            LocalFaultPoint::AfterObjectPublication,
                            LocalFaultEffect::OutcomeUnknown,
                            0,
                        )])
                        .expect("bounded fault");
                    let result = repository.put_if_absent(payload.clone()).await;
                    assert!(matches!(
                        result,
                        Ok(PutOutcome::AlreadyPresent) | Err(RepositoryFailure::OutcomeUnknown)
                    ));
                    present = true;
                    drop(repository);
                    repository = LocalRepository::attach(directory.path(), &identity)
                        .await
                        .expect("uncertain publication reopen");
                },
            }
            match repository.head(payload.id()).await {
                Ok(metadata) => {
                    assert!(present);
                    assert_eq!(metadata.checksum(), payload.id().checksum());
                },
                Err(RepositoryFailure::NotFound) => assert!(!present),
                other => panic!("unexpected committed-route observation: {other:?}"),
            }
            assert_eq!(
                repository.identify().await.expect("immutable identity"),
                identity
            );
        }
        // Exercise persistent native parsers using bounded hostile bytes.
        let hostile = data.iter().copied().take(512).collect::<Vec<_>>();
        if let Some(selector) = data.first() {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let name = match selector % 3 {
                0 => String::from("identity"),
                1 => HeadSlot::registry().name(),
                _ => UploadPlan::new(payload.id(), payload.bytes().len() as u64)
                    .expect("bounded plan")
                    .id()
                    .name(),
            };
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(directory.path().join(name))
                .expect("native hostile fixture");
            file.write_all(&hostile).expect("bounded bytes");
            drop(file);
            match selector % 3 {
                0 => {
                    let _result = repository.identify().await;
                },
                1 => {
                    let _result = repository.registry_head_at(HeadSlot::registry()).await;
                },
                _ => {
                    let _result = repository
                        .inspect_upload(
                            UploadPlan::new(payload.id(), payload.bytes().len() as u64)
                                .expect("bounded plan")
                                .id(),
                        )
                        .await;
                },
            }
        }
        let bounded = data.get(..data.len().min(512)).expect("bounded input");
        if let Ok(decoded) = RepositoryIdentity::decode(bounded) {
            assert_eq!(
                RepositoryIdentity::decode(&decoded.encode()).expect("canonical identity"),
                decoded
            );
        }
    });
}
