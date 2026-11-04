#![cfg(feature = "test-support")]
use super::support::establish_catalog_authority;
use positron_kernel::*;
use std::sync::mpsc;
use std::time::Duration;

fn proposal(id: u8, bytes: &[u8]) -> Result<CatalogProposal, CatalogFailure> {
    CatalogProposal::new(
        TransactionId::new([id; 16])?,
        FormatEpoch::new(1)?,
        vec![CatalogObject::new(bytes.to_vec())?],
    )
}

#[test]
fn prepared_mutation_excludes_a_competing_publication_until_its_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let root =
        std::env::temp_dir().join(format!("positron-prepared-mutation-{}", std::process::id()));
    std::fs::create_dir(&root)?;
    let volume = PrimaryDataVolume::acquire(&root, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let expected = catalog.pin()?.identity();
    let (entered, start) = mpsc::channel();
    let (attempted, attempt) = mpsc::channel();
    let (finished, finish) = mpsc::channel();
    std::thread::scope(|scope| {
        let catalog_ref = &catalog;
        let competitor = scope.spawn(move || {
            start.recv().expect("preparation entered");
            attempted.send(()).expect("notify attempt");
            let result = catalog_ref.commit(
                expected,
                proposal(0xb4, b"competing").expect("proposal"),
                None,
            );
            finished.send(result).expect("report outcome");
        });
        let mut early = None;
        let prepared = catalog.prepare_and_commit_for_test::<_, CatalogFailure>(|_| {
            entered.send(()).expect("start competitor");
            attempt.recv().expect("competitor attempted");
            early = finish.recv_timeout(Duration::from_millis(100)).ok();
            Ok(((), Some(proposal(0xb5, b"prepared")?)))
        });
        competitor.join().expect("competitor completes");
        if let Some(result) = &early {
            assert_eq!(
                result
                    .as_ref()
                    .expect_err("no competing commit during preparation")
                    .code(),
                CatalogFailureCode::ResourceAdmissionRefused
            );
        }
        let competing = early.unwrap_or_else(|| finish.recv().expect("competitor outcome"));
        match prepared {
            Ok(((), Some(_))) => assert!(competing.is_err()),
            Err(failure) => {
                assert_eq!(failure.code(), CatalogFailureCode::ResourceAdmissionRefused);
                competing.expect("competitor commits after prepared scope releases its guards");
            },
            Ok(((), None)) => panic!("prepared mutation must publish"),
        }
    });
    let snapshot = catalog.pin()?;
    let prepared_object = CatalogObject::new(b"prepared".to_vec())?;
    let competing_object = CatalogObject::new(b"competing".to_vec())?;
    // Retry the capacity-refused or stale participant against the completed scope.
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xb6; 16])?,
            FormatEpoch::new(1)?,
            vec![
                CatalogObject::new(b"prepared".to_vec())?,
                CatalogObject::new(b"competing".to_vec())?,
            ],
        )?,
        None,
    )?;
    drop(catalog);
    let reopened = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let snapshot = reopened.pin()?;
    assert!(snapshot.object(prepared_object.identity())?.is_some());
    assert!(snapshot.object(competing_object.identity())?.is_some());
    assert_eq!(snapshot.number(), 2);
    drop(reopened);
    drop(authority);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn with_catalog(
    action: impl FnOnce(&Catalog<'_>, &std::path::Path) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "positron-prepared-contract-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&root)?;
    let volume = PrimaryDataVolume::acquire(&root, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xc1; 16])?,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let result = action(&catalog, &root);
    drop(catalog);
    drop(authority);
    std::fs::remove_dir_all(root)?;
    result
}

#[test]
fn prepared_noop_and_exact_transaction_retry_do_not_advance_generation()
-> Result<(), Box<dyn std::error::Error>> {
    with_catalog(|catalog, _| {
        let origin = catalog.pin()?.identity();
        let (value, no_commit) =
            catalog.prepare_and_commit_for_test::<_, CatalogFailure>(|_| Ok((7, None)))?;
        assert_eq!(value, 7);
        assert!(no_commit.is_none());
        assert_eq!(catalog.pin()?.identity(), origin);
        catalog.prepare_and_commit_for_test::<_, CatalogFailure>(|_| {
            Ok(((), Some(proposal(0xc4, b"exact")?)))
        })?;
        let published = catalog.pin()?.identity();
        catalog.prepare_and_commit_for_test::<_, CatalogFailure>(|_| {
            Ok(((), Some(proposal(0xc4, b"exact")?)))
        })?;
        assert_eq!(catalog.pin()?.identity(), published);
        Ok(())
    })
}

#[test]
fn prepared_mutation_authenticates_current_objects_before_preparation()
-> Result<(), Box<dyn std::error::Error>> {
    with_catalog(|catalog, root| {
        catalog.commit(
            catalog.pin()?.identity(),
            proposal(0xc5, b"authenticated")?,
            None,
        )?;
        let object = std::fs::read_dir(root.join("catalog/objects"))?
            .next()
            .ok_or("object")??
            .path();
        let original = std::fs::read(&object)?;
        let mut changed = original.clone();
        let last = changed.last_mut().ok_or("protected object is nonempty")?;
        *last ^= 1;
        std::fs::write(&object, changed)?;
        let mut prepared = false;
        let refused = catalog
            .prepare_and_commit_for_test::<_, CatalogFailure>(|_| {
                prepared = true;
                Ok(((), Some(proposal(0xc6, b"must-not-publish")?)))
            })
            .expect_err("tampering fails closed");
        assert!(!prepared);
        assert!(matches!(
            refused.code(),
            CatalogFailureCode::AuthenticationFailed | CatalogFailureCode::IntegrityCorruption
        ));
        std::fs::write(object, original)?;
        assert!(
            catalog
                .committed_transaction(TransactionId::new([0xc6; 16])?)?
                .is_none()
        );
        Ok(())
    })
}

#[test]
fn prepared_marker_failures_reconcile_exact_transaction_and_allow_hook_reentry()
-> Result<(), Box<dyn std::error::Error>> {
    for (fault, visible) in [
        (CatalogPublicationFault::RenameMarker, false),
        (
            CatalogPublicationFault::SynchronizeGenerationDirectory,
            true,
        ),
    ] {
        with_catalog(|catalog, _| {
            let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let hook_observed = observed.clone();
            let result = with_catalog_publication_ambiguity_hook_after(
                fault,
                0,
                move |catalog| {
                    // These calls acquire Catalog guards and must run after preparation releases them.
                    catalog
                        .refresh_after_ambiguous_publication_for_test()
                        .expect("refresh after ambiguity");
                    let _ = catalog.pin().expect("pin after ambiguity");
                    hook_observed.store(true, std::sync::atomic::Ordering::Relaxed);
                },
                || {
                    catalog.prepare_and_commit_for_test::<_, CatalogFailure>(|_| {
                        Ok(((), Some(proposal(0xc7, b"ambiguous")?)))
                    })
                },
            );
            assert_eq!(
                result.expect_err("injected publication failure").code(),
                CatalogFailureCode::StorageUnavailable
            );
            assert!(observed.load(std::sync::atomic::Ordering::Relaxed));
            let transaction = TransactionId::new([0xc7; 16])?;
            assert_eq!(
                catalog.committed_transaction(transaction)?.is_some(),
                visible
            );
            catalog.prepare_and_commit_for_test::<_, CatalogFailure>(|_| {
                Ok(((), Some(proposal(0xc7, b"ambiguous")?)))
            })?;
            assert!(
                catalog
                    .confirm_committed_transaction(transaction)?
                    .is_some()
            );
            assert_eq!(catalog.pin()?.number(), 1);
            Ok(())
        })?;
    }
    Ok(())
}
