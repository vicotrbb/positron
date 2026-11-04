use super::super::*;
use super::support::establish_catalog_authority;
use crate::{MountQualification, PrimaryDataVolume, ResourceDimension};

#[test]
fn prepared_mutation_refuses_an_unavailable_wrapping_route_before_preparation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "positron-prepared-key-refusal-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root)?;
    let authority = establish_catalog_authority(PrimaryDataVolume::acquire(
        &root,
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd5; 16])?,
        CatalogSecret::from_owned(Box::new([0xd6; 32]), Box::new([0xd7; 32])),
    )?;
    let transaction = TransactionId::new([0xd8; 16])?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            transaction,
            FormatEpoch::new(1)?,
            vec![CatalogObject::new(b"protected source".to_vec())?],
        )?,
        None,
    )?;
    let generation = catalog.pin()?.identity();
    let before = authority.governor().inspect()?;
    // Fault the key custody boundary while preserving the authentic marker key.
    let previous = {
        let mut secret = catalog.secret.lock().map_err(|_| "fixture key lock")?;
        std::mem::replace(
            &mut secret.wrapping,
            CatalogWrappingKey::from_owned_at_epoch(Box::new([0xd9; 32]), [0xda; 16], 2)?,
        )
    };
    let mut prepared = false;
    let failure = catalog
        .prepare_and_commit::<_, CatalogFailure>(|_| {
            prepared = true;
            Ok(((), None))
        })
        .expect_err("missing wrapping route must fail before mutation preparation");
    assert_eq!(failure.code(), CatalogFailureCode::AuthenticationFailed);
    assert!(!prepared);
    assert_eq!(catalog.pin()?.identity(), generation);
    let after = authority.governor().inspect()?;
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), before.usage(dimension));
    }
    catalog
        .secret
        .lock()
        .map_err(|_| "fixture key lock")?
        .wrapping = previous;
    assert!(
        catalog
            .confirm_committed_transaction(transaction)?
            .is_some()
    );
    drop(catalog);
    drop(authority);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn prepared_exact_admission_preserves_disk_refusal_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "positron-prepared-disk-refusal-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root)?;
    let authority = establish_catalog_authority(PrimaryDataVolume::acquire(
        &root,
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe5; 16])?,
        CatalogSecret::from_owned(Box::new([0xe6; 32]), Box::new([0xe7; 32])),
    )?;
    let before = authority.governor().inspect()?;
    let generation = catalog.pin()?.identity();
    let failure = catalog
        .prepare_and_commit::<_, CatalogFailure>(|_| {
            authority
                .observe_disk_for_test(crate::DiskObservation::new(0))
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::StorageUnavailable))?;
            Ok((
                (),
                Some(CatalogProposal::new(
                    TransactionId::new([0xe8; 16])?,
                    FormatEpoch::new(1)?,
                    vec![CatalogObject::new(
                        b"publication requires headroom".to_vec(),
                    )?],
                )?),
            ))
        })
        .expect_err("exact publication requires disk after preparation");
    let admission = failure
        .admission_failure()
        .ok_or("original admission evidence")?;
    assert_eq!(
        admission.code(),
        crate::AdmissionFailureCode::CapacityExhausted
    );
    assert_eq!(
        admission.retry(),
        crate::AdmissionRetry::AfterPressureTransition
    );
    assert_eq!(
        admission.limiting_dimension(),
        Some(ResourceDimension::DiskHeadroomBytes)
    );
    assert_eq!(
        authority.governor().inspect()?.lifecycle(),
        crate::GovernorLifecycle::Open
    );
    assert_eq!(catalog.pin()?.identity(), generation);
    authority.observe_disk_for_test(crate::DiskObservation::new(before.usable_disk_bytes()))?;
    drop(catalog);
    drop(authority);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
