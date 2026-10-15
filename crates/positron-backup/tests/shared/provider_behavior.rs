//! The same native-provider cases are imported by every adapter qualification.
use positron_backup::*;
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub async fn conformance(
    repository: &dyn Repository,
    identity: RepositoryIdentity,
    doctor_budget: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = doctor(
        repository,
        DoctorPlan::new(
            [101; 32],
            identity.clone(),
            doctor_budget,
            Arc::new(AtomicBool::new(false)),
        )?,
    )
    .await?;
    assert!(report.verified() && report.probes_deleted());
    object_conformance(repository, identity).await
}

pub async fn object_conformance(
    repository: &dyn Repository,
    identity: RepositoryIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(repository.identify().await?, identity);
    let absent = ImmutableObject::new(b"conformance absent encrypted frame".to_vec())?;
    assert_eq!(
        repository.head(absent.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    assert_eq!(
        repository.delete(absent.id()).await?,
        DeleteOutcome::AlreadyAbsent
    );
    let stored = ImmutableObject::new(b"conformance immutable encrypted frame".to_vec())?;
    assert_eq!(
        repository.put_if_absent(stored.clone()).await?,
        PutOutcome::Created
    );
    assert_eq!(
        repository.put_if_absent(stored.clone()).await?,
        PutOutcome::AlreadyPresent
    );
    assert_eq!(
        repository
            .read_range(ObjectRange::new(stored.id(), 1, 4)?)
            .await?
            .bytes(),
        &stored.bytes()[1..5]
    );
    assert_eq!(
        repository
            .read_range(ObjectRange::new(
                stored.id(),
                stored.bytes().len() as u64,
                1
            )?)
            .await,
        Err(RepositoryFailure::InvalidInput)
    );
    let page = repository
        .list(ListRequest::new(ListKind::Objects, None, 1)?)
        .await?;
    assert!(page.entries().len() <= 1);
    // Listing is advisory: the direct object read is the correctness proof.
    assert_eq!(
        repository.head(stored.id()).await?.checksum(),
        stored.id().checksum()
    );
    assert_eq!(
        repository.delete(stored.id()).await?,
        DeleteOutcome::Deleted
    );
    assert_eq!(
        repository.head(stored.id()).await,
        Err(RepositoryFailure::NotFound)
    );
    Ok(())
}
