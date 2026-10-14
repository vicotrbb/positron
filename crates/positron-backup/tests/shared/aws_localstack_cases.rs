//! LocalStack 4.8 exercises supported native calls; conditional-delete gaps fail closed.
use super::{TestResult, repository};
use positron_backup::*;
use positron_kernel::NativeAwsResources;
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub async fn conformance(
    target: &AwsS3Target,
    foreign_target: &AwsS3Target,
    identity: &RepositoryIdentity,
    resources: &Arc<NativeAwsResources>,
    other_resources: &Arc<NativeAwsResources>,
    address: SocketAddr,
) -> TestResult {
    eprintln!("owned LocalStack fixture prefix: {}", target.prefix());
    let foreign_identity =
        RepositoryIdentity::aws_s3([224; 16], [225; 16], [226; 32], foreign_target)?;
    let foreign = repository(foreign_target, &foreign_identity, resources, Some(address)).await?;
    let history = foreign.qualification_hidden_history_snapshot().await?;
    assert_eq!(
        foreign.initialize().await,
        Err(RepositoryFailure::ForeignPrefix)
    );
    assert_eq!(foreign.attach().await, Err(RepositoryFailure::NotFound));
    assert_eq!(
        foreign.qualification_hidden_history_snapshot().await?,
        history
    );
    drop(foreign);

    let native = repository(target, identity, resources, Some(address)).await?;
    native.initialize().await?;
    let object = ImmutableObject::new(b"LocalStack immutable encrypted frame".to_vec())?;
    assert_eq!(
        native.put_if_absent(object.clone()).await?,
        PutOutcome::Created
    );
    assert_eq!(
        native.put_if_absent(object.clone()).await?,
        PutOutcome::AlreadyPresent
    );
    assert_eq!(
        native.head(object.id()).await?.checksum(),
        object.id().checksum()
    );
    assert_eq!(
        native
            .read_range(ObjectRange::new(object.id(), 1, 4)?)
            .await?
            .bytes(),
        &object.bytes()[1..5]
    );
    assert_eq!(
        native
            .read_range(ObjectRange::new(
                object.id(),
                object.bytes().len() as u64,
                1
            )?)
            .await,
        Err(RepositoryFailure::InvalidInput)
    );
    let page = native
        .list(ListRequest::new(ListKind::Objects, None, 1)?)
        .await?;
    assert_eq!(page.entries(), &[ListEntry::Object(object.id())]);
    assert_eq!(
        native.storage_policy().await?.versioning,
        PolicyObservation::Observed(VersioningPolicy::Enabled)
    );

    let rival = repository(target, identity, other_resources, Some(address)).await?;
    let slot = HeadSlot::from_checksum([202; 32]);
    let (first, second) = tokio::join!(
        native.compare_and_swap_head_at(slot, RegistryHeadChange::new(None, b"first".to_vec())?),
        rival.compare_and_swap_head_at(slot, RegistryHeadChange::new(None, b"second".to_vec())?),
    );
    let winner = match (first?, second?) {
        (CasOutcome::Published(version), CasOutcome::Conflict(_))
        | (CasOutcome::Conflict(_), CasOutcome::Published(version)) => version,
        _ => return Err("conditional race must have exactly one winner".into()),
    };
    // The pinned emulator returns 501 for general-bucket If-Match deletion.
    // The adapter must retain the head and expose the uncertain mutation.
    assert_eq!(
        native.delete_head_if_version(slot, winner).await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert_eq!(
        rival
            .registry_head_at(slot)
            .await?
            .map(|head| head.version()),
        Some(winner)
    );
    assert_eq!(
        native.delete(object.id()).await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert_eq!(
        rival.head(object.id()).await?.checksum(),
        object.id().checksum()
    );
    drop(rival);
    drop(native);

    // A real 4 MiB accepted prefix survives cold attachment. Native multipart
    // completion and final publication succeed; unsupported cleanup stays unknown.
    let object = ImmutableObject::new(vec![203; 6 * 1024 * 1024])?;
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64)?;
    let native = repository(target, identity, resources, Some(address)).await?;
    let state = native.begin_upload(plan).await?;
    let UploadOutcome::Pending(prefix) = native
        .resume_upload(UploadPart::new(
            state,
            object.bytes()[..4 * 1024 * 1024].to_vec(),
        )?)
        .await?
    else {
        return Err("bounded first part must remain resumable".into());
    };
    assert_eq!(prefix.uploaded_bytes(), 4 * 1024 * 1024);
    drop(native);
    let cold = repository(target, identity, resources, Some(address)).await?;
    assert_eq!(cold.attach().await?, *identity);
    let resumed = cold.begin_upload(plan).await?;
    assert_eq!(resumed, prefix);
    assert_eq!(
        cold.resume_upload(UploadPart::new(
            resumed,
            object.bytes()[4 * 1024 * 1024..].to_vec()
        )?)
        .await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert_eq!(
        cold.head(object.id()).await?.checksum(),
        object.id().checksum()
    );
    assert_eq!(
        cold.read_range(ObjectRange::new(object.id(), 5 * 1024 * 1024, 4)?)
            .await?
            .bytes(),
        &[203; 4],
    );
    assert!(cold.inspect_upload(plan.id()).await?.is_some());
    assert_eq!(
        cold.begin_upload(plan).await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert!(cold.inspect_upload(plan.id()).await?.is_some());
    // Doctor cannot report verified while its required cleanup is unsupported.
    assert_eq!(
        doctor(
            &cold,
            DoctorPlan::new(
                [231; 32],
                identity.clone(),
                Duration::from_secs(30),
                Arc::new(AtomicBool::new(false))
            )?
        )
        .await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    drop(cold);
    let foreign = repository(foreign_target, &foreign_identity, resources, Some(address)).await?;
    assert_eq!(
        foreign.qualification_hidden_history_snapshot().await?,
        history
    );
    Ok(())
}
