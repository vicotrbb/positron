use positron_backup::*;
pub async fn conformance(
    reader: &dyn Repository,
    writer: &dyn Repository,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(reader.identify().await?, writer.identify().await?);
    let object = ImmutableObject::new(b"read-only restore ciphertext".to_vec())?;
    writer.put_if_absent(object.clone()).await?;
    assert_eq!(
        reader.head(object.id()).await?.size(),
        object.bytes().len() as u64
    );
    assert_eq!(
        reader
            .read_range(ObjectRange::new(
                object.id(),
                0,
                object.bytes().len() as u64
            )?)
            .await?
            .bytes(),
        object.bytes()
    );
    assert_eq!(
        reader.registry_head_at(HeadSlot::registry()).await?,
        writer.registry_head_at(HeadSlot::registry()).await?
    );
    let pending = ImmutableObject::new(b"pending read-only upload".to_vec())?;
    let plan = UploadPlan::new(pending.id(), pending.bytes().len() as u64)?;
    let state = writer.begin_upload(plan).await?;
    assert_eq!(
        reader.begin_upload(plan).await,
        Err(RepositoryFailure::PermissionDenied)
    );
    assert_eq!(
        reader.inspect_upload(state.id()).await,
        Err(RepositoryFailure::PermissionDenied)
    );
    assert_eq!(
        reader
            .resume_upload(UploadPart::new(state, pending.bytes().to_vec())?)
            .await,
        Err(RepositoryFailure::PermissionDenied)
    );
    assert_eq!(
        reader.abort_upload(state.id()).await,
        Err(RepositoryFailure::PermissionDenied)
    );
    assert_eq!(
        reader.put_if_absent(object.clone()).await,
        Err(RepositoryFailure::PermissionDenied)
    );
    assert_eq!(
        reader.delete(object.id()).await,
        Err(RepositoryFailure::PermissionDenied)
    );
    assert_eq!(
        reader
            .compare_and_swap_head_at(
                HeadSlot::registry(),
                RegistryHeadChange::new(None, vec![1])?
            )
            .await,
        Err(RepositoryFailure::PermissionDenied)
    );
    let version = match writer
        .compare_and_swap_head_at(
            HeadSlot::registry(),
            RegistryHeadChange::new(None, vec![1])?,
        )
        .await?
    {
        CasOutcome::Published(version) => version,
        _ => return Err("fixture head publication".into()),
    };
    assert_eq!(
        reader
            .delete_head_if_version(HeadSlot::registry(), version)
            .await,
        Err(RepositoryFailure::PermissionDenied)
    );
    writer
        .delete_head_if_version(HeadSlot::registry(), version)
        .await?;
    writer.abort_upload(state.id()).await?;
    writer.delete(object.id()).await?;
    Ok(())
}
