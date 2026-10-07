use super::*;

#[test]
fn corrupted_schema_checkpoint_blocks_serving() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _) = fixture.initialized()?;
    publish_unrelated_bytes(&initialized, b"PSCHEMA1-corrupt".to_vec())?;
    assert!(matches!(
        ServiceHandle::new(Arc::clone(&initialized)),
        Err(ServiceFailure::CorruptState)
    ));
    Ok(())
}

#[test]
fn duplicate_tenant_checkpoints_block_serving() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let older = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?
        .into_catalog_bytes();
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("new-schema").encode_to_vec())?
            .accepted_records(),
        1
    );
    let newer = services
        .schema_sessions
        .session(initialized.tenant, initialized.resource_governor())?
        .checkpoint()?
        .into_catalog_bytes();
    assert_ne!(older, newer);
    publish_unrelated_bytes(&initialized, older)?;
    publish_unrelated_bytes_with_transaction(&initialized, newer, [0x76; 16])?;
    drop(services);

    assert!(matches!(
        ServiceHandle::new(Arc::clone(&initialized)),
        Err(ServiceFailure::CorruptState)
    ));
    Ok(())
}
