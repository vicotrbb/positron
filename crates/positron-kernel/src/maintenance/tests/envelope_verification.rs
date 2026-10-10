use super::*;

#[test]
fn verification_source_excludes_only_its_authenticated_task_and_invalidates_other_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
    )?;
    let instance = InstanceId::new(nonzero_id(1))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x51; 32]), Box::new([0x52; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"actual source authority".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([42; 16]).expect("task identity"),
        MaintenanceTaskClass::EnvelopeVerification,
        MaintenanceScope::tenant(TenantId::from_bytes([0x43; 16])?),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    )
    .expect("bounded task");
    assert!(
        catalog
            .pin()?
            .envelope_verification_source_identity(instance, &task)
            .is_err()
    );
    coordinator
        .submit_and_persist(&catalog, task.clone(), 7)
        .expect("persist task");
    let source = catalog
        .pin()?
        .envelope_verification_source_identity(instance, &task)?;
    let execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            8,
            false,
            Some(MaintenanceTaskClass::EnvelopeVerification),
        )
        .expect("admit exact handler")
        .expect("queued task");
    assert_eq!(
        catalog
            .pin()?
            .envelope_verification_source_identity(instance, &task)?,
        source
    );
    assert_eq!(
        execution.checkpoint_and_persist(
            &coordinator,
            &catalog,
            MaintenanceCheckpoint::new(1, 0, b"generic fabricated progress".to_vec())
                .expect("bounded input"),
        ),
        Err(MaintenanceFailure::InvalidTransition)
    );
    assert_eq!(
        execution.complete_and_persist(&coordinator, &catalog, true),
        Err(MaintenanceFailure::InvalidTransition)
    );
    assert_eq!(
        catalog
            .pin()?
            .envelope_verification_source_identity(instance, &task)?,
        source
    );
    let basis = catalog.pin()?;
    let mut objects = Vec::new();
    for identity in basis.object_identities() {
        objects.push(CatalogObject::new(
            basis.object(identity)?.ok_or("object")?.to_vec(),
        )?);
    }
    objects.push(CatalogObject::new(
        b"new actual managed reference".to_vec(),
    )?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x53; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert_ne!(
        catalog
            .pin()?
            .envelope_verification_source_identity(instance, &task)?,
        source
    );
    Ok(())
}

#[test]
fn envelope_checkpoint_binds_instance_tenant_epoch_and_rejects_noncanonical_progress() {
    let instance = InstanceId::new([1; 16]).expect("instance");
    let tenant = TenantId::from_bytes([2; 16]).expect("tenant");
    let scope = crate::SegmentScope::new(
        tenant,
        SignalKind::Logs,
        VirtualShardId::new(1).expect("shard"),
    );
    let progress =
        crate::EnvelopeVerificationCheckpoint::new(instance, tenant, 2, [3; 32], Some(scope), None)
            .expect("bounded progress");
    let checkpoint = progress.checkpoint(1).expect("checkpoint");
    assert_eq!(
        crate::EnvelopeVerificationCheckpoint::from_checkpoint(&checkpoint, instance, tenant, 2)
            .expect("context verified"),
        progress
    );
    assert!(
        crate::EnvelopeVerificationCheckpoint::from_checkpoint(
            &checkpoint,
            InstanceId::new([4; 16]).expect("other instance"),
            tenant,
            2
        )
        .is_err()
    );
    assert!(
        crate::EnvelopeVerificationCheckpoint::from_checkpoint(
            &checkpoint,
            instance,
            TenantId::from_bytes([4; 16]).expect("other tenant"),
            2
        )
        .is_err()
    );
    assert!(
        crate::EnvelopeVerificationCheckpoint::from_checkpoint(&checkpoint, instance, tenant, 3)
            .is_err()
    );
    let encoded = checkpoint.opaque_progress();
    for size in 0..encoded.len() {
        let truncated =
            MaintenanceCheckpoint::new(1, 0, encoded[..size].to_vec()).expect("bounded input");
        assert!(
            crate::EnvelopeVerificationCheckpoint::from_checkpoint(&truncated, instance, tenant, 2)
                .is_err()
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(
        crate::EnvelopeVerificationCheckpoint::from_checkpoint(
            &MaintenanceCheckpoint::new(1, 0, trailing).expect("bounded trailing"),
            instance,
            tenant,
            2
        )
        .is_err()
    );
}
