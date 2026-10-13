use super::*;
#[test]
fn repository_task_reopens_exact_owned_dispatch_binding() -> Result<(), Box<dyn std::error::Error>>
{
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let instance = InstanceId::new(nonzero_id(1))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"repository task basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([81; 16], [82; 32]).expect("binding");
    let task = coordinator
        .submit_repository_operation_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
            7,
        )
        .expect("submission");
    assert_eq!(task.class(), MaintenanceTaskClass::RepositoryVerification);
    assert_eq!(
        coordinator
            .submit_repository_operation_and_persist(&catalog, binding, task.preconditions(), 7)
            .expect("replay"),
        task
    );
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
    let execution = restored
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            8,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .expect("admission")
        .ok_or("no dispatched repository task")?;
    assert_eq!(
        RepositoryOperationBinding::from_execution(&execution).expect("owned dispatch"),
        binding
    );
    execution
        .complete_and_persist(&restored, &catalog, true)
        .expect("complete");
    assert_eq!(
        restored
            .status(task.identity())
            .expect("terminal status")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    drop(execution);
    let session = crate::RootRewrapSession::admit(&authority)?;
    assert!(
        restored
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_err()
    );
    assert_eq!(
        restored
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("reference-free terminal record reclamation"),
        1
    );
    assert!(
        restored
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_ok()
    );

    let other = RepositoryOperationBinding::new([83; 16], [84; 32]).expect("second binding");
    restored
        .submit_repository_operation_and_persist(
            &catalog,
            other,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
            9,
        )
        .expect("second submission");
    let execution = restored
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            10,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .expect("second dispatch")
        .ok_or("second execution")?;
    let mut malformed = b"REPBND01".to_vec();
    malformed.extend_from_slice(&[85; 16]);
    malformed.extend_from_slice(&[84; 32]);
    execution
        .checkpoint_and_persist(
            &restored,
            &catalog,
            MaintenanceCheckpoint::new(2, 0, malformed).expect("malformed fixture"),
        )
        .expect("checkpoint publication");
    execution
        .complete_and_persist(&restored, &catalog, true)
        .expect("second completion");
    drop(execution);
    assert_eq!(
        restored
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("conservative reclamation"),
        0
    );
    assert!(
        restored
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_err()
    );
    Ok(())
}

#[test]
fn repository_dispatch_refuses_insufficient_capacity_and_preserves_queued_work()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
    )?;
    let instance = InstanceId::new(nonzero_id(1))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x63; 32]), Box::new([0x64; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"bounded repository task".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = coordinator
        .submit_repository_operation_and_persist(
            &catalog,
            RepositoryOperationBinding::new([83; 16], [84; 32]).expect("binding"),
            MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
            7,
        )
        .expect("submission");
    assert!(matches!(
        coordinator.start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            8,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification)
        ),
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    ));
    assert_eq!(
        coordinator
            .status(task.identity())
            .expect("queued status")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    let restored =
        MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore queued operation");
    assert_eq!(
        restored
            .status(task.identity())
            .expect("restored queued status")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    Ok(())
}

#[test]
fn installed_repository_handler_does_not_dispatch_unbound_same_class_work()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        131_072,
    )?;
    let instance = InstanceId::new(nonzero_id(1))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x65; 32]), Box::new([0x66; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"unowned repository task".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let unowned = task(
        94,
        MaintenanceTaskClass::RepositoryVerification,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        Vec::new(),
    );
    let id = unowned.identity();
    coordinator
        .submit_and_persist(&catalog, unowned, 7)
        .expect("generic submission");
    let selected = coordinator.start_next_with_root_migration_handler_and_snapshot_lease_times(
        &catalog,
        &authority,
        8,
        false,
        &[MaintenanceTaskClass::RepositoryVerification],
        &std::collections::BTreeMap::new(),
    );
    assert!(
        matches!(selected, Err(MaintenanceFailure::ResourceAdmissionRefused)),
        "unowned work remains undispatched"
    );
    assert_eq!(
        coordinator.status(id).expect("unowned status").phase(),
        MaintenanceTaskPhase::Queued
    );
    Ok(())
}
