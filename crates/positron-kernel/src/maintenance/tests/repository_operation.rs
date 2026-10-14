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

#[test]
fn repository_native_handoff_keeps_one_grant_until_the_last_worker_drops()
-> Result<(), Box<dyn std::error::Error>> {
    use aws_config::credential_process::CredentialProcessAdmission;
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(1))?,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"native resource owner".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([91; 16], [92; 32]).expect("binding");
    coordinator
        .submit_repository_operation_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
            7,
        )
        .expect("submission");
    let mut execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            8,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
        .expect("dispatch")
        .ok_or("execution")?;
    let before = authority.governor().inspect()?.outstanding_reservations();
    assert!(
        execution
            .transfer_repository_resources(
                RepositoryOperationBinding::new([93; 16], [92; 32]).expect("wrong binding")
            )
            .is_err()
    );
    assert!(
        execution
            .retained_repository_resources(binding)
            .expect("before handoff")
            .is_none()
    );
    let grant = execution
        .transfer_repository_resources(binding)
        .expect("handoff");
    assert!(
        execution
            .retained_repository_resources(
                RepositoryOperationBinding::new([93; 16], [92; 32]).expect("wrong retry binding")
            )
            .is_err()
    );
    let retry = execution
        .retained_repository_resources(binding)
        .expect("retry owner")
        .ok_or("lost admitted owner")?;
    assert_eq!(
        authority.governor().inspect()?.outstanding_reservations(),
        before
    );
    assert!(execution.transfer_repository_resources(binding).is_err());
    drop(grant);
    let resources = retry;
    let process = crate::NativeAwsCredentialProcessAdmission::new(resources.clone());
    let worker = process.try_acquire().ok_or("worker lease")?;
    execution
        .complete_and_persist(&coordinator, &catalog, false)
        .expect("terminal publication");
    drop(execution);
    drop(process);
    drop(resources);
    assert_eq!(
        authority.governor().inspect()?.outstanding_reservations(),
        before
    );
    drop(worker);
    assert_eq!(
        authority.governor().inspect()?.outstanding_reservations(),
        before - 1
    );
    Ok(())
}

#[test]
fn repository_transport_peak_is_admitted_before_dispatch() -> Result<(), Box<dyn std::error::Error>>
{
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(1))?,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"transport admission".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([94; 16], [95; 32]).expect("binding");
    coordinator
        .submit_repository_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
            ResourceAmounts::new([268_435_456, 1, 4, 0, 1, 1, 2, 4, 1, 8, 16_384]),
            7,
        )
        .expect("persist native claim");
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
            .status(MaintenanceTaskId::new(binding.operation_id()).expect("task"))
            .expect("queued task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    Ok(())
}
