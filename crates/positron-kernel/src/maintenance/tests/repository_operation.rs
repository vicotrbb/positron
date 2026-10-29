use super::*;
#[path = "backup_verification_reference.rs"]
mod backup_verification_reference;
#[test]
fn repository_task_reopens_exact_owned_dispatch_binding() -> Result<(), Box<dyn std::error::Error>>
{
    repository_task_reopens_dispatch_binding(false)
}

#[test]
fn installed_handler_dispatches_the_reopened_repository_binding()
-> Result<(), Box<dyn std::error::Error>> {
    repository_task_reopens_dispatch_binding(true)
}

fn repository_task_reopens_dispatch_binding(
    installed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let execution = if installed {
        restored.start_next_with_root_migration_handler_and_snapshot_lease_times(
            &catalog,
            &authority,
            8,
            false,
            &[MaintenanceTaskClass::RepositoryVerification],
            &std::collections::BTreeMap::new(),
        )
    } else {
        restored.start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            8,
            false,
            Some(MaintenanceTaskClass::RepositoryVerification),
        )
    }
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

#[test]
fn backup_task_restores_exact_binding_and_bounded_transfer_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(1))?,
        CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(b"backup task basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([91; 16], [92; 32]).expect("binding");
    let task = coordinator
        .submit_backup_operation_with_resources_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            ResourceAmounts::new([25_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16_384]),
            7,
        )
        .expect("submit");
    assert_eq!(task.class(), MaintenanceTaskClass::BackupSnapshot);
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
    let execution = restored
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            8,
            false,
            Some(MaintenanceTaskClass::BackupSnapshot),
        )
        .expect("admit")
        .ok_or("execution")?;
    assert_eq!(
        RepositoryOperationBinding::from_execution(&execution).expect("binding"),
        binding
    );
    execution
        .checkpoint_and_persist(
            &restored,
            &catalog,
            binding
                .backup_checkpoint(2, b"transfer-cursor")
                .expect("checkpoint"),
        )
        .expect("persist");
    drop(execution);
    let recovered = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("cold restore");
    let execution = recovered
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            9,
            false,
            Some(MaintenanceTaskClass::BackupSnapshot),
        )
        .expect("resume")
        .ok_or("resumed execution")?;
    assert_eq!(
        RepositoryOperationBinding::from_execution(&execution).expect("resumed binding"),
        binding
    );
    assert_eq!(
        binding.backup_progress(&execution).expect("progress"),
        b"transfer-cursor"
    );
    assert!(binding.backup_checkpoint(1, b"invalid").is_err());
    assert!(binding.backup_checkpoint(3, &vec![0; 65_536]).is_err());
    Ok(())
}

#[test]
fn backup_readmission_preserves_failed_owner_and_cold_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    for (native, class) in [
        (false, MaintenanceTaskClass::BackupSnapshot),
        (true, MaintenanceTaskClass::BackupSnapshot),
        (false, MaintenanceTaskClass::RepositoryCleanup),
        (true, MaintenanceTaskClass::RepositoryCleanup),
    ] {
        let root = CatalogRoot::new()?;
        let authority =
            crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
                PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
                70_000_001,
                30_000_000,
            )?;
        let catalog = Catalog::open(
            &authority,
            InstanceId::new(nonzero_id(1))?,
            CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
        )?;
        catalog.commit(
            catalog.pin()?.identity(),
            CatalogProposal::new(
                TransactionId::new(nonzero_id(2))?,
                FormatEpoch::CATALOG_V2,
                vec![CatalogObject::new(b"readmission basis".to_vec())?],
            )?,
            None,
        )?;
        let coordinator = MaintenanceCoordinator::new();
        let binding = RepositoryOperationBinding::new([101; 16], [102; 32]).expect("binding");
        let old = ResourceAmounts::new([25_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16_384]);
        let larger = ResourceAmounts::new([26_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 9, 32_768]);
        let preconditions = MaintenancePreconditions::new(1, 1).expect("preconditions");
        let task = if class == MaintenanceTaskClass::RepositoryCleanup {
            coordinator.submit_backup_retention_operation_with_resources_and_persist(
                &catalog,
                binding,
                preconditions,
                old,
                7,
            )
        } else {
            coordinator.submit_backup_operation_with_resources_and_persist(
                &catalog,
                binding,
                preconditions,
                old,
                7,
            )
        }
        .expect("submit");
        let mut execution = coordinator
            .start_next_with_reservation_and_persist_for_class(
                &catalog,
                &authority,
                8,
                false,
                Some(class),
            )
            .expect("dispatch")
            .ok_or("dispatch")?;
        let checkpoint = binding
            .backup_checkpoint(2, b"cold exact cursor")
            .expect("checkpoint");
        execution
            .checkpoint_and_persist(&coordinator, &catalog, checkpoint.clone())
            .expect("persist");
        assert_eq!(
            binding
                .backup_progress(&execution)
                .expect("cached progress"),
            b""
        );
        assert_eq!(
            binding
                .current_backup_progress(&coordinator, &execution)
                .expect("current progress"),
            (2, b"cold exact cursor".to_vec())
        );
        assert!(
            RepositoryOperationBinding::new([103; 16], [102; 32])
                .expect("wrong binding")
                .current_backup_progress(&coordinator, &execution)
                .is_err()
        );
        coordinator
            .cancel_and_persist(&catalog, task.identity())
            .expect("request cancellation");
        let charged = authority
            .governor()
            .inspect()
            .expect("usage before handoff")
            .usage(ResourceDimension::MemoryBytes);
        assert!(charged >= old.get(ResourceDimension::MemoryBytes));
        let native_owner = if native {
            Some(
                execution
                    .transfer_repository_resources(binding)
                    .expect("transfer"),
            )
        } else {
            None
        };
        if native {
            assert!(
                execution
                    .requeue_backup_with_resources_and_persist(
                        &coordinator,
                        &catalog,
                        binding,
                        larger,
                        9
                    )
                    .is_err()
            );
        }
        drop(native_owner);
        let wrong = RepositoryOperationBinding::new([101; 16], [103; 32]).expect("wrong binding");
        assert!(
            execution
                .requeue_backup_with_resources_and_persist(&coordinator, &catalog, wrong, larger, 9)
                .is_err()
        );
        assert!(
            execution
                .requeue_backup_with_resources_and_persist(
                    &coordinator,
                    &catalog,
                    binding,
                    ResourceAmounts::new([24_000_000, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16_384]),
                    9
                )
                .is_err()
        );
        let usage = authority
            .governor()
            .inspect()
            .expect("publication headroom");
        let memory = ResourceDimension::MemoryBytes;
        let kind = crate::RecoveryWorkKind::DurabilityCompletion;
        let headroom = usage.recovery_pool_capacity(kind, memory)
            + usage.recovery_shared_capacity(memory)
            - usage.recovery_pool_usage(kind, memory)
            - usage.recovery_shared_usage(memory)
            - usage.usage(memory);
        // The system scope owns a protected slice of the global recovery
        // capacity. Its typed refusal reports the exact remaining ceiling.
        let refusal = authority
            .recovery()
            .reserve(
                crate::RecoveryWorkClaim::system(
                    kind,
                    ResourceAmounts::new([headroom, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                )
                .expect("scope probe"),
            )
            .expect_err("global headroom exceeds system slice");
        let available = refusal.allowed() - refusal.in_use();
        let blocker = authority
            .recovery()
            .reserve(
                crate::RecoveryWorkClaim::system(
                    kind,
                    ResourceAmounts::new([available - 65_536, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                )
                .expect("blocking claim"),
            )
            .expect("occupy publication headroom");
        assert!(
            execution
                .requeue_backup_with_resources_and_persist(
                    &coordinator,
                    &catalog,
                    binding,
                    larger,
                    9
                )
                .is_err()
        );
        assert_eq!(
            coordinator
                .status(task.identity())
                .expect("denied status")
                .phase(),
            MaintenanceTaskPhase::Running
        );
        assert_eq!(execution.reservation().granted(), old);
        assert_eq!(
            RepositoryOperationBinding::from_execution(&execution).expect("denied owner"),
            binding
        );
        drop(blocker);
        let failed = crate::catalog::with_catalog_fault(
            crate::catalog::CatalogFileEvent::WriteMarker,
            || {
                execution.requeue_backup_with_resources_and_persist(
                    &coordinator,
                    &catalog,
                    binding,
                    larger,
                    9,
                )
            },
        );
        assert!(failed.is_err());
        assert_eq!(
            coordinator.status(task.identity()).expect("status").phase(),
            MaintenanceTaskPhase::Running
        );
        assert_eq!(execution.reservation().granted(), old);
        assert_eq!(
            RepositoryOperationBinding::from_execution(&execution).expect("binding remains live"),
            binding
        );
        execution
            .requeue_backup_with_resources_and_persist(&coordinator, &catalog, binding, larger, 10)
            .expect("requeue");
        assert_eq!(
            coordinator.status(task.identity()).expect("status").phase(),
            MaintenanceTaskPhase::Queued
        );
        assert!(
            ResourceDimension::ALL.iter().all(|dimension| execution
                .reservation()
                .granted()
                .get(*dimension)
                == 0)
        );
        assert!(RepositoryOperationBinding::from_execution(&execution).is_err());
        assert_eq!(
            authority
                .governor()
                .inspect()
                .expect("usage after handoff")
                .usage(ResourceDimension::MemoryBytes),
            charged
        );
        assert!(
            coordinator
                .status(task.identity())
                .expect("queued status")
                .cancellation_requested()
        );
        assert!(
            execution
                .checkpoint_and_persist(
                    &coordinator,
                    &catalog,
                    binding
                        .backup_checkpoint(3, b"stale owner")
                        .expect("stale checkpoint")
                )
                .is_err()
        );
        assert!(
            execution
                .complete_and_persist(&coordinator, &catalog, true)
                .is_err()
        );
        drop(execution);
        let recovered = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
        let resumed = recovered
            .start_next_with_reservation_and_persist_for_class(
                &catalog,
                &authority,
                11,
                false,
                Some(class),
            )
            .expect("readmission")
            .ok_or("readmission")?;
        assert!(
            recovered
                .status(task.identity())
                .expect("readmitted status")
                .cancellation_requested()
        );
        assert_eq!(resumed.task().reservations(), larger);
        assert_eq!(resumed.reservation().granted(), larger);
        assert_eq!(resumed.task_checkpoint(), Some(&checkpoint));
        assert_eq!(
            RepositoryOperationBinding::from_execution(&resumed).expect("resumed binding"),
            binding
        );
    }
    Ok(())
}

#[test]
fn tenant_purge_start_replay_preserves_advanced_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(1))?,
        CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(2))?,
            FormatEpoch::CATALOG_V2,
            vec![CatalogObject::new(b"purge replay basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RepositoryOperationBinding::new([101; 16], [102; 32]).expect("binding");
    let tenant = TenantId::from_bytes([103; 16])?;
    let preconditions = MaintenancePreconditions::new(1, 1).expect("preconditions");
    let task = coordinator
        .submit_tenant_purge_and_persist(&catalog, binding, preconditions, tenant, 7)
        .expect("submit");
    assert_eq!(
        coordinator.start_next(8, false).expect("dispatch"),
        Some(task.clone())
    );
    coordinator
        .checkpoint(
            task.identity(),
            binding
                .backup_checkpoint(2, b"exact deletion cursor")
                .expect("cursor"),
        )
        .expect("progress");
    assert_eq!(
        coordinator
            .submit_tenant_purge_and_persist(&catalog, binding, preconditions, tenant, 9)
            .expect("exact start replay"),
        task
    );
    assert_eq!(
        coordinator
            .status(task.identity())
            .expect("status")
            .checkpoint()
            .map(MaintenanceCheckpoint::sequence),
        Some(2)
    );
    assert!(
        coordinator
            .submit_tenant_purge_and_persist(
                &catalog,
                RepositoryOperationBinding::new([101; 16], [104; 32]).expect("changed intent"),
                preconditions,
                tenant,
                9
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn backup_submission_floor_defers_exact_recovered_admission()
-> Result<(), Box<dyn std::error::Error>> {
    recovered_backup_submission_floor(true)
}

#[test]
fn backup_submission_floor_defers_general_recovered_admission()
-> Result<(), Box<dyn std::error::Error>> {
    recovered_backup_submission_floor(false)
}

fn recovered_backup_submission_floor(exact: bool) -> Result<(), Box<dyn std::error::Error>> {
    for native in [false, true] {
        let root = CatalogRoot::new()?;
        let authority =
            crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
                PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
                70_000_001,
                30_000_000,
            )?;
        let catalog = Catalog::open(
            &authority,
            InstanceId::new(nonzero_id(1))?,
            CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
        )?;
        catalog.commit(
            catalog.pin()?.identity(),
            CatalogProposal::new(
                TransactionId::new(nonzero_id(2))?,
                FormatEpoch::CATALOG_V2,
                vec![CatalogObject::new(b"submission floor basis".to_vec())?],
            )?,
            None,
        )?;
        let original = MaintenanceCoordinator::new();
        let binding = RepositoryOperationBinding::new([111; 16], [112; 32]).expect("binding");
        let resources = ResourceAmounts::new([8_519_680, 1, 1, 0, 1, 0, 1, 1, 1, 8, 16_384]);
        let task = original
            .submit_backup_operation_with_resources_and_persist(
                &catalog,
                binding,
                MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
                resources,
                100,
            )
            .expect("persist submission");
        drop(original);
        let coordinator = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
        let before = coordinator.status(task.identity()).expect("status");
        let generation = catalog.pin()?.number();
        let usage = authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes);
        let early = if exact {
            coordinator
                .start_backup_operation_with_reservation_and_persist(
                    &catalog,
                    &authority,
                    99,
                    false,
                    task.identity(),
                )
                .expect("exact admission")
        } else {
            coordinator
                .start_next_with_reservation_and_persist(&catalog, &authority, 99, false)
                .expect("early admission")
        };
        assert!(
            early.is_none(),
            "a recovered task cannot dispatch before its persisted submission"
        );
        assert_eq!(coordinator.status(task.identity()).expect("status"), before);
        assert_eq!(catalog.pin()?.number(), generation);
        assert_eq!(
            authority
                .governor()
                .inspect()?
                .usage(ResourceDimension::MemoryBytes),
            usage
        );
        let mut execution = if exact {
            coordinator
                .start_backup_operation_with_reservation_and_persist(
                    &catalog,
                    &authority,
                    100,
                    false,
                    task.identity(),
                )
                .expect("exact admission")
        } else {
            coordinator
                .start_next_with_reservation_and_persist(&catalog, &authority, 100, false)
                .expect("due admission")
        }
        .ok_or("eligible recovered Backup task")?;
        if native {
            drop(
                execution
                    .transfer_repository_resources(binding)
                    .expect("native transfer"),
            );
        }
        let larger = ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| {
            if dimension == ResourceDimension::MemoryBytes {
                resources.get(dimension) + 4096
            } else {
                resources.get(dimension)
            }
        }));
        execution
            .requeue_backup_with_resources_and_persist(&coordinator, &catalog, binding, larger, 100)
            .expect("growth requeue");
        assert_eq!(
            coordinator.status(task.identity()).expect("status").phase(),
            MaintenanceTaskPhase::Queued
        );
        assert_eq!(
            coordinator
                .status(task.identity())
                .expect("status")
                .task()
                .reservations(),
            larger
        );
        drop(execution);
        assert_eq!(
            authority
                .governor()
                .inspect()?
                .usage(ResourceDimension::MemoryBytes),
            usage
        );
    }
    Ok(())
}
