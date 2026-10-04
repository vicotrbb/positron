use super::*;
use crate::AuditIntent;

#[test]
fn durable_checkpoint_restores_the_same_task_after_a_process_restart() {
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        9,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Ordinary,
        Vec::new(),
    );
    let identity = task.identity();
    coordinator.submit(task).expect("accepted");
    coordinator.start_next(1, false).expect("start");
    coordinator
        .checkpoint(
            identity,
            MaintenanceCheckpoint::new(1, 0, vec![9, 8]).expect("checkpoint"),
        )
        .expect("record checkpoint");
    let records = coordinator.durable_records().expect("durable records");

    let restored = MaintenanceCoordinator::restore(records).expect("restore");
    assert_eq!(
        restored
            .status(identity)
            .expect("restored status")
            .checkpoint()
            .map(MaintenanceCheckpoint::opaque_progress),
        Some(&[9, 8][..])
    );
}
#[test]
fn catalog_checkpoint_reopen_restores_one_queued_task_with_its_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(1))?;
    let secret = CatalogSecret::from_owned(Box::new([0x51; 32]), Box::new([0x52; 32]));
    let catalog = Catalog::open(&authority, instance, secret)?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(2))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(b"maintenance catalog basis".to_vec())?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([42; 16]).expect("stable task identity"),
        MaintenanceTaskClass::SchemaStatistics,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(4, 9).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    );
    let task = task.expect("bounded task");
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("submission must publish its record");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("dispatch admission")
        .expect("persisted task must dispatch");
    assert_eq!(
        coordinator
            .status_with_progress_slo(identity, Some(67), false)
            .expect("running status")
            .no_durable_progress_slo_breached(),
        Some(false)
    );
    let failed_checkpoint =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            execution.checkpoint_and_persist_at(
                &coordinator,
                &catalog,
                MaintenanceCheckpoint::new(1, 0, vec![4, 2]).expect("checkpoint"),
                20,
            )
        });
    assert_eq!(
        failed_checkpoint.expect_err("checkpoint publication must fail"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        coordinator
            .status_with_progress_slo(identity, Some(68), false)
            .expect("running status")
            .no_durable_progress_slo_breached(),
        Some(true),
        "an unpublished checkpoint cannot reset the durable-progress deadline"
    );
    execution
        .checkpoint_and_persist(
            &coordinator,
            &catalog,
            MaintenanceCheckpoint::new(1, 0, vec![4, 2]).expect("checkpoint"),
        )
        .expect("checkpoint must publish");
    drop(execution);
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x51; 32]), Box::new([0x52; 32])),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&reopened).expect("restore");
    let status = restored.status(identity).expect("restored status");
    assert_eq!(status.phase(), MaintenanceTaskPhase::Queued);
    assert_eq!(
        status
            .checkpoint()
            .map(MaintenanceCheckpoint::opaque_progress),
        Some(&[4, 2][..])
    );
    let execution = restored
        .start_next_with_reservation_and_persist(&reopened, &authority, 9, false)
        .expect("resumed dispatch admission")
        .expect("recovered task must dispatch");
    let failure =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            execution.complete_and_persist(&restored, &reopened, true)
        });
    assert_eq!(
        failure.expect_err("terminal publication must fail"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        restored.status(identity).expect("running status").phase(),
        MaintenanceTaskPhase::Running,
        "the retained execution can retry its exact terminal record"
    );
    execution
        .complete_and_persist(&restored, &reopened, true)
        .expect("terminal outcome must publish");
    assert_eq!(
        restored.status(identity).expect("terminal status").phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        execution
            .complete_and_persist(&restored, &reopened, true)
            .expect_err("a terminal execution cannot publish a second outcome"),
        MaintenanceFailure::InvalidTransition
    );
    let durable = reopened.pin()?;
    assert_eq!(
        durable
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1,
        "each task owns one replacement record"
    );
    assert!(
        durable
            .plaintext_objects()
            .any(|bytes| bytes == b"maintenance catalog basis")
    );
    Ok(())
}

#[test]
fn catalog_submission_fault_leaves_no_in_memory_task_and_exact_retry_publishes_once()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(11))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(12))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance fault basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([43; 16]).expect("stable task identity"),
        MaintenanceTaskClass::SchemaStatistics,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(4, 9).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    )
    .expect("bounded task");
    let identity = task.identity();
    let result =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            coordinator.submit_and_persist(&catalog, task.clone(), 7)
        });
    assert_eq!(
        result.expect_err("publication must fail"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        coordinator
            .status(identity)
            .expect_err("state cannot outrun durable publication"),
        MaintenanceFailure::UnknownTask
    );
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        0
    );
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("exact retry must publish the queued task");
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn catalog_dispatch_fault_keeps_work_queued_and_reopen_recovers_durable_running()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(21))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(22))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance dispatch basis".to_vec())?],
        )?,
        None,
    )?;

    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(44);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    let failure =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            coordinator.start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        });
    let Err(failure) = failure else {
        panic!("running publication must fail");
    };
    assert_eq!(failure, MaintenanceFailure::CatalogUnavailable);
    assert_eq!(
        coordinator.status(identity).expect("queued status").phase(),
        MaintenanceTaskPhase::Queued,
        "resource admission cannot make running state visible before Catalog publication"
    );

    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("retry admission")
        .expect("exact retry must reserve and publish running");
    assert_eq!(
        coordinator
            .status(identity)
            .expect("running status")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    drop(execution);
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&reopened).expect("restore");
    assert_eq!(
        restored.status(identity).expect("restored status").phase(),
        MaintenanceTaskPhase::Queued,
        "a process exit releases the in-memory reservation and resumes the durable checkpoint"
    );
    Ok(())
}

#[test]
fn catalog_reload_refuses_to_replace_a_live_dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(24))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x75; 32]), Box::new([0x76; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(25))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance reload basis".to_vec())?],
        )?,
        None,
    )?;

    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(46);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("dispatch admission")
        .expect("queued task must dispatch");

    assert_eq!(
        coordinator
            .replace_from_catalog(&catalog)
            .expect_err("reload must preserve the live dispatch authority"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        coordinator.status(identity).expect("running task").phase(),
        MaintenanceTaskPhase::Running,
        "a rejected reload cannot discard the in-flight reservation"
    );
    drop(execution);
    coordinator
        .replace_from_catalog(&catalog)
        .expect("a stopped execution may recover from the authenticated Catalog");
    assert_eq!(
        coordinator
            .status(identity)
            .expect("recovered task")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the durable running checkpoint resumes only after its live reservation is released"
    );
    Ok(())
}

#[test]
fn catalog_pause_and_finite_window_survive_reopen_without_deferring_past_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(31))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x81; 32]), Box::new([0x82; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(32))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance controls basis".to_vec())?],
        )?,
        None,
    )?;

    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(45);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    coordinator
        .pause_and_persist(&catalog, identity, 9, 12, 8)
        .expect("pause must publish");
    coordinator
        .resume_and_persist(&catalog, identity)
        .expect("resume must publish");
    coordinator
        .set_window_and_persist(
            &catalog,
            [
                MaintenanceTaskClass::BackupSnapshot,
                MaintenanceTaskClass::RepositoryVerification,
            ],
            20,
            9,
        )
        .expect("window must publish");
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x81; 32]), Box::new([0x82; 32])),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&reopened).expect("restore");
    assert_eq!(
        restored.status(identity).expect("restored status").phase(),
        MaintenanceTaskPhase::Queued
    );
    assert_eq!(
        restored
            .window_blocking_until(identity, 19)
            .expect("persisted window inspection"),
        Some(20),
        "inspection and scheduling share the restored finite-window predicate"
    );
    assert_eq!(
        restored
            .window_blocking_until(identity, 20)
            .expect("expired window inspection"),
        None,
        "the same predicate releases work at the server-derived expiry"
    );
    assert!(
        restored
            .start_next_with_reservation_and_persist(&reopened, &authority, 19, false)
            .expect("window admission")
            .is_none(),
        "the persisted finite window defers only before its lifecycle expiry"
    );
    let execution = restored
        .start_next_with_reservation_and_persist(&reopened, &authority, 20, false)
        .expect("expiry admission")
        .expect("window expiry must make the queued task eligible");
    drop(execution);
    Ok(())
}

#[test]
fn audited_pause_publication_fault_keeps_the_task_queued_without_a_partial_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(36))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x86; 32]), Box::new([0x87; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(37))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                b"audited maintenance pause basis".to_vec(),
            )?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(48);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    let result =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            coordinator.pause_and_persist_audited(
                &catalog,
                identity,
                9,
                12,
                8,
                AuditIntent::new(b"maintenance pause audit".to_vec())
                    .map_err(|_| MaintenanceFailure::CatalogUnavailable)?,
            )
        });
    assert_eq!(
        result.expect_err("audited pause publication must fail"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        coordinator
            .status(identity)
            .expect("failed publication must retain queued task")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the scheduler cannot observe a pause whose Catalog transaction failed"
    );
    assert!(catalog.governance_audit_records()?.is_empty());
    Ok(())
}

#[test]
fn catalog_post_publication_completion_ambiguity_retries_without_losing_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(41))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x91; 32]), Box::new([0x92; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(42))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance ambiguity basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(46);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("dispatch admission")
        .expect("task must dispatch");

    let result = crate::catalog::with_catalog_fault(
        crate::catalog::CatalogFileEvent::SynchronizeGenerationDirectory,
        || execution.complete_and_persist(&coordinator, &catalog, true),
    );
    assert_eq!(
        result.expect_err("post-marker acknowledgement must be ambiguous"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        coordinator
            .status(identity)
            .expect("local running state")
            .phase(),
        MaintenanceTaskPhase::Running,
        "the retained execution is the sole retry capability until acknowledgement resolves"
    );
    execution
        .complete_and_persist(&coordinator, &catalog, true)
        .expect("exact retry resolves the durable terminal publication");
    assert_eq!(
        coordinator
            .status(identity)
            .expect("terminal state")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}

#[test]
fn catalog_failed_terminal_cause_is_atomic_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(47))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x93; 32]), Box::new([0x94; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(48))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                b"maintenance terminal cause basis".to_vec(),
            )?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(49);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .map_err(|failure| format!("submit task: {failure:?}"))?;
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .map_err(|failure| format!("dispatch task: {failure:?}"))?
        .ok_or("task must dispatch")?;

    let failure =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            execution.fail_and_persist(
                &coordinator,
                &catalog,
                MaintenanceTerminalFailure::IdentityMismatch,
            )
        });
    assert_eq!(failure, Err(MaintenanceFailure::CatalogUnavailable));
    let running = coordinator
        .status(identity)
        .map_err(|failure| format!("running task: {failure:?}"))?;
    assert_eq!(running.phase(), MaintenanceTaskPhase::Running);
    assert_eq!(running.terminal_failure(), None);

    execution
        .fail_and_persist(
            &coordinator,
            &catalog,
            MaintenanceTerminalFailure::IdentityMismatch,
        )
        .map_err(|failure| format!("publish failed terminal cause: {failure:?}"))?;
    let failed = coordinator
        .status(identity)
        .map_err(|failure| format!("failed task: {failure:?}"))?;
    assert_eq!(failed.phase(), MaintenanceTaskPhase::Failed);
    assert_eq!(
        failed.terminal_failure(),
        Some(MaintenanceTerminalFailure::IdentityMismatch)
    );
    drop(execution);
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x93; 32]), Box::new([0x94; 32])),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&reopened)
        .map_err(|failure| format!("restore task: {failure:?}"))?;
    assert_eq!(
        restored
            .status(identity)
            .map_err(|failure| format!("restored task: {failure:?}"))?
            .terminal_failure(),
        Some(MaintenanceTerminalFailure::IdentityMismatch)
    );
    Ok(())
}
