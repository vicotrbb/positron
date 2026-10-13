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
        vec![MaintenanceObjectId::new([43; 32]).expect("checkpoint input")],
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
                MaintenanceCheckpoint::new(1, 1, vec![4, 2]).expect("checkpoint"),
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
            MaintenanceCheckpoint::new(1, 1, vec![4, 2]).expect("checkpoint"),
        )
        .expect("checkpoint must publish");
    let untimed_progress = coordinator
        .status_with_progress_slo(identity, Some(68), false)
        .expect("checkpoint status");
    assert_eq!(untimed_progress.last_progress_at(), None);
    assert_eq!(untimed_progress.no_durable_progress_slo_breached(), None);
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
        status.last_progress_at(),
        None,
        "recovery requeues an interrupted execution without carrying its running deadline"
    );
    assert_eq!(
        restored
            .durable_records()
            .expect("requeued recovery state must remain persistable")
            .len(),
        1
    );
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
    let resumed = restored
        .status_with_progress_slo(identity, Some(9), false)
        .expect("resumed status");
    assert_eq!(resumed.last_progress_at(), Some(9));
    assert_eq!(resumed.no_durable_progress_slo_breached(), Some(false));
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

#[test]
fn root_terminal_reclamation_retries_ambiguous_publication_without_losing_its_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        volume,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let instance = InstanceId::new(nonzero_id(51))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xa1; 32]), Box::new([0xa2; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(52))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"root reclamation basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([56; 16]).expect("task identity"),
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
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("maintenance fixture operation");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("maintenance fixture operation")
        .ok_or("task dispatch")?;
    execution
        .complete_and_persist(&coordinator, &catalog, true)
        .expect("maintenance fixture operation");
    drop(execution);
    let session = crate::RootRewrapSession::admit(&authority)?;
    let original = catalog.pin()?.identity();
    assert!(
        coordinator
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_ok()
    );
    let definite = crate::with_catalog_publication_fault_after(
        crate::CatalogPublicationFault::SynchronizeCommit,
        0,
        || coordinator.reclaim_terminal_records_for_root_retirement(&session, &catalog),
    );
    assert_eq!(definite, Err(MaintenanceFailure::CatalogUnavailable));
    assert_eq!(catalog.pin()?.identity(), original);
    assert_eq!(
        coordinator
            .status(identity)
            .expect("retained terminal task")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("authenticated original records")
            .statuses()
            .expect("restored statuses")
            .len(),
        1
    );
    let failure = crate::with_catalog_publication_fault_sequence_after(
        &[
            (
                crate::CatalogPublicationFault::SynchronizeGenerationDirectory,
                0,
            ),
            (
                crate::CatalogPublicationFault::SynchronizeGenerationDirectory,
                0,
            ),
            (
                crate::CatalogPublicationFault::SynchronizeGenerationDirectory,
                0,
            ),
        ],
        || coordinator.reclaim_terminal_records_for_root_retirement(&session, &catalog),
    );
    assert_eq!(failure, Err(MaintenanceFailure::CatalogUnavailable));
    assert_eq!(
        coordinator
            .status(identity)
            .expect("maintenance fixture operation")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert!(matches!(
        coordinator.guard_root_retirement_references(&session, &catalog, &catalog.pin()?),
        Err(MaintenanceFailure::ConcurrentAccess)
    ));
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("maintenance fixture operation"),
        1
    );
    assert!(
        coordinator
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_ok()
    );
    assert!(
        coordinator
            .statuses()
            .expect("maintenance fixture operation")
            .is_empty()
    );
    assert!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("maintenance fixture operation")
            .statuses()
            .expect("maintenance fixture operation")
            .is_empty()
    );
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("maintenance fixture operation"),
        0
    );
    Ok(())
}

#[test]
fn root_reclamation_preserves_opaque_scrub_references_and_expires_digest_only_descriptors()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(61))?,
        CatalogSecret::from_owned(Box::new([0xa1; 32]), Box::new([0xa2; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(62))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"scrub descriptor retirement".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let scope = MaintenanceScope::segment(
        positron_domain::identity::TenantId::from_bytes([0x43; 16])?,
        positron_domain::routing::SignalKind::Logs,
        positron_domain::routing::VirtualShardId::new(1)?,
    );
    let canonical = MaintenanceTask::integrity_scrub(
        MaintenanceTaskId::new([63; 16]).expect("identity"),
        scope,
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("basis"),
        [65; 32],
        0,
    )
    .expect("canonical metadata descriptor");
    let canonical_id = canonical.identity();
    let mut opaque = canonical.clone();
    opaque.identity = MaintenanceTaskId::new([64; 16]).expect("identity");
    opaque
        .inputs
        .push(MaintenanceObjectId::new([66; 32]).expect("opaque reference"));
    let opaque_id = opaque.identity();
    let mut output = canonical.clone();
    output.identity = MaintenanceTaskId::new([67; 16]).expect("identity");
    output
        .outputs
        .push(MaintenanceObjectId::new([68; 32]).expect("opaque output"));
    output.reservations = ResourceAmounts::new([1; 11]);
    let mut wrong_claim = canonical.clone();
    wrong_claim.identity = MaintenanceTaskId::new([69; 16]).expect("identity");
    wrong_claim.reservations = ResourceAmounts::new([1; 11]);
    let retained = [opaque_id, output.identity(), wrong_claim.identity()];
    for (index, task) in [canonical, opaque, output, wrong_claim]
        .into_iter()
        .enumerate()
    {
        let id = task.identity();
        coordinator
            .submit_and_persist(&catalog, task, 1)
            .expect("persist descriptor");
        if index < 2 {
            coordinator
                .cancel_and_persist(&catalog, id)
                .expect("cancel descriptor");
        } else {
            let execution = coordinator
                .start_integrity_scrub_task_with_reservation_and_persist(
                    &catalog, &authority, 2, false, id,
                )
                .expect("dispatch")
                .ok_or("dispatch")?;
            execution
                .complete_and_persist(&coordinator, &catalog, index == 2)
                .expect("terminal outcome");
        }
    }
    let session = crate::RootRewrapSession::admit(&authority)?;
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("bounded descriptor expiration"),
        1
    );
    assert!(matches!(
        coordinator.status(canonical_id),
        Err(MaintenanceFailure::UnknownTask)
    ));
    for (identity, phase) in retained.into_iter().zip([
        MaintenanceTaskPhase::Cancelled,
        MaintenanceTaskPhase::Succeeded,
        MaintenanceTaskPhase::Failed,
    ]) {
        assert_eq!(
            coordinator
                .status(identity)
                .expect("opaque remains")
                .phase(),
            phase
        );
    }
    assert!(
        coordinator
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_err()
    );
    Ok(())
}

#[test]
fn root_reclamation_keeps_snapshot_expiry_until_its_exact_lease_object_is_absent()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(71))?,
        CatalogSecret::from_owned(Box::new([0xa1; 32]), Box::new([0xa2; 32])),
    )?;
    let retained = CatalogObject::new(b"fixed opaque retained lease object".to_vec())?;
    let retained_id = retained.identity();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(72))?,
            FormatEpoch::CATALOG_V1,
            vec![
                retained,
                CatalogObject::new(b"nonempty expiry catalog basis".to_vec())?,
            ],
        )?,
        None,
    )?;
    let task = MaintenanceTask::with_contract_not_before(
        MaintenanceTaskId::new([73; 16]).expect("identity"),
        MaintenanceTaskClass::SnapshotLeaseExpiry,
        MaintenanceScope::segment(
            positron_domain::identity::TenantId::from_bytes([0x43; 16])?,
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::VirtualShardId::new(1)?,
        ),
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("basis"),
        vec![MaintenanceObjectId::new(retained_id.to_bytes()).expect("object")],
        Vec::new(),
        ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        100,
    )
    .expect("expiry descriptor");
    let identity = task.identity();
    let coordinator = MaintenanceCoordinator::new();
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .expect("persist expiry");
    coordinator
        .cancel_and_persist(&catalog, identity)
        .expect("cancel expiry");
    let session = crate::RootRewrapSession::admit(&authority)?;
    let basis = catalog.pin()?;
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("reference check"),
        0
    );
    assert_eq!(catalog.pin()?.identity(), basis.identity());
    assert!(
        coordinator
            .guard_root_retirement_references(&session, &catalog, &basis)
            .is_err()
    );
    let objects = basis
        .plaintext_objects()
        .filter_map(|bytes| {
            let object = CatalogObject::new(bytes.to_vec()).expect("authenticated object");
            (object.identity() != retained_id).then_some(object)
        })
        .collect();
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(74))?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    drop(basis);
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("released descriptor"),
        1
    );
    assert!(matches!(
        coordinator.status(identity),
        Err(MaintenanceFailure::UnknownTask)
    ));
    Ok(())
}

#[test]
fn root_retirement_accepts_only_the_exact_running_root_migration_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        volume,
        70_000_001,
        1_048_576 + 16_384,
    )?;
    let instance = InstanceId::new(nonzero_id(91))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xb1; 32]), Box::new([0xb2; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(92))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"root migration basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let binding = RootProviderMigrationBinding::new([0xb3; 16], [0xb4; 32]).expect("binding");
    coordinator
        .submit_root_provider_migration_and_persist(
            &catalog,
            binding,
            MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
            7,
        )
        .expect("submit bound migration");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("start")
        .ok_or("root migration execution")?;
    let session = crate::RootRewrapSession::admit(&authority)?;
    assert!(
        coordinator
            .guard_root_retirement_references(&session, &catalog, &catalog.pin()?)
            .is_err()
    );
    assert!(
        coordinator
            .guard_root_retirement_for_migration(
                &session,
                &catalog,
                &catalog.pin()?,
                &execution,
                binding
            )
            .is_ok()
    );
    {
        let proof = coordinator
            .guard_root_retirement_for_migration(
                &session,
                &catalog,
                &catalog.pin()?,
                &execution,
                binding,
            )
            .expect("exact coordinator proof");
        assert!(
            crate::ActiveSegmentLedger::guard_local_root_retirement(&authority, &catalog).is_err()
        );
        drop(
            crate::ActiveSegmentLedger::guard_local_root_retirement_with_references(
                &authority, &catalog, &proof,
            )
            .expect("ledger accepts exact proof"),
        );
        let other_root = CatalogRoot::new()?;
        let other_authority =
            crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
                PrimaryDataVolume::acquire(&other_root.0, MountQualification::LocalHost)?,
                70_000_001,
                1_048_576 + 16_384,
            )?;
        assert!(
            crate::ActiveSegmentLedger::guard_local_root_retirement_with_references(
                &other_authority,
                &catalog,
                &proof,
            )
            .is_err()
        );
        let basis = catalog.pin()?;
        let objects = basis
            .plaintext_objects()
            .map(|bytes| CatalogObject::new(bytes.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new(nonzero_id(93))?,
                FormatEpoch::CATALOG_V1,
                objects,
            )?,
            None,
        )?;
        assert!(
            crate::ActiveSegmentLedger::guard_local_root_retirement_with_references(
                &authority, &catalog, &proof,
            )
            .is_err()
        );
    }
    assert!(
        coordinator
            .guard_root_retirement_for_migration(
                &session,
                &catalog,
                &catalog.pin()?,
                &execution,
                RootProviderMigrationBinding::new([0xb5; 16], [0xb4; 32]).expect("other binding")
            )
            .is_err()
    );
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
    assert!(
        restored
            .guard_root_retirement_for_migration(
                &session,
                &catalog,
                &catalog.pin()?,
                &execution,
                binding
            )
            .is_err()
    );
    drop(restored);
    let unrelated = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0xb6; 16]).expect("task identity"),
        MaintenanceTaskClass::Migration,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(catalog.pin()?.number(), 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    )
    .expect("unrelated task");
    coordinator
        .submit_and_persist(&catalog, unrelated, 9)
        .expect("unrelated submission");
    assert!(
        coordinator
            .guard_root_retirement_for_migration(
                &session,
                &catalog,
                &catalog.pin()?,
                &execution,
                binding
            )
            .is_err()
    );
    execution
        .complete_and_persist(&coordinator, &catalog, true)
        .expect("complete bound migration");
    drop(execution);
    assert_eq!(
        coordinator
            .reclaim_terminal_records_for_root_retirement(&session, &catalog)
            .expect("terminal reclamation"),
        1
    );
    assert!(
        coordinator
            .status(MaintenanceTaskId::new(binding.operation_id()).expect("owned task"))
            .is_err()
    );
    assert_eq!(
        coordinator
            .status(MaintenanceTaskId::new([0xb6; 16]).expect("unrelated identity"))
            .expect("unrelated task retained")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    Ok(())
}
