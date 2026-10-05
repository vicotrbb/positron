use super::*;

#[test]
fn governance_audit_checkpoint_binding_rejects_malformed_checkpoints() {
    let valid = GovernanceAuditCheckpointBinding::new(1, [1; 32], [2; 32])
        .expect("nonzero binding")
        .checkpoint()
        .expect("bounded checkpoint");
    assert!(GovernanceAuditCheckpointBinding::from_checkpoint(Some(&valid)).is_ok());

    for checkpoint in [
        None,
        Some(MaintenanceCheckpoint::new(2, 0, valid.opaque_progress().to_vec()).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 1, valid.opaque_progress().to_vec()).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 0, vec![0; 79]).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 0, vec![0; 80]).expect("shape")),
    ] {
        assert_eq!(
            GovernanceAuditCheckpointBinding::from_checkpoint(checkpoint.as_ref()),
            Err(MaintenanceFailure::InvalidInput)
        );
    }
}

#[test]
fn generic_submission_cannot_persist_a_compaction_without_its_typed_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(0x57))?,
        CatalogSecret::from_owned(Box::new([0x58; 32]), Box::new([0x59; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        0x5a,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        Vec::new(),
    );
    assert_eq!(
        coordinator
            .submit_and_persist(&catalog, task, 1)
            .expect_err("generic ingress must not create an unbound compaction"),
        MaintenanceFailure::InvalidInput
    );
    assert!(
        coordinator
            .durable_records()
            .expect("refused ingress has no durable task record")
            .is_empty()
    );
    Ok(())
}

#[test]
fn running_work_reports_the_server_owned_no_progress_deadline_at_its_boundary() {
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::new(
        MaintenanceTaskId::new([0x81; 16]).expect("non-zero stable identity"),
        MaintenanceTaskClass::SchemaStatistics,
    );
    let identity = task.identity();
    coordinator.submit(task).expect("task is accepted");
    coordinator.start_next(1, false).expect("scheduler runs");

    assert_eq!(
        coordinator
            .status_with_progress_slo(identity, Some(60), false)
            .expect("running status")
            .no_durable_progress_slo_breached(),
        Some(false),
        "59 seconds without durable progress remains inside the initial SLO"
    );
    assert_eq!(
        coordinator
            .status_with_progress_slo(identity, Some(61), false)
            .expect("running status")
            .no_durable_progress_slo_breached(),
        Some(true),
        "60 seconds without durable progress is a server-reported breach"
    );
    assert_eq!(
        coordinator
            .status_with_progress_slo(identity, Some(61), true)
            .expect("running status")
            .no_durable_progress_slo_breached(),
        None,
        "an uncertain lifecycle clock cannot invent a healthy or stale deadline fact"
    );
}

#[test]
fn only_an_advancing_durable_checkpoint_resets_the_running_progress_deadline() {
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        0x82,
        MaintenanceTaskClass::SchemaStatistics,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        vec![
            MaintenanceObjectId::new([0x82; 32]).expect("first input"),
            MaintenanceObjectId::new([0x83; 32]).expect("second input"),
        ],
    );
    let identity = task.identity();
    coordinator.submit(task).expect("task is accepted");
    coordinator.start_next(1, false).expect("scheduler runs");
    coordinator
        .checkpoint_at(
            identity,
            MaintenanceCheckpoint::new(1, 1, vec![1]).expect("checkpoint"),
            10,
        )
        .expect("completed input advances durable progress");
    coordinator
        .checkpoint_at(
            identity,
            MaintenanceCheckpoint::new(2, 1, vec![2]).expect("rewritten cursor"),
            30,
        )
        .expect("a non-advancing checkpoint remains durable state");
    assert_eq!(
        coordinator
            .status_with_progress_slo(identity, Some(70), false)
            .expect("running status")
            .no_durable_progress_slo_breached(),
        Some(true),
        "changing only checkpoint metadata or cursor bytes cannot hide a stall"
    );
    coordinator
        .checkpoint_at(
            identity,
            MaintenanceCheckpoint::new(3, 2, vec![3]).expect("checkpoint"),
            71,
        )
        .expect("a further completed input advances durable progress");
    assert_eq!(
        coordinator
            .status_with_progress_slo(identity, Some(130), false)
            .expect("running status")
            .no_durable_progress_slo_breached(),
        Some(false)
    );
}
