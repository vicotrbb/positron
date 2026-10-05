use super::*;
use positron_domain::identity::TenantId;

#[test]
fn conflicting_copy_on_write_work_waits_for_the_running_owner_across_scopes() {
    let coordinator = MaintenanceCoordinator::new();
    let input = MaintenanceObjectId::new([3; 32]).expect("object identity");
    let first = task(
        1,
        MaintenanceTaskClass::SchemaStatistics,
        MaintenanceTrigger::Event,
        MaintenancePriority::Ordinary,
        vec![input],
    );
    let mut second = task(
        2,
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        vec![input],
    );
    second.scope =
        MaintenanceScope::tenant(TenantId::from_bytes([4; 16]).expect("tenant identity"));
    let second_identity = second.identity();
    coordinator
        .submit_at(first.clone(), 1)
        .expect("system task accepted");
    coordinator
        .submit_at(second.clone(), 2)
        .expect("tenant task accepted");

    assert_eq!(
        coordinator.start_next(3, false).expect("first starts"),
        Some(second)
    );
    assert_eq!(
        coordinator
            .start_next(4, false)
            .expect("object conflict is evaluated"),
        None,
        "the same immutable object cannot be read or written concurrently across scopes"
    );
    let blocked = coordinator
        .statuses()
        .expect("bounded public coordinator statuses")
        .into_iter()
        .find(|status| status.task().identity() == first.identity())
        .expect("blocked task remains visible");
    assert_eq!(
        blocked.conflict_owner(),
        Some(second_identity),
        "the status identifies the running conflict owner without exposing its object"
    );
    coordinator
        .complete(
            MaintenanceTaskId::new([2; 16]).expect("task identity"),
            true,
        )
        .expect("complete owner");
    assert_eq!(
        coordinator.start_next(5, false).expect("unblocked"),
        Some(first)
    );
}

#[test]
fn clock_uncertain_inspection_reports_the_same_destructive_schedule_blocker_as_dispatch() {
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        9,
        MaintenanceTaskClass::RetentionReclamation,
        MaintenanceTrigger::Scheduled,
        MaintenancePriority::Urgent,
        Vec::new(),
    );
    let identity = task.identity();
    coordinator
        .submit_at(task, 1)
        .expect("scheduled task accepted");

    assert!(
        coordinator
            .status_with_clock_uncertainty(identity, true)
            .expect("inspection status")
            .clock_uncertain_blocked(),
        "inspection must expose the scheduler's ClockUncertain blocker"
    );
    assert_eq!(
        coordinator.start_next(2, true).expect("scheduler result"),
        None,
        "dispatch applies the same blocker"
    );
    assert!(
        !coordinator
            .status_with_clock_uncertainty(identity, false)
            .expect("certain status")
            .clock_uncertain_blocked()
    );
}
