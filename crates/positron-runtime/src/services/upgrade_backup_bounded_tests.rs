//! Cold bounded turns must converge using only authenticated durable child progress.
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperationAdministration as Administration,
    DurableOperationStatus,
};
use std::time::{Duration, Instant};

#[test]
fn upgrade_verification_completes_after_each_native_turn_expires_and_reopens()
-> Result<(), Box<dyn std::error::Error>> {
    cold_verification_after_expiry(
        crate::services::backup_administration::StopPoint::VerificationNativeFileVerified,
        2,
    )
}

#[test]
fn upgrade_verification_finishes_after_metadata_turn_expires_and_reopens()
-> Result<(), Box<dyn std::error::Error>> {
    cold_verification_after_expiry(
        crate::services::backup_administration::StopPoint::VerificationMetadataVerified,
        1,
    )
}

fn cold_verification_after_expiry(
    point: crate::services::backup_administration::StopPoint,
    minimum_turns: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::services::backup_administration::expire_turn_after;
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = crate::services::tests::schema_maintenance::Fixture::new()?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let export = fixture.recovery_export_directory()?;
    let identity = age::x25519::Identity::generate();
    let bundle = export.join("cold-native-turns.age");
    instance.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[identity.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(
        &bundle,
        positron_kernel::RecoveryUnlock::Identity(&identity),
    )?;
    let services = super::super::ServiceHandle::new(instance.clone())?;
    super::tests::initialize_registered_repository(&instance, &services, &administrator, &export)?;
    let snapshot = {
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        Administration::inspect_by_idempotency(
            &catalog,
            AdministrativeIdempotencyKey::new([22; 16])?,
        )?
        .ok_or("completed registered snapshot")?
    };
    let actor = services
        .authorize_system_administration(&administrator)
        .map_err(|failure| format!("actor: {failure:?}"))?;
    let mut operation = services.accept_upgrade_verification(
        actor,
        snapshot,
        AdministrativeIdempotencyKey::new([0x91; 16])?,
        super::tests::generation(&instance)?,
    )?;
    drop((services, instance));
    let mut native_turns = 0;
    let mut last_checkpoint = None;
    for _ in 0..128 {
        let (instance, services) =
            ready_cold_services(&fixture, operation.updated_at_unix_seconds())?;
        let boundary = expire_turn_after(
            instance.instance.to_bytes(),
            operation.operation_id().to_bytes(),
            point,
        )?;
        operation = services
            .drive_upgrade_backup_operation(operation.operation_id(), Instant::now() + Duration::from_secs(30))
            .map_err(|failure| format!("cold bounded verification must preserve successful native progress: {failure:?}"))?;
        native_turns += usize::from(boundary.observed());
        let status = instance
            .maintenance_coordinator()
            .status(
                positron_kernel::MaintenanceTaskId::new(operation.operation_id().to_bytes())
                    .map_err(|failure| format!("task identity: {failure:?}"))?,
            )
            .map_err(|failure| format!("task status: {failure:?}"))?;
        let checkpoint = status
            .checkpoint()
            .map(|checkpoint| checkpoint.opaque_progress().to_vec());
        assert!(
            operation.status().is_terminal()
                || boundary.observed()
                || checkpoint != last_checkpoint,
            "a cold turn must publish progress or complete its public verification outcome"
        );
        last_checkpoint = checkpoint;
        if operation.status().is_terminal() {
            break;
        }
    }
    assert!(
        native_turns >= minimum_turns,
        "verification crossed the requested genuine native turn boundaries"
    );
    assert_eq!(operation.status(), DurableOperationStatus::Succeeded);
    assert!(operation.backup_verification_report().is_some());
    Ok(())
}

#[test]
fn upgrade_bounded_verification_turns_survive_cold_service_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = crate::services::tests::schema_maintenance::Fixture::new()?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let export = fixture.recovery_export_directory()?;
    let identity = age::x25519::Identity::generate();
    let bundle = export.join("bounded.age");
    instance.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[identity.to_public().to_string()])?,
    )?;
    instance.verify_recovery_bundle(
        &bundle,
        positron_kernel::RecoveryUnlock::Identity(&identity),
    )?;
    let services = super::super::ServiceHandle::new(instance.clone())?;
    super::tests::initialize_registered_repository(&instance, &services, &administrator, &export)?;
    let snapshot = {
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        Administration::inspect_by_idempotency(
            &catalog,
            AdministrativeIdempotencyKey::new([22; 16])?,
        )?
        .ok_or("completed registered snapshot")?
    };
    assert_eq!(snapshot.status(), DurableOperationStatus::Succeeded);
    let actor = services
        .authorize_system_administration(&administrator)
        .map_err(|e| format!("actor {e:?}"))?;
    let verification = services.accept_upgrade_verification(
        actor,
        snapshot,
        AdministrativeIdempotencyKey::new([0x82; 16])?,
        super::tests::generation(&instance)?,
    )?;
    // The authenticated operation can be ahead of a conservatively recovered
    // LifecycleClock; install that persisted state without changing its clock.
    let verification = {
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        Administration::begin(
            &catalog,
            actor,
            verification.operation_id(),
            verification
                .updated_at_unix_seconds()
                .checked_add(60)
                .ok_or("clock range")?,
        )?
    };
    drop(services);
    drop(instance);
    let mut last = verification;
    let task = positron_kernel::MaintenanceTaskId::new(last.operation_id().to_bytes())
        .map_err(|e| format!("task {e:?}"))?;
    {
        let instance = fixture.reopen()?;
        let services = super::super::ServiceHandle::new(instance.clone())?;
        let before = instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|e| format!("status {e:?}"))?;
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        let basis = catalog.pin()?.identity();
        drop(catalog);
        assert!(instance.retention_time.governance_now_seconds()? < last.updated_at_unix_seconds());
        let result = services.drive_upgrade_backup_operation(
            last.operation_id(),
            Instant::now() + Duration::from_secs(1),
        );
        assert!(
            matches!(result, Err(crate::UpgradeFailure::CapacityUnavailable)),
            "ineligible result: {result:?}"
        );
        assert_eq!(
            instance
                .maintenance_coordinator()
                .status(task)
                .map_err(|e| format!("status {e:?}"))?,
            before
        );
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        assert_eq!(catalog.pin()?.identity(), basis);
        assert_eq!(
            Administration::inspect(&catalog, last.operation_id())?,
            Some(last)
        );
    }
    let stopped_resources = {
        use crate::services::backup_administration::{StopPoint, stop_after};
        let (instance, services) = ready_cold_services(&fixture, last.updated_at_unix_seconds())?;
        let stop = stop_after(
            services.instance.instance.to_bytes(),
            last.operation_id().to_bytes(),
            StopPoint::VerificationNativeFileVerified,
        )?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut stopped = false;
        for _ in 0..4 {
            match services.drive_upgrade_backup_operation(last.operation_id(), deadline) {
                Err(crate::UpgradeFailure::SnapshotUnavailable) => {
                    assert!(
                        stop.observed(),
                        "only the exact native-file stop explains this refusal"
                    );
                    stopped = true;
                    break;
                },
                Ok(operation) => {
                    assert!(
                        !operation.status().is_terminal(),
                        "the native-file stop must precede completion"
                    );
                },
                Err(error) => return Err(error.into()),
            }
        }
        assert!(
            stopped,
            "the bounded turn must authenticate an actual native file"
        );
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        last = Administration::inspect(&catalog, last.operation_id())?
            .ok_or("stopped verification")?;
        assert!(!last.status().is_terminal());
        assert!(last.backup_verification_report().is_none());
        let status = instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|e| format!("stopped task {e:?}"))?;
        let checkpoint = status
            .checkpoint()
            .ok_or("authenticated remote checkpoint")?
            .opaque_progress()
            .to_vec();
        (status.task().reservations(), checkpoint)
    };
    let mut expected_cold_resources = Some(stopped_resources.0);
    let mut expected_cold_checkpoint = Some(stopped_resources.1);
    for _ in 0..32 {
        let (instance, services) = ready_cold_services(&fixture, last.updated_at_unix_seconds())?;
        let before_resources = instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|e| format!("status {e:?}"))?
            .task()
            .reservations();
        if let Some(expected) = expected_cold_resources {
            assert_eq!(
                before_resources, expected,
                "cold reopen must retain exact readmission bounds"
            );
        }
        let before = instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|e| format!("status {e:?}"))?
            .checkpoint()
            .map(|checkpoint| checkpoint.opaque_progress().to_vec());
        if let Some(expected) = expected_cold_checkpoint.take() {
            assert_eq!(
                before.as_deref(),
                Some(expected.as_slice()),
                "cold reopen must retain the authenticated stopped checkpoint"
            );
        }
        let result = services.drive_upgrade_backup_operation(
            last.operation_id(),
            Instant::now() + Duration::from_secs(1),
        );
        let status = instance
            .maintenance_coordinator()
            .status(task)
            .map_err(|e| format!("status {e:?}"))?;
        let after = status
            .checkpoint()
            .map(|checkpoint| checkpoint.opaque_progress().to_vec());
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        let current =
            Administration::inspect(&catalog, last.operation_id())?.ok_or("current child")?;
        drop(catalog);
        match result {
            Err(crate::UpgradeFailure::CapacityUnavailable) => {
                assert_eq!(
                    current, last,
                    "insufficient turn preserves exact intent and lifecycle"
                );
                assert_eq!(before, after, "no semantic checkpoint progress");
                assert_eq!(
                    status.task().reservations(),
                    before_resources,
                    "a refused turn cannot claim readmission progress"
                );
                assert_eq!(
                    status.phase(),
                    positron_kernel::MaintenanceTaskPhase::Queued
                );
                break;
            },
            Ok(operation) => {
                let after_resources = status.task().reservations();
                let readmitted = before_resources != after_resources;
                if readmitted {
                    assert_eq!(
                        status.phase(),
                        positron_kernel::MaintenanceTaskPhase::Queued
                    );
                    eprintln!(
                        "cold_verification_readmission before={before_resources:?} after={after_resources:?}"
                    );
                    assert!(
                        positron_kernel::ResourceDimension::ALL
                            .iter()
                            .all(|dimension| after_resources.get(*dimension)
                                >= before_resources.get(*dimension)),
                        "readmission preserves every previously admitted resource peak"
                    );
                    assert!(
                        positron_kernel::ResourceDimension::ALL
                            .iter()
                            .any(|dimension| after_resources.get(*dimension)
                                > before_resources.get(*dimension)),
                        "readmission must strictly increase an actual resource demand"
                    );
                    assert!(
                        after_resources.get(positron_kernel::ResourceDimension::MemoryBytes) > 0
                    );
                    assert!(
                        after_resources.get(positron_kernel::ResourceDimension::DiskHeadroomBytes)
                            > 0,
                        "native continuation has a durable storage reservation"
                    );
                    // The next cold turn must use exactly this published grant;
                    // its authenticated native resume must converge successfully.
                    expected_cold_resources = Some(after_resources);
                }
                assert!(
                    operation.revision() != last.revision() || before != after || readmitted,
                    "a turn with no durable progress must report retryable capacity"
                );
                last = operation;
                if last.status().is_terminal() {
                    assert_eq!(last.status(), DurableOperationStatus::Succeeded);
                    break;
                }
            },
            Err(error) => return Err(error.into()),
        }
    }
    for turn in 0..4 {
        let (instance, services) = ready_cold_services(&fixture, last.updated_at_unix_seconds())?;
        last = services
            .drive_upgrade_backup_operation(
                last.operation_id(),
                Instant::now() + Duration::from_secs(30),
            )
            .map_err(|error| {
                format!(
                    "long turn {turn}: {error:?}; operation={last:?}; clock={:?}; task={:?}",
                    instance.retention_time.status(),
                    instance.maintenance_coordinator().status(task)
                )
            })?;
        if last.status().is_terminal() {
            break;
        }
    }
    assert_eq!(
        last.status(),
        DurableOperationStatus::Succeeded,
        "documented cold turn must converge: {last:?}"
    );
    assert!(last.backup_verification_report().is_some());
    Ok(())
}

#[test]
fn retained_owner_waits_for_genuine_elapsed_time_without_catalog_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = crate::services::tests::schema_maintenance::Fixture::new()?;
    let (instance, _, _, _) = fixture.initialized_with_admin()?;
    let target = instance
        .retention_time
        .governance_now_seconds()?
        .checked_add(1)
        .ok_or("clock range")?;
    let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
    let basis = catalog.pin()?.identity();
    crate::upgrade::await_lifecycle_time(
        &instance,
        target,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )?;
    assert!(instance.retention_time.governance_now_seconds()? >= target);
    assert_eq!(catalog.pin()?.identity(), basis);
    Ok(())
}

// Cursor tests isolate work recovery from conservative cold time eligibility.
// Advance only after ServiceHandle has recovered the canonical Catalog anchor.
fn ready_cold_services(
    fixture: &crate::services::tests::schema_maintenance::Fixture,
    updated_at: u64,
) -> Result<
    (
        std::sync::Arc<crate::InitializedInstance>,
        super::super::ServiceHandle,
    ),
    Box<dyn std::error::Error>,
> {
    let (instance, elapsed, _) = super::tests::reopen_with_trusted_test_clock(fixture)?;
    let services = super::super::ServiceHandle::new(instance.clone())?;
    let trusted = instance.retention_time.governance_now_seconds()?;
    if trusted < updated_at {
        elapsed.advance((updated_at - trusted + 1) * 1_000_000_000)?;
    }
    Ok((instance, services))
}
