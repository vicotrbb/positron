//! Durable operation success survives a retryable task-completion publication.
use super::*;

#[test]
fn root_operation_success_survives_task_completion_publication_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let generation = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .map_err(|e| format!("status {e:?}"))?
        .catalog_generation;
    let accepted = services
        .manage_provider_migration(
            &administrator,
            &positron_api::provider_migration::ProviderMigrationRequest {
                action: "prepare".into(),
                expected_catalog_generation: Some(generation),
                idempotency_key: Some("edededed-eded-4ded-8ded-edededededed".into()),
                configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                operation_id: None,
            }
            .encode()?,
        )
        .map_err(|e| format!("accept prepare {e:?}"))?;
    let lookup = positron_api::provider_migration::ProviderMigrationRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        configuration_reference: None,
        operation_id: Some(accepted.operation.ok_or("accepted operation")?.id),
    }
    .encode()?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancel = cancellation.clone();
    let worker = std::thread::spawn(move || {
        positron_kernel::with_catalog_publication_fault_sequence_after(
            &[
                (CatalogPublicationFault::RenameMarker, 5),
                (CatalogPublicationFault::RenameMarker, 0),
                (CatalogPublicationFault::RenameMarker, 0),
                (CatalogPublicationFault::RenameMarker, 0),
            ],
            || worker_services.run_maintenance_worker(&worker_cancel),
        )
    });
    let observed = (|| -> Result<_, Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut success_with_running_task = false;
        loop {
            let operation = match services.manage_provider_migration(&administrator, &lookup) {
                Ok(operation) => operation,
                Err(MaintenanceServiceFailure::CapacityUnavailable)
                    if !worker.is_finished() && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                },
                Err(failure) => return Err(format!("lookup {failure:?}").into()),
            };
            let tasks = match services.maintenance_status(&administrator, br"{}") {
                Ok(tasks) => tasks,
                Err(MaintenanceServiceFailure::CapacityUnavailable)
                    if !worker.is_finished() && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                },
                Err(failure) => return Err(format!("tasks {failure:?}").into()),
            };
            let task = tasks
                .tasks
                .iter()
                .find(|task| task.class == "migration")
                .ok_or("migration task")?;
            if operation
                .operation
                .as_ref()
                .is_some_and(|op| op.status == "succeeded")
            {
                success_with_running_task |= task.phase == "running";
                if task.phase == "succeeded" {
                    return Ok((success_with_running_task, operation.root_phase));
                }
            }
            if worker.is_finished() || std::time::Instant::now() >= deadline {
                return Err(
                    format!("completion publication deadline: {operation:?}; {tasks:?}").into(),
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    cancellation.cancel();
    worker.join().map_err(|_| "worker panic")??;
    let (success_with_running_task, phase) = observed?;
    assert!(
        success_with_running_task,
        "fault did not reach the post-success task publication"
    );
    assert_eq!(phase, "prepared");
    Ok(())
}
