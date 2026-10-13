use super::*;
use positron_api::provider_migration::{
    ProviderMigrationRequest, ProviderMigrationServiceClient, ProviderMigrationTransport,
};

#[test]
fn running_provider_migration_requires_administrator_before_configuration_access()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let prepare = br#"{"action":"prepare","expected_catalog_generation":1,"idempotency_key":"11111111-1111-4111-8111-111111111111","configuration_reference":"/unavailable/protected-provider.toml"}"#;
    assert_eq!(
        services.manage_provider_migration(&ingest, prepare),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    let status = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("authorized root status");
    assert_eq!(status.root_phase, "active");
    assert_eq!(status.active_epoch, 1);
    assert!(status.operation.is_none());
    assert_eq!(
        services.manage_provider_migration(&administrator, prepare),
        Err(MaintenanceServiceFailure::InvalidRequest)
    );
    Ok(())
}

#[test]
fn accepted_provider_preparation_recovers_after_task_publication_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let status = services
        .manage_provider_migration(&administrator, br#"{"action":"status"}"#)
        .expect("status");
    let preparation = positron_api::provider_migration::ProviderMigrationRequest {
        action: "prepare".into(),
        expected_catalog_generation: Some(status.catalog_generation),
        idempotency_key: Some("14141414-1414-4414-8414-141414141414".into()),
        configuration_reference: Some(configuration.to_string_lossy().into_owned()),
        operation_id: None,
    }
    .encode()?;
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::RenameMarker, 1, || {
            services.manage_provider_migration(&administrator, &preparation)
        });
    assert_eq!(failure, Err(MaintenanceServiceFailure::TaskUnavailable));
    drop(services);
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(initialized)?;
    let lookup = br#"{"action":"lookup","idempotency_key":"14141414-1414-4414-8414-141414141414"}"#;
    assert_eq!(
        services
            .manage_provider_migration(&administrator, lookup)
            .expect("accepted durable operation")
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("pending")
    );
    for _ in 0..32 {
        let status = services
            .manage_provider_migration(&administrator, lookup)
            .expect("recovered lookup");
        if status
            .operation
            .as_ref()
            .is_some_and(|operation| operation.status == "succeeded")
        {
            break;
        }
        super::super::super::maintenance::wake_runtime_maintenance(&services, None)?;
    }
    let completed = services
        .manage_provider_migration(&administrator, lookup)
        .expect("completed recovered preparation");
    assert_eq!(completed.root_phase, "prepared");
    assert_eq!(
        completed
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("succeeded")
    );
    Ok(())
}

#[path = "provider_migration/lifecycle.rs"]
mod lifecycle;
#[path = "provider_migration/online.rs"]
mod online;

#[path = "provider_migration/failures.rs"]
mod failures;
