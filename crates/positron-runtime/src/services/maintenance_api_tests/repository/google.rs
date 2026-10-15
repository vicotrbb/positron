//! Admission and canonical wire behavior, without credential/provider work.
use super::*;
#[test]
fn google_repository_admission_binds_native_target_without_provider_io()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::services::repository_administration::RepositoryLocation;
    use positron_governance::RepositoryProviderKind;
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let target = positron_backup::GoogleCloudStorageTarget::new(
        "positron-example",
        "123456789012",
        "US-CENTRAL1",
        "diagnostic/",
    )?;
    let generation = services
        .open_maintenance_catalog()
        .expect("catalog")
        .pin()?
        .number();
    let input = RepositoryAdmission {
        action: RepositoryAction::Doctor,
        locator: RepositoryLocation::GoogleCloudStorage(&target),
        repository: [101; 16],
        expected_generation: generation,
        idempotency: AdministrativeIdempotencyKey::new([102; 16])?,
    };
    assert_eq!(
        services.accept_repository_operation(&ingest, input),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    let operation = services
        .accept_repository_operation(&administrator, input)
        .expect("accepted native target");
    let parameters = operation
        .repository_parameters()
        .ok_or("missing parameters")?;
    assert_eq!(
        parameters.provider_kind(),
        RepositoryProviderKind::GoogleCloudStorage
    );
    assert_eq!(parameters.prefix_commitment(), target.commitment());
    assert_eq!(operation.status(), DurableOperationStatus::Pending);
    assert_eq!(
        services
            .accept_repository_operation(&administrator, input)
            .expect("accepted native target")
            .operation_id(),
        operation.operation_id()
    );
    let request = positron_api::repository::RepositoryRequest {
        action: "doctor".into(),
        expected_catalog_generation: Some(generation),
        idempotency_key: Some("66666666-6666-4666-8666-666666666666".into()),
        locator: None,
        repository_id: Some("65656565-6565-4565-8565-656565656565".into()),
        operation_id: None,
        aws_s3: None,
        google_cloud_storage: Some(
            positron_api::repository::RepositoryGoogleCloudStorageTarget {
                bucket: target.bucket().into(),
                project_number: target.project_number().into(),
                location: target.location().into(),
                prefix: target.prefix().into(),
            },
        ),
    };
    let mut request = request;
    request.expected_catalog_generation = Some(
        services
            .open_maintenance_catalog()
            .expect("current catalog")
            .pin()?
            .number(),
    );
    let native_response = services
        .manage_repository(&administrator, &request.encode()?)
        .expect("native canonical request");
    assert_eq!(
        native_response
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("pending")
    );
    let mut refused = false;
    for _ in 0..32 {
        match crate::services::maintenance::wake_runtime_maintenance(&services, None) {
            Err(crate::ServiceFailure::CapacityUnavailable) => {
                refused = true;
                break;
            },
            Ok(_) => {},
            Err(failure) => return Err(format!("unexpected dispatch failure: {failure:?}").into()),
        }
        assert_eq!(
            services
                .repository_operation_status(&administrator, operation.operation_id())
                .expect("native receipt")
                .status(),
            DurableOperationStatus::Pending
        );
    }
    assert!(
        refused,
        "native transport must be admitted before provider work"
    );
    Ok(())
}
