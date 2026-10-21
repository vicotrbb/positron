use super::*;
use crate::services::repository_administration::RepositoryAdmission;
use positron_governance::{AdministrativeIdempotencyKey, DurableOperationStatus, RepositoryAction};
use std::os::unix::fs::PermissionsExt;
#[test]
fn repository_status_recovers_after_catalog_writer_contention()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::repository::{
        RepositoryRequest, RepositoryServiceClient, RepositoryServiceClientFailure,
        RepositoryTransport,
    };
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    drop(initialized);
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint")?;
    let client = RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint })?;
    let request = RepositoryRequest::decode(br#"{"action":"status"}"#)?;
    assert_eq!(
        client.manage(&ingest, &request),
        Err(RepositoryServiceClientFailure::AuthenticationRejected),
    );
    let services = process.services().ok_or("serving services")?;
    // Retain the actual sole-writer lease, without retaining the API gate.
    // The diagnostic read must expose temporary unavailability, not replace
    // that writer or misclassify the already valid credential.
    let writer = {
        let _gate = services.catalog_operation()?;
        open_catalog(&services.instance)?
    };
    assert_eq!(
        client.manage(&administrator, &request),
        Err(RepositoryServiceClientFailure::AdministrationUnavailable),
    );
    drop(writer);
    let recovered = client.manage(&administrator, &request)?;
    assert!(recovered.operation.is_none());
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful,
    );
    Ok(())
}

#[test]
fn serving_repository_initialize_and_doctor_are_authenticated_durable_tasks()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-runtime-repository-{}",
        std::process::id()
    ));
    std::fs::create_dir(&repository_path)?;
    std::fs::set_permissions(&repository_path, std::fs::Permissions::from_mode(0o700))?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let generation = services
        .open_maintenance_catalog()
        .expect("catalog")
        .pin()?
        .number();
    let admission = RepositoryAdmission {
        action: RepositoryAction::Initialize,
        locator: crate::services::repository_administration::RepositoryLocation::Local(
            &repository_path,
        ),
        repository: [91; 16],
        expected_generation: generation,
        idempotency: AdministrativeIdempotencyKey::new([92; 16])?,
    };
    assert_eq!(
        services.accept_repository_operation(&ingest, admission),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    assert_eq!(std::fs::read_dir(&repository_path)?.count(), 0);
    let stale = RepositoryAdmission {
        expected_generation: generation
            .checked_sub(1)
            .filter(|value| *value > 0)
            .ok_or("fixture stale generation")?,
        ..admission
    };
    assert_eq!(
        services.accept_repository_operation(&administrator, stale),
        Err(MaintenanceServiceFailure::StaleGeneration)
    );
    assert_eq!(std::fs::read_dir(&repository_path)?.count(), 0);

    let accepted = services
        .accept_repository_operation(&administrator, admission)
        .expect("accepted initialization");
    assert_eq!(accepted.status(), DurableOperationStatus::Pending);
    for _ in 0..32 {
        let operation = services
            .repository_operation_status(&administrator, accepted.operation_id())
            .expect("initialization status");
        if operation.status().is_terminal() {
            break;
        }
        crate::services::maintenance::wake_runtime_maintenance(&services, None)?;
    }
    assert_eq!(
        services
            .repository_operation_status(&administrator, accepted.operation_id())
            .expect("initialization status")
            .status(),
        DurableOperationStatus::Succeeded
    );
    let generation = services
        .open_maintenance_catalog()
        .expect("catalog")
        .pin()?
        .number();
    let doctor = services
        .accept_repository_operation(
            &administrator,
            RepositoryAdmission {
                action: RepositoryAction::Doctor,
                expected_generation: generation,
                idempotency: AdministrativeIdempotencyKey::new([93; 16])?,
                ..admission
            },
        )
        .expect("accepted doctor");
    for _ in 0..32 {
        let operation = services
            .repository_operation_status(&administrator, doctor.operation_id())
            .expect("doctor status");
        if operation.status().is_terminal() {
            break;
        }
        crate::services::maintenance::wake_runtime_maintenance(&services, None)?;
    }
    assert_eq!(
        services
            .repository_operation_status(&administrator, doctor.operation_id())
            .expect("doctor status")
            .status(),
        DurableOperationStatus::Succeeded
    );
    assert_eq!(
        services
            .repository_operation_status(&administrator, doctor.operation_id())
            .expect("doctor policy receipt")
            .repository_policy(),
        Some(positron_backup::RepositoryPolicy {
            soft_delete: None,
            doctor_probe: Some(positron_backup::ObjectProtection::unobservable()),
            ..positron_backup::RepositoryPolicy::local()
        })
    );
    assert_eq!(
        services
            .repository_operation_status(&administrator, accepted.operation_id())
            .expect("initialization policy receipt")
            .repository_policy(),
        Some(positron_backup::RepositoryPolicy::local())
    );
    assert_eq!(std::fs::read_dir(&repository_path)?.count(), 1);
    let catalog = services
        .open_maintenance_catalog()
        .expect("reclamation catalog");
    let session = positron_kernel::RootRewrapSession::admit(&services.instance._authority)?;
    services
        .instance
        .maintenance_coordinator()
        .reclaim_terminal_records_for_root_retirement(&session, &catalog)
        .expect("reference-free terminal reclamation");
    for id in [accepted.operation_id(), doctor.operation_id()] {
        assert!(matches!(
            services.instance.maintenance_coordinator().status(
                positron_kernel::MaintenanceTaskId::new(id.to_bytes()).expect("task identity")
            ),
            Err(positron_kernel::MaintenanceFailure::UnknownTask)
        ));
    }
    drop(session);
    drop(catalog);
    assert_eq!(
        services
            .repository_operation_status(&administrator, doctor.operation_id())
            .expect("terminal receipt retained")
            .status(),
        DurableOperationStatus::Succeeded
    );

    std::fs::remove_dir_all(repository_path)?;
    Ok(())
}

#[test]
fn accepted_repository_initialization_recovers_task_publication_gap_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let path = std::env::temp_dir().join(format!("positron-repository-gap-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let generation = services
        .open_maintenance_catalog()
        .expect("catalog")
        .pin()?
        .number();
    let key = AdministrativeIdempotencyKey::new([95; 16])?;
    let admission = RepositoryAdmission {
        action: RepositoryAction::Initialize,
        locator: crate::services::repository_administration::RepositoryLocation::Local(&path),
        repository: [96; 16],
        expected_generation: generation,
        idempotency: key,
    };
    let result =
        with_catalog_publication_fault_after(CatalogPublicationFault::RenameMarker, 1, || {
            services.accept_repository_operation(&administrator, admission)
        });
    assert_eq!(result, Err(MaintenanceServiceFailure::TaskUnavailable));
    assert_eq!(std::fs::read_dir(&path)?.count(), 0);
    drop(services);
    let services = ServiceHandle::new(fixture.reopen()?)?;
    let accepted = services
        .repository_operation_by_idempotency(&administrator, key)
        .expect("accepted operation survives gap");
    assert_eq!(accepted.status(), DurableOperationStatus::Pending);
    for _ in 0..32 {
        if services
            .repository_operation_status(&administrator, accepted.operation_id())
            .expect("operation status")
            .status()
            .is_terminal()
        {
            break;
        }
        crate::services::maintenance::wake_runtime_maintenance(&services, None)?;
    }
    let completed = services
        .repository_operation_status(&administrator, accepted.operation_id())
        .expect("completed status");
    assert_eq!(completed.status(), DurableOperationStatus::Succeeded);
    drop(services);
    let services = ServiceHandle::new(fixture.reopen()?)?;
    assert_eq!(
        services
            .repository_operation_by_idempotency(&administrator, key)
            .expect("terminal lookup survives reopen"),
        completed
    );
    assert_eq!(std::fs::read_dir(&path)?.count(), 1);
    std::fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn native_admin_http_exposes_repository_lifecycle_and_redacted_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::repository::{
        RepositoryRequest, RepositoryServiceClient, RepositoryTransport,
    };
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let path =
        std::env::temp_dir().join(format!("positron-repository-http-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    drop(initialized);
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint")?;
    // Dispatch opens its Catalog before reserving the provider peak. Prove
    // the canonical authority admits that overlap with native listeners live.
    let services = process.services().ok_or("native repository services")?;
    {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&services.instance)?;
        let resources = crate::services::repository_administration::repository_resources(
            positron_governance::RepositoryProviderKind::LocalFilesystem,
        );
        let claim = positron_kernel::WorkClaim::backup_repository_read(resources)?;
        let governor = services.instance.resource_governor();
        let admission_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let reservation = loop {
            match governor.reserve(claim.clone()) {
                Ok(reservation) => break reservation,
                Err(failure)
                    if failure.code() == positron_kernel::AdmissionFailureCode::GovernorContended
                        && failure.completion_state()
                            == positron_kernel::AdmissionCompletionState::RejectedBeforeReservation
                        && std::time::Instant::now() < admission_deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                },
                Err(failure) => {
                    return Err(format!(
                        "canonical native repository dispatch admission: {failure:?}"
                    )
                    .into());
                },
            }
        };
        drop(reservation);
        drop(catalog);
    }
    let client = RepositoryServiceClient::new(RepositoryTransport::PlaintextOptOut { endpoint })?;
    let status = RepositoryRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        aws_s3: None,
        google_cloud_storage: None,
        azure_blob: None,
        locator: None,
        repository_id: None,
        operation_id: None,
    };
    assert!(client.manage(&ingest, &status).is_err());
    let current = client
        .manage(&administrator, &status)
        .map_err(|failure| format!("repository HTTP stage=initial-status: {failure:?}"))?;
    let mut request = RepositoryRequest {
        action: "init".into(),
        expected_catalog_generation: Some(current.catalog_generation),
        idempotency_key: Some("61616161-6161-4161-8161-616161616161".into()),
        aws_s3: None,
        google_cloud_storage: None,
        azure_blob: None,
        locator: Some(path.to_string_lossy().into_owned()),
        repository_id: Some("62626262-6262-4262-8262-626262626262".into()),
        operation_id: None,
    };
    let admission_deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut accepted = loop {
        match client.manage(&administrator, &request) {
            Ok(accepted) => break accepted,
            Err(positron_api::repository::RepositoryServiceClientFailure::StaleGeneration)
                if std::time::Instant::now() < admission_deadline =>
            {
                request.expected_catalog_generation = Some(
                    client
                        .manage(&administrator, &status)
                        .map_err(|failure| {
                            format!("repository HTTP stage=generation-refresh: {failure:?}")
                        })?
                        .catalog_generation,
                );
            },
            Err(error) => {
                return Err(format!("repository HTTP stage=init-admission: {error:?}").into());
            },
        }
    };
    let id = accepted
        .operation
        .as_ref()
        .ok_or("missing durable operation")?
        .id
        .clone();
    let query = RepositoryRequest {
        operation_id: Some(id),
        ..status
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while accepted
        .operation
        .as_ref()
        .is_some_and(|operation| matches!(operation.status.as_str(), "pending" | "running"))
    {
        if std::time::Instant::now() >= deadline {
            let _gate = services.catalog_operation()?;
            let catalog = open_catalog(&services.instance)?;
            let claim = positron_kernel::WorkClaim::backup_repository_read(
                crate::services::repository_administration::repository_resources(
                    positron_governance::RepositoryProviderKind::LocalFilesystem,
                ),
            )?;
            let governor = services.instance.resource_governor();
            let admission = governor.reserve(claim);
            return Err(format!(
                "Repository HTTP completion deadline; native admission={:?}; tasks={:?}; catalog_generation={}",
                admission.as_ref().err(),
                services.instance.maintenance_coordinator().statuses(),
                catalog.pin()?.number(),
            ).into());
        }
        std::thread::sleep(Duration::from_millis(25));
        accepted = client
            .manage(&administrator, &query)
            .map_err(|failure| format!("repository HTTP stage=operation-status: {failure:?}"))?;
    }
    assert_eq!(
        accepted
            .operation
            .as_ref()
            .map(|operation| operation.status.as_str()),
        Some("succeeded")
    );
    assert_eq!(
        accepted
            .identity
            .as_ref()
            .map(|identity| identity.provider_kind.as_str()),
        Some("local_filesystem")
    );
    let policy = accepted
        .policy
        .as_ref()
        .ok_or("missing native policy receipt")?;
    assert_eq!(policy.versioning.state, "unobservable");
    assert_eq!(policy.object_lock.state, "unobservable");
    assert_eq!(policy.lifecycle.state, "unobservable");
    assert!(policy.observed_at_unix_seconds > 0);
    let encoded = accepted.encode()?;
    let output = std::str::from_utf8(&encoded)?;
    assert!(!output.contains(path.to_string_lossy().as_ref()));
    assert!(!output.contains(&administrator));
    assert!(!output.contains(&ingest));
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    std::fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn repository_pending_cancellation_replay_and_creator_lookup_survive_restart()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::repository::RepositoryRequest;
    let fixture = Fixture::new()?;
    let path =
        std::env::temp_dir().join(format!("positron-repository-cancel-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let request = RepositoryRequest {
        action: "init".into(),
        expected_catalog_generation: Some(
            services
                .open_maintenance_catalog()
                .expect("catalog")
                .pin()?
                .number(),
        ),
        idempotency_key: Some("81818181-8181-4181-8181-818181818181".into()),
        repository_id: Some("82828282-8282-4282-8282-828282828282".into()),
        aws_s3: None,
        google_cloud_storage: None,
        azure_blob: None,
        locator: Some(path.to_string_lossy().into_owned()),
        operation_id: None,
    };
    let encoded = request.encode()?;
    let accepted = services
        .manage_repository(&administrator, &encoded)
        .expect("accepted");
    assert_eq!(
        services.manage_repository(&ingest, &encoded),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    let mut conflict = request.clone();
    conflict.repository_id = Some("83838383-8383-4383-8383-838383838383".into());
    assert_eq!(
        services.manage_repository(&administrator, &conflict.encode()?),
        Err(MaintenanceServiceFailure::IdempotencyConflict)
    );
    let id = accepted.operation.as_ref().expect("operation").id.clone();
    let cancel = RepositoryRequest {
        action: "cancel".into(),
        expected_catalog_generation: Some(accepted.catalog_generation),
        idempotency_key: Some("84848484-8484-4484-8484-848484848484".into()),
        operation_id: Some(id.clone()),
        aws_s3: None,
        google_cloud_storage: None,
        azure_blob: None,
        locator: None,
        repository_id: None,
    };
    let cancelled = services
        .manage_repository(&administrator, &cancel.encode()?)
        .expect("cancelled");
    assert_eq!(
        cancelled.operation.as_ref().map(|op| op.status.as_str()),
        Some("cancelled")
    );
    assert_eq!(
        services
            .manage_repository(&administrator, &cancel.encode()?)
            .expect("cancel retry")
            .operation,
        cancelled.operation
    );
    assert_eq!(std::fs::read_dir(&path)?.count(), 0);
    drop(services);
    let reopened = ServiceHandle::new(fixture.reopen()?)?;
    let query = RepositoryRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        aws_s3: None,
        google_cloud_storage: None,
        azure_blob: None,
        locator: None,
        repository_id: None,
        operation_id: Some(id),
    };
    assert_eq!(
        reopened
            .manage_repository(&administrator, &query.encode()?)
            .expect("terminal lookup")
            .operation,
        cancelled.operation
    );
    crate::services::maintenance::wake_runtime_maintenance(&reopened, None)?;
    assert_eq!(std::fs::read_dir(&path)?.count(), 0);
    std::fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn accepted_repository_work_fails_closed_when_native_requesters_grant_is_revoked()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let path = std::env::temp_dir().join(format!(
        "positron-repository-revoked-{}",
        std::process::id()
    ));
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let generation = services
        .open_maintenance_catalog()
        .expect("catalog")
        .pin()?
        .number();
    let accepted = services
        .accept_repository_operation(
            &administrator,
            RepositoryAdmission {
                action: RepositoryAction::Initialize,
                locator: crate::services::repository_administration::RepositoryLocation::Local(
                    &path,
                ),
                repository: [131; 16],
                expected_generation: generation,
                idempotency: AdministrativeIdempotencyKey::new([132; 16])?,
            },
        )
        .expect("accepted");
    // The owning persistent credential schema permits a revoked grant. The
    // operator API deliberately has no system-credential rotation surface.
    {
        let catalog = services
            .open_maintenance_catalog()
            .expect("credential fixture catalog");
        let basis = catalog.pin()?;
        let (identity, governance) = basis.governance_object()?;
        let credentials = governance
            .credentials()
            .iter()
            .map(|credential| {
                if credential.scope_code() == 4 {
                    credential.with_active(false)
                } else {
                    *credential
                }
            })
            .collect::<Vec<_>>();
        let changed = positron_kernel::CatalogObject::new(
            governance.with_credentials(governance.credential_generation() + 1, &credentials)?,
        )?;
        let mut objects = basis
            .object_identities()
            .map(|identity| {
                let bytes = basis.object(identity)?.expect("fixture object missing");
                positron_kernel::CatalogObject::new(bytes.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        objects.retain(|object| object.identity() != identity);
        objects.push(changed);
        catalog.commit(
            basis.identity(),
            positron_kernel::CatalogProposal::new(
                positron_kernel::TransactionId::new([0xd3; 16])?,
                positron_kernel::FormatEpoch::CATALOG_V1,
                objects,
            )?,
            None,
        )?;
    }

    crate::services::maintenance::wake_runtime_maintenance(&services, None)?;
    let catalog = services
        .open_maintenance_catalog()
        .expect("outcome catalog");
    let failed = positron_governance::DurableOperationAdministration::inspect(
        &catalog,
        accepted.operation_id(),
    )?
    .ok_or("failed operation")?;
    assert_eq!(failed.status(), DurableOperationStatus::Failed);
    assert_eq!(std::fs::read_dir(&path)?.count(), 0);
    assert_eq!(
        services.repository_operation_status(&administrator, accepted.operation_id()),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    std::fs::remove_dir_all(path)?;
    Ok(())
}

#[path = "repository/fifo.rs"]
mod fifo;

#[test]
fn aws_repository_admission_binds_native_target_without_provider_io()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::services::repository_administration::RepositoryLocation;
    use positron_governance::RepositoryProviderKind;
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let target = positron_backup::AwsS3Target::new(
        "positron-example",
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com",
        "123456789012",
        "diagnostic/",
    )?;
    let generation = services
        .open_maintenance_catalog()
        .expect("catalog")
        .pin()?
        .number();
    let input = RepositoryAdmission {
        action: RepositoryAction::Doctor,
        locator: RepositoryLocation::AwsS3(&target),
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
    assert_eq!(parameters.provider_kind(), RepositoryProviderKind::AwsS3);
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
        google_cloud_storage: None,
        azure_blob: None,
        aws_s3: Some(positron_api::repository::RepositoryAwsS3Target {
            bucket: target.bucket().into(),
            region: target.region().into(),
            endpoint: target.endpoint().into(),
            expected_owner: target.expected_owner().into(),
            prefix: target.prefix().into(),
        }),
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

#[path = "repository/google.rs"]
mod google;

#[path = "repository/azure.rs"]
mod azure;
