use super::*;
use positron_api::backup::{
    BackupRequest, BackupResponse, BackupServiceClient, BackupServiceClientFailure, BackupTransport,
};
use positron_backup::{LocalRepository, RepositoryIdentity};
use std::os::unix::fs::PermissionsExt;

#[test]
fn backup_catalog_open_preserves_resource_admission_refusal()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let generation = initialized.catalog_generation();
    let before = initialized.resource_governor().inspect()?;
    let secret = initialized.key.catalog_secret(initialized.instance)?;
    initialized
        ._authority
        .with_control_contention_for_test(|| {
            assert_eq!(
                positron_kernel::Catalog::open(
                    &initialized._authority,
                    initialized.instance,
                    secret
                )
                .err()
                .map(|failure| failure.code()),
                Some(positron_kernel::CatalogFailureCode::ResourceAdmissionRefused),
            );
            assert_eq!(
                services.open_maintenance_catalog().err(),
                Some(MaintenanceServiceFailure::CapacityUnavailable),
            );
        })?;
    assert_eq!(initialized.catalog_generation(), generation);
    let after = initialized.resource_governor().inspect()?;
    assert_eq!(
        after.outstanding_reservations(),
        before.outstanding_reservations()
    );
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), before.usage(dimension));
    }
    assert_eq!(
        services
            .open_maintenance_catalog()
            .map_err(|_| "Catalog reopen")?
            .pin()?
            .number(),
        generation
    );
    Ok(())
}

#[test]
fn backup_status_identity_read_refusal_reports_only_its_closed_stage()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let state = crate::health::ProcessState::starting();
    services.attach_health(state.health());
    let request = BackupRequest::decode(
        br#"{"action":"status","operation_id":"11111111111111111111111111111111"}"#,
    )?
    .encode()?;
    let invalid = "invalid-administrator-secret-canary";
    for credential in ["", invalid] {
        assert_eq!(
            services.manage_backup(credential, &request),
            Err(MaintenanceServiceFailure::AuthenticationRejected)
        );
    }
    let generation = initialized.catalog_generation();
    let before = initialized.resource_governor().inspect()?;
    initialized
        ._authority
        .with_control_contention_for_test(|| {
            assert_eq!(
                initialized
                    .durable_identity()
                    .err()
                    .map(|failure| failure.code()),
                Some(crate::BootstrapFailureCode::ResourceUnavailable)
            );
            assert_eq!(
                services.manage_backup(&administrator, &request),
                Err(MaintenanceServiceFailure::CapacityUnavailable)
            );
        })?;
    assert_eq!(initialized.catalog_generation(), generation);
    let after = initialized.resource_governor().inspect()?;
    assert_eq!(
        after.outstanding_reservations(),
        before.outstanding_reservations()
    );
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), before.usage(dimension));
    }
    let rendered = state
        .health()
        .operational_logs_json()
        .map_err(|_| "operational logs unavailable")?;
    assert!(!rendered.contains(&administrator));
    assert!(!rendered.contains(invalid));
    let records: Vec<serde_json::Value> = serde_json::from_str(&rendered)?;
    let failures = records
        .iter()
        .filter(|record| record["event"] == "backup_read_failure")
        .collect::<Vec<_>>();
    assert_eq!(failures.len(), 1, "{rendered}");
    assert_eq!(
        failures.first().ok_or("read diagnostic")?["stage"],
        "administrator_identity"
    );
    assert_eq!(
        failures.first().ok_or("read diagnostic")?["failure"],
        "CapacityUnavailable"
    );
    Ok(())
}

#[test]
fn online_backup_requires_verified_recovery_and_publishes_reusable_ciphertext()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-online-backup-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&repository_path)?;
    fs::set_permissions(&repository_path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        initialized.instance.to_bytes(),
        initialized.integrity_key_fingerprint(),
        &repository_path,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    drop(runtime.block_on(LocalRepository::initialize(
        &repository_path,
        identity.clone(),
    ))?);
    drop(runtime);
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("online backup telemetry").encode_to_vec())?;
    let initial = create(
        &services,
        &repository_path,
        "11111111-1111-4111-8111-111111111111",
    )?;
    assert_eq!(
        services.manage_backup(&ingest, &initial.encode()?),
        Err(MaintenanceServiceFailure::AuthenticationRejected)
    );
    assert_eq!(
        services.manage_backup(&administrator, &initial.encode()?),
        Err(MaintenanceServiceFailure::PreconditionFailed)
    );
    let unlock = age::x25519::Identity::generate();
    let recipients = positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?;
    let bundle = fixture.recovery_export_directory()?.join("snapshot.age");
    initialized.create_recovery_bundle(&bundle, &recipients)?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    drop(services);
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
    let services = process.services().ok_or("serving services")?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint")?;
    let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
    let (initial, accepted) = create_current(
        &client,
        &services,
        &administrator,
        &repository_path,
        "11111111-1111-4111-8111-111111111111",
    )?;
    assert_eq!(accepted.operation.status, "pending");
    let first = finish(&client, &services, &administrator, &accepted.operation.id)
        .map_err(|failure| format!("first backup completion: {failure}"))?;
    assert_eq!(first.operation.status, "succeeded");
    assert_eq!(
        first.operation.irreversible_boundary,
        "backup_registry_published"
    );
    assert!(first.receipt.ok_or("first receipt")?.uploaded_bytes > 0);
    assert_eq!(
        client
            .manage(&administrator, &initial)
            .map_err(|failure| format!("exact retry: {failure:?}"))?
            .operation
            .id,
        accepted.operation.id
    );
    let (_, second) = create_current(
        &client,
        &services,
        &administrator,
        &repository_path,
        "22222222-2222-4222-8222-222222222222",
    )?;
    let second = finish(&client, &services, &administrator, &second.operation.id)
        .map_err(|failure| format!("second backup completion: {failure}"))?;
    assert_eq!(second.operation.status, "succeeded");
    assert!(second.receipt.ok_or("second receipt")?.reused_bytes > 0);
    let listing = positron_api::backup::BackupListRequest {
        repository_id: "5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b".into(),
        limit: 1,
        cursor: None,
    };
    let page = client.list(&administrator, &listing)?;
    assert_eq!(page.entries.len(), 1);
    assert!(page.registry_generation_checksum.is_some());
    let old_cursor = page.next_cursor.clone().ok_or("second page cursor")?;
    let next = client.list(
        &administrator,
        &positron_api::backup::BackupListRequest {
            cursor: Some(old_cursor.clone()),
            ..listing.clone()
        },
    )?;
    assert_eq!(next.entries.len(), 1);
    assert!(next.next_cursor.is_none());
    assert_ne!(
        page.entries
            .first()
            .ok_or("first listed snapshot")?
            .snapshot_id,
        next.entries
            .first()
            .ok_or("second listed snapshot")?
            .snapshot_id
    );
    let (_, cancelling) = create_current(
        &client,
        &services,
        &administrator,
        &repository_path,
        "33333333-3333-4333-8333-333333333333",
    )?;
    let cancellation = cancel_current(
        &client,
        &services,
        &administrator,
        &cancelling.operation.id,
        "44444444-4444-4444-8444-444444444444",
    )
    .map_err(|failure| format!("initial backup cancellation: {failure}"))?;
    assert_eq!(cancellation.operation.phase, "backup_cancellation");
    assert!(cancellation.cleanup_pending);
    let cancelled = finish(&client, &services, &administrator, &cancelling.operation.id)
        .map_err(|failure| format!("initial backup cleanup: {failure}"))?;
    assert_eq!(cancelled.operation.status, "cancelled");
    assert!(!cancelled.cleanup_pending);
    let cursor = client
        .list(&administrator, &listing)
        .map_err(|failure| format!("fresh cursor after initial cancellation: {failure:?}"))?
        .next_cursor
        .ok_or("fresh cursor")?;
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    let initialized = fixture
        .reopen()
        .map_err(|failure| format!("reopen before reservation: {failure}"))?;
    let services = ServiceHandle::new(Arc::clone(&initialized))
        .map_err(|failure| format!("services before reservation: {failure:?}"))?;
    let reserved = services
        .manage_backup(
            &administrator,
            &create(
                &services,
                &repository_path,
                "55555555-5555-4555-8555-555555555555",
            )?
            .encode()?,
        )
        .map_err(|failure| format!("accept reserved backup: {failure:?}"))?;
    let cursor_request = positron_api::backup::BackupListRequest {
        cursor: Some(cursor),
        ..listing
    };
    assert_eq!(
        services
            .list_backups(&administrator, &cursor_request.encode()?)
            .map_err(|failure| format!("cursor before reservation: {failure:?}"))?
            .entries
            .len(),
        1
    );
    let snapshot =
        crate::services::maintenance_verification::decode_fixed_hex(&reserved.operation.id)
            .ok_or("reserved operation")?;
    let stop = crate::services::backup_administration::stop_after(
        initialized.instance.to_bytes(),
        snapshot,
        crate::services::backup_administration::StopPoint::ReservationRegistered,
    )
    .map_err(|failure| format!("arm reservation stop: {failure:?}"))?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancellation = cancellation.clone();
    let worker =
        std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancellation));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !stop.observed() && !worker.is_finished() {
        if std::time::Instant::now() >= deadline {
            cancellation.cancel();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let worker_result = worker.join().map_err(|_| "reservation worker panic")?;
    assert!(
        stop.observed(),
        "reservation stop not reached: {worker_result:?}"
    );
    assert_eq!(worker_result, Ok(()));
    assert_signed_reservation(&services, &repository_path, &identity, snapshot)
        .map_err(|failure| format!("inspect stopped signed reservation: {failure}"))?;
    assert_eq!(
        services.list_backups(&administrator, &cursor_request.encode()?),
        Err(MaintenanceServiceFailure::PreconditionFailed)
    );
    let status = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status", "operation_id":reserved.operation.id}),
    )?)?;
    let revision = services
        .manage_backup(&administrator, &status.encode()?)
        .map_err(|failure| format!("stopped backup status: {failure:?}"))?
        .operation_revision;
    let cancellation = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"cancel", "operation_id":reserved.operation.id, "idempotency_key":"66666666-6666-4666-8666-666666666666", "expected_operation_revision":revision}),
    )?)?;
    // The stopped worker and this request share the established clock. Reopening
    // first would introduce conservative clock recovery and a publication race.
    let cancellation = services
        .manage_backup(&administrator, &cancellation.encode()?)
        .map_err(|failure| format!("stopped backup cancellation: {failure:?}"))?;
    assert_eq!(cancellation.operation.status, "running");
    assert_eq!(cancellation.operation.phase, "backup_cancellation");
    assert!(cancellation.cleanup_pending);
    drop(stop);
    drop(services);
    drop(initialized);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )
    .map_err(|failure| format!("restart after signed reservation: {failure:?}"))?;
    let services = process.services().ok_or("reopened services")?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("reopened API endpoint")?;
    let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
    let recovered = client
        .manage(&administrator, &status)
        .map_err(|failure| format!("cancelled intent after restart: {failure:?}"))?;
    assert!(matches!(
        recovered.operation.status.as_str(),
        "running" | "cancelled"
    ));
    assert!(matches!(
        recovered.operation.phase.as_str(),
        "backup_cancellation" | "cancelled"
    ));
    let cancelled = finish(&client, &services, &administrator, &reserved.operation.id)
        .map_err(|failure| format!("reserved backup cleanup after restart: {failure}"))?;
    assert_eq!(cancelled.operation.status, "cancelled");
    assert!(!cancelled.cleanup_pending);
    {
        let _gate = services.catalog_operation()?;
        assert_eq!(
            crate::BackupRepositoryInspection::from_authenticated_catalog(
                &open_catalog(&services.instance)?.pin()?
            )
            .map_err(|_| "inspection")?
            .label(),
            "configured"
        );
    }
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    fs::remove_dir_all(repository_path)?;
    Ok(())
}
fn assert_signed_reservation(
    services: &ServiceHandle,
    path: &std::path::Path,
    identity: &RepositoryIdentity,
    snapshot: [u8; 16],
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&services.instance)?;
        let basis = catalog.pin()?;
        let (_, governance) = basis.governance_object()?;
        services.instance.key.backup_control_signer(
            services.instance.instance,
            governance.protected_integrity_key(),
        )?
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let repository = runtime.block_on(LocalRepository::attach(path, identity))?;
    let resources = backup_read_resources(services)?;
    let publisher = positron_backup::BackupPublisher::new(&repository, identity, &signer)
        .with_control_resources(&resources, 0)?;
    let proof = backup_inspection_proof(&runtime, &publisher, snapshot)?;
    let verified = publisher.with_registry_verification(&proof)?;
    assert_eq!(
        runtime
            .block_on(verified.cancellation_candidate(snapshot))?
            .ok_or("signed reservation")?
            .snapshot_id(),
        snapshot
    );
    Ok(())
}
fn wait_for_signed_reservation(
    services: &ServiceHandle,
    path: &std::path::Path,
    identity: &RepositoryIdentity,
    operation: &str,
    bearer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = crate::services::maintenance_verification::decode_fixed_hex(operation)
        .ok_or("operation identity")?;
    let signer = {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&services.instance)?;
        let basis = catalog.pin()?;
        let (_, governance) = basis.governance_object()?;
        services.instance.key.backup_control_signer(
            services.instance.instance,
            governance.protected_integrity_key(),
        )?
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let repository = runtime.block_on(LocalRepository::attach(path, identity))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let candidate = {
            let resources = backup_read_resources_until(services, deadline)?;
            let publisher = positron_backup::BackupPublisher::new(&repository, identity, &signer)
                .with_control_resources(&resources, 0)?;
            (|| {
                let proof = backup_inspection_proof(&runtime, &publisher, snapshot)?;
                let verified = publisher.with_registry_verification(&proof)?;
                runtime.block_on(verified.cancellation_candidate(snapshot))
            })()
        };
        match candidate {
            Ok(Some(candidate)) => {
                assert_eq!(candidate.snapshot_id(), snapshot);
                return Ok(());
            },
            Ok(None)
            | Err(positron_backup::RepositoryFailure::PreconditionFailed)
            | Err(positron_backup::RepositoryFailure::Busy) => {},
            Err(failure) => return Err(failure.into()),
        }
        if std::time::Instant::now() >= deadline {
            let task = positron_kernel::MaintenanceTaskId::new(snapshot)
                .map_err(|failure| format!("task identity: {failure:?}"))?;
            let task = services
                .instance
                .maintenance_coordinator()
                .status(task)
                .map(|status| {
                    (
                        status.phase(),
                        status.task().reservations(),
                        status.checkpoint().map(|checkpoint| {
                            (checkpoint.sequence(), checkpoint.opaque_progress().len())
                        }),
                        status.cancellation_requested(),
                        {
                            let governor = services.instance.resource_governor();
                            let claim = positron_kernel::WorkClaim::backup_repository_read(
                                status.task().reservations(),
                            );
                            match claim {
                                Ok(claim) => Ok(governor.reserve(claim).err()),
                                Err(failure) => Err(failure),
                            }
                        },
                    )
                });
            let request = BackupRequest::decode(&serde_json::to_vec(
                &serde_json::json!({"action":"status","operation_id":operation}),
            )?)?;
            let public = services
                .manage_backup(bearer, &request.encode()?)
                .map(|response| {
                    (
                        response.operation.status,
                        response.operation.phase,
                        response.operation.progress_percent,
                        response.operation_revision,
                        response.cleanup_pending,
                    )
                });
            return Err(format!(
                "backup did not publish its signed reservation: task={task:?}, operation={public:?}"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn cancel_current(
    client: &BackupServiceClient,
    _services: &ServiceHandle,
    bearer: &str,
    operation: &str,
    cancellation_key: &str,
) -> Result<BackupResponse, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let status = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status", "operation_id":operation}),
    )?)?;
    loop {
        let revision = client
            .manage(bearer, &status)
            .map_err(|failure| format!("cancellation status read: {failure:?}"))?
            .operation_revision;
        let request = BackupRequest::decode(&serde_json::to_vec(
            &serde_json::json!({"action":"cancel", "operation_id":operation, "idempotency_key":cancellation_key, "expected_operation_revision":revision}),
        )?)?;
        match client.manage(bearer, &request) {
            Ok(response) => return Ok(response),
            Err(BackupServiceClientFailure::StaleGeneration) => {
                if client.manage(bearer, &status)?.operation_revision == revision
                    || std::time::Instant::now() >= deadline
                {
                    return Err("cancellation refused without stale operation revision".into());
                }
            },
            Err(failure) => return Err(format!("cancellation write: {failure:?}").into()),
        }
    }
}

fn create_current(
    client: &BackupServiceClient,
    services: &ServiceHandle,
    bearer: &str,
    repository: &std::path::Path,
    idempotency: &str,
) -> Result<(BackupRequest, BackupResponse), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let request = create(services, repository, idempotency)?;
        match client.manage(bearer, &request) {
            Ok(response) => return Ok((request, response)),
            Err(BackupServiceClientFailure::StaleGeneration) => {
                let _gate = services.catalog_operation()?;
                let generation = open_catalog(&services.instance)?.pin()?.number();
                if request.expected_catalog_generation == Some(generation)
                    || services.instance.checked_backup_key_recovery_readiness()?
                        != crate::RecoveryReadiness::Verified
                    || std::time::Instant::now() >= deadline
                {
                    return Err(format!(
                        "backup create refused: expected {:?}, current {generation}",
                        request.expected_catalog_generation
                    )
                    .into());
                }
                // The rejected request was not accepted. Refresh only its stale
                // Catalog precondition; retain the exact successful request above.
            },
            Err(failure) => return Err(failure.into()),
        }
    }
}

fn create(
    services: &ServiceHandle,
    repository: &std::path::Path,
    idempotency: &str,
) -> Result<BackupRequest, Box<dyn std::error::Error>> {
    let _gate = services.catalog_operation()?;
    let generation = open_catalog(&services.instance)?.pin()?.number();
    Ok(BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"create", "repository_id":"5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b", "locator":repository, "retention_seconds":3600,"expected_catalog_generation":generation,"idempotency_key":idempotency}),
    )?)?)
}
fn finish(
    client: &BackupServiceClient,
    services: &ServiceHandle,
    bearer: &str,
    id: &str,
) -> Result<BackupResponse, Box<dyn std::error::Error>> {
    let request = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status","operation_id":id}),
    )?)?;
    // This is a fixture completion budget, not a product latency promise.
    // Every bounded data turn durably publishes a Catalog checkpoint; polling
    // shares that Catalog gate, so leave time for progress between reads.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut last_response = String::new();
    loop {
        match client.manage(bearer, &request) {
            Ok(response) => {
                last_response = format!(
                    "status={} phase={} progress={} cleanup_pending={}",
                    response.operation.status,
                    response.operation.phase,
                    response.operation.progress_percent,
                    response.cleanup_pending
                );
                if response.operation.status == "failed" {
                    return Ok(response);
                }
                if response.operation.status == "cancelled" {
                    let operation = crate::services::maintenance_verification::decode_fixed_hex(id)
                        .ok_or("cancelled operation identity")?;
                    if services
                        .instance
                        .maintenance_coordinator()
                        .statuses()
                        .map_err(|_| "task status")?
                        .iter()
                        .any(|status| {
                            status.task().identity().to_bytes() == operation
                                && status.phase() == MaintenanceTaskPhase::Cancelled
                        })
                    {
                        return Ok(response);
                    }
                }
                if response.operation.status == "succeeded"
                    && services
                        .instance
                        .maintenance_coordinator()
                        .statuses()
                        .expect("task status")
                        .iter()
                        .filter(|status| {
                            status.task().class() == MaintenanceTaskClass::BackupSnapshot
                        })
                        .all(|status| status.phase() == MaintenanceTaskPhase::Succeeded)
                {
                    return Ok(response);
                }
            },
            Err(BackupServiceClientFailure::CapacityUnavailable) => {},
            Err(failure) => return Err(failure.into()),
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "backup did not finish ({last_response}): {:?}",
                services
                    .instance
                    .maintenance_coordinator()
                    .statuses()
                    .map(|statuses| statuses
                        .into_iter()
                        .filter(
                            |status| status.task().class() == MaintenanceTaskClass::BackupSnapshot
                        )
                        .collect::<Vec<_>>())
            )
            .into());
        }
        // HTTP status authentication shares the Catalog gate with each bounded
        // worker turn. Poll less frequently to reduce contention with worker turns.
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[path = "backup_recovery.rs"]
mod recovery;

#[path = "backup_failure.rs"]
mod failure;

#[path = "backup_readmission.rs"]
mod readmission;

#[path = "backup_retention.rs"]
mod retention;
#[path = "backup_verification.rs"]
mod verification;

fn backup_read_resources(
    services: &ServiceHandle,
) -> Result<Arc<positron_kernel::NativeAwsResources>, Box<dyn std::error::Error>> {
    backup_read_resources_until(
        services,
        std::time::Instant::now() + Duration::from_secs(30),
    )
}
fn backup_read_resources_until(
    services: &ServiceHandle,
    deadline: std::time::Instant,
) -> Result<Arc<positron_kernel::NativeAwsResources>, Box<dyn std::error::Error>> {
    let native = crate::services::repository_administration::repository_resources(
        positron_governance::RepositoryProviderKind::LocalFilesystem,
    );
    // The fixture's small Catalog/key controls have a one-MiB upper bound.
    // Charge provider, control baseline and eightfold codec overlap together;
    // the actual Publisher guard still refuses fixtures beyond this demand.
    let memory = positron_backup::BackupPublisher::control_read_memory_bytes()
        .checked_add(8 * 1024 * 1024)
        .and_then(|bytes| {
            bytes.checked_add(native.get(positron_kernel::ResourceDimension::MemoryBytes))
        })
        .ok_or("fixture inspection memory overflow")?;
    let resources = positron_kernel::ResourceAmounts::new(
        positron_kernel::ResourceDimension::ALL.map(|dimension| {
            if dimension == positron_kernel::ResourceDimension::MemoryBytes {
                memory
            } else {
                native.get(dimension)
            }
        }),
    );
    let claim = positron_kernel::WorkClaim::backup_repository_read(resources)?;
    loop {
        match services.instance.resource_governor().reserve(claim.clone()) {
            Ok(reservation) => {
                return Ok(positron_kernel::NativeAwsResources::new(
                    reservation.transfer(),
                ));
            },
            Err(failure)
                if failure.code() == positron_kernel::AdmissionFailureCode::GovernorContended
                    && failure.completion_state()
                        == positron_kernel::AdmissionCompletionState::RejectedBeforeReservation
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10))
            },
            Err(failure) => return Err(failure.into()),
        }
    }
}

// Inspection callers use the same bounded signed ancestry protocol as the worker.
fn backup_inspection_proof(
    runtime: &tokio::runtime::Runtime,
    publisher: &positron_backup::BackupPublisher<'_>,
    owner: [u8; 16],
) -> Result<positron_backup::BackupRegistryVerification, positron_backup::RepositoryFailure> {
    let mut proof = runtime.block_on(publisher.begin_registry_verification(owner, [0x6d; 32]))?;
    for _ in 0..4096 {
        if proof.complete()? {
            return Ok(proof);
        }
        runtime.block_on(publisher.registry_verification_step(&mut proof))?;
    }
    if !proof.complete()? {
        return Err(positron_backup::RepositoryFailure::LimitExceeded);
    }
    Ok(proof)
}

#[path = "backup_verification_http.rs"]
mod verification_http;

#[path = "backup_envelope_migration.rs"]
mod envelope_migration;

#[path = "backup_restore.rs"]
mod restore;

#[path = "backup_tenant_purge.rs"]
mod tenant_purge;

#[path = "backup_snapshot_authorization.rs"]
mod snapshot_authorization;
