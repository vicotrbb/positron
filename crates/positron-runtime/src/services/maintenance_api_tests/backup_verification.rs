use super::*;
use crate::services::backup_administration::{StopPoint, stop_after};

#[test]
fn independent_verification_partial_native_cold_reopen_reauthenticates()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationNativeFileVerified,
        false,
        0,
        None,
        false,
    )
}
#[test]
fn independent_verification_partial_native_cancel_preserves_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationNativeFileVerified,
        true,
        0,
        None,
        false,
    )
}

#[test]
fn independent_verification_rebuilds_native_metadata_after_cold_stop()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        false,
        0,
        None,
        false,
    )
}
#[test]
fn independent_verification_rechecks_remote_keys_after_cold_stop()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(StopPoint::VerificationKeyRecovered, false, 0, None, false)
}
#[test]
fn independent_verification_cancellation_drops_reads_without_deleting_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        true,
        0,
        None,
        false,
    )
}
#[test]
fn independent_verification_report_survives_stop_before_maintenance_completion()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationReportPublished,
        false,
        0,
        None,
        false,
    )
}
#[test]
fn independent_verification_rejects_a_checksum_valid_remote_key_that_cannot_unwrap()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        false,
        1,
        None,
        false,
    )
}

#[test]
fn independent_verification_rejects_a_remote_envelope_with_the_wrong_native_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        false,
        2,
        None,
        false,
    )
}
#[test]
fn independent_verification_rejects_a_remote_envelope_with_the_wrong_native_fingerprint()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        false,
        3,
        None,
        false,
    )
}

#[test]
fn independent_verification_rechecks_requester_grant_on_the_next_advance()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        false,
        4,
        None,
        false,
    )
}

#[derive(Clone, Copy)]
enum SemanticPeak {
    Schema,
    Policy,
}

#[test]
fn independent_verification_admits_schema_peak_before_semantic_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        false,
        0,
        Some(SemanticPeak::Schema),
        false,
    )
}

#[test]
fn independent_verification_admits_policy_peak_before_semantic_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationMetadataVerified,
        false,
        0,
        Some(SemanticPeak::Policy),
        false,
    )
}

#[test]
fn independent_verification_coalesces_checkpoint_publications_and_resumes_unpublished_work()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationRemoteRangeVerified,
        false,
        0,
        None,
        false,
    )
}

#[test]
fn independent_verification_reauthenticates_the_unpublished_suffix_after_cold_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationRemoteRangeVerified,
        false,
        0,
        None,
        true,
    )
}

#[test]
fn independent_verification_can_cancel_with_unpublished_remote_progress()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationRemoteRangeVerified,
        true,
        0,
        None,
        false,
    )
}

#[test]
fn independent_verification_retries_a_failed_pending_checkpoint_before_another_read()
-> Result<(), Box<dyn std::error::Error>> {
    restart_at(
        StopPoint::VerificationRemoteCheckpointDue,
        false,
        0,
        None,
        true,
    )
}

fn restart_at(
    point: StopPoint,
    cancel: bool,
    key_failure: u8,
    semantic_peak: Option<SemanticPeak>,
    corrupt_unpublished: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (initialized, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let repository_path = std::env::temp_dir().join(format!(
        "positron-independent-verification-{}",
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
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    let mut telemetry = request("independently verified telemetry");
    if matches!(semantic_peak, Some(SemanticPeak::Schema)) {
        use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
        let record = telemetry
            .resource_logs
            .first_mut()
            .and_then(|resource| resource.scope_logs.first_mut())
            .and_then(|scope| scope.log_records.first_mut())
            .ok_or("schema fixture log")?;
        record.attributes = (0..128)
            .map(|index| KeyValue {
                key: format!("semantic-bound-{index}"),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue("observed".into())),
                }),
                ..KeyValue::default()
            })
            .collect();
    }
    services.ingest_otlp_logs(&ingest, telemetry.encode_to_vec())?;
    if matches!(semantic_peak, Some(SemanticPeak::Policy)) {
        use positron_domain::identity::Scope;
        use positron_governance::{
            AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
            ResourceGeneration,
        };
        let system = initialized.attribute(
            PresentedCredential::parse(&administrator)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        let created = initialized.create_api_key_for_tenant(
            system,
            initialized.default_tenant_id(),
            Scope::TenantAdministration,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xe1; 16])?,
        )?;
        let actor = initialized.attribute(
            PresentedCredential::parse(
                created.secret().ok_or("policy administration credential")?,
            )?,
            RequestedIntent::TenantAdministration,
            CompatibilityHints::none(),
        )?;
        services.activate_ingest_policy(
            actor,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xe2; 16])?,
            positron_policy::IngestPolicy::reject_exact_text_body(
                2,
                "large-verification-policy",
                &"x".repeat(8192),
            )?,
        )?;
    }
    if semantic_peak.is_some() {
        services.prepare_shutdown_schema_checkpoint()?;
        services.publish_prepared_shutdown_schema_checkpoint(&mut || false)?;
        let catalog = open_catalog(&initialized)?;
        let basis = catalog.pin()?;
        let mut schema = 0;
        let mut policy = 0;
        for identity in basis.object_identities() {
            let bytes = basis.object(identity)?.ok_or("semantic fixture object")?;
            if bytes.starts_with(b"PSCHEMA1") {
                schema = schema.max(positron_signals::SchemaCatalog::catalog_memory_bound(
                    bytes,
                )?);
            } else if bytes.starts_with(b"PIPACT01") {
                policy = policy
                    .max(positron_policy::IngestPolicy::activated_object_memory_bound(bytes)?);
            }
        }
        match semantic_peak {
            Some(SemanticPeak::Schema) => assert!(schema > policy),
            Some(SemanticPeak::Policy) => assert!(policy > schema),
            None => unreachable!(),
        }
    }
    let unlock = age::x25519::Identity::generate();
    let bundle = fixture
        .recovery_export_directory()?
        .join("verification.age");
    initialized.create_recovery_bundle(
        &bundle,
        &positron_kernel::RecoveryRecipients::parse(&[unlock.to_public().to_string()])?,
    )?;
    initialized
        .verify_recovery_bundle(&bundle, positron_kernel::RecoveryUnlock::Identity(&unlock))?;
    let captured_source_objects = if point == StopPoint::VerificationRemoteRangeVerified {
        open_catalog(&initialized)?
            .pin()?
            .object_identities()
            .count()
    } else {
        0
    };
    let created = services
        .manage_backup(
            &administrator,
            &create(
                &services,
                &repository_path,
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            )?
            .encode()?,
        )
        .map_err(|failure| format!("create: {failure:?}"))?;
    let cancellation = crate::TaskCancellation::new();
    let worker_services = services.clone();
    let worker_cancel = cancellation.clone();
    let worker = std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancel));
    let published = retention::finish_direct(&services, &administrator, &created.operation.id);
    cancellation.cancel();
    let worker_result = worker.join().map_err(|_| "backup worker panic")?;
    let published =
        published.map_err(|failure| format!("backup: {failure}; worker={worker_result:?}"))?;
    let manifest = published.receipt.ok_or("backup receipt")?.manifest_checksum;
    if (1..=3).contains(&key_failure) {
        replace_remote_key(
            &services,
            &runtime,
            &repository_path,
            &identity,
            &created.operation.id,
            key_failure,
        )?;
    }
    let generation = {
        let _gate = services.catalog_operation()?;
        open_catalog(&initialized)?.pin()?.number()
    };
    let request = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"verify", "repository_id":"5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b", "snapshot_id":created.operation.id, "expected_manifest_checksum":manifest,"expected_catalog_generation":generation,"idempotency_key":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}),
    )?)?;
    let accepted = services
        .manage_backup(&administrator, &request.encode()?)
        .map_err(|failure| format!("verify: {failure:?}"))?;
    if semantic_peak.is_some() {
        verify_semantic_admission(&services, &administrator, &accepted.operation.id)?;
        drop(runtime);
        drop(services);
        drop(initialized);
        fs::remove_dir_all(repository_path)?;
        return Ok(());
    }
    if key_failure == 4 {
        let id = positron_governance::OperationId::from_bytes(
            crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
                .ok_or("verification operation ID")?,
        )?;
        let task =
            positron_kernel::MaintenanceTaskId::new(id.to_bytes()).map_err(|e| format!("{e:?}"))?;
        let coordinator = initialized.maintenance_coordinator();
        let mut execution = {
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|e| format!("{e:?}"))?;
            coordinator
                .start_backup_operation_with_reservation_and_persist(
                    &catalog,
                    &initialized._authority,
                    services
                        .maintenance_status_now()
                        .map_err(|e| format!("{e:?}"))?,
                    false,
                    task,
                )
                .map_err(|e| format!("{e:?}"))?
                .ok_or("verification start")?
        };
        let mut work = None;
        assert!(!crate::services::backup_administration::complete(
            &services,
            &mut execution,
            &mut work,
            None,
        )?);
        // Change the canonical persistent grant between advances. There is no
        // operator API for rotating the bootstrap system credential.
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|e| format!("{e:?}"))?;
        let basis = catalog.pin()?;
        let (source, governance) = basis.governance_object()?;
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
                let bytes = basis.object(identity)?.expect("fixture object");
                positron_kernel::CatalogObject::new(bytes.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        objects.retain(|object| object.identity() != source);
        objects.push(changed);
        catalog.commit(
            basis.identity(),
            positron_kernel::CatalogProposal::new(
                positron_kernel::TransactionId::new([0xd4; 16])?,
                positron_kernel::FormatEpoch::CATALOG_V1,
                objects,
            )?,
            None,
        )?;
        drop(basis);
        drop(catalog);
        assert_eq!(
            crate::services::backup_administration::complete(
                &services,
                &mut execution,
                &mut work,
                None,
            ),
            Err(crate::ServiceFailure::Unauthorized)
        );
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|e| format!("{e:?}"))?;
        let refused = positron_governance::DurableOperationAdministration::inspect(&catalog, id)?
            .ok_or("verification outcome")?;
        assert_eq!(
            refused.status(),
            positron_governance::DurableOperationStatus::Running
        );
        assert!(refused.backup_verification_report().is_none());
        drop(catalog);
        let status = BackupRequest::decode(&serde_json::to_vec(
            &serde_json::json!({"action":"status","operation_id":accepted.operation.id}),
        )?)?;
        assert_eq!(
            services.manage_backup(&administrator, &status.encode()?),
            Err(MaintenanceServiceFailure::AuthenticationRejected)
        );
        drop(work);
        drop(execution);
        drop(runtime);
        drop(services);
        drop(initialized);
        fs::remove_dir_all(repository_path)?;
        return Ok(());
    }
    if point == StopPoint::VerificationRemoteCheckpointDue {
        verify_pending_checkpoint_fault(
            &services,
            &runtime,
            &repository_path,
            &identity,
            &created.operation.id,
            &accepted.operation.id,
        )?;
    } else {
        let stop = stop_after(
            services.instance.instance.to_bytes(),
            crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
                .ok_or("stop operation identity")?,
            point,
        )?;
        let cancellation = crate::TaskCancellation::new();
        let worker_services = services.clone();
        let worker_cancel = cancellation.clone();
        let capacity_blocker =
            if point == StopPoint::VerificationMetadataVerified && !cancel && key_failure == 0 {
                let amounts = |memory| {
                    positron_kernel::ResourceAmounts::new([memory, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                };
                let mut requested = u64::MAX;
                let mut blocker = None;
                for _ in 0..4 {
                    match initialized.resource_governor().reserve(
                        positron_kernel::WorkClaim::backup_repository_read(amounts(requested))?,
                    ) {
                        Ok(reservation) => {
                            blocker = Some(reservation);
                            break;
                        },
                        Err(refusal) => {
                            let next = refusal
                                .allowed()
                                .checked_sub(refusal.in_use())
                                .and_then(|bytes| bytes.checked_sub(1_048_576))
                                .ok_or("verification admission headroom")?;
                            if next >= requested {
                                return Err("verification admission did not narrow".into());
                            }
                            requested = next;
                        },
                    }
                }
                Some(blocker.ok_or("verification capacity blocker")?)
            } else {
                None
            };
        let worker =
            std::thread::spawn(move || worker_services.run_maintenance_worker(&worker_cancel));
        if capacity_blocker.is_some() {
            std::thread::sleep(Duration::from_millis(100));
            let status = BackupRequest::decode(&serde_json::to_vec(
                &serde_json::json!({"action":"status","operation_id":accepted.operation.id}),
            )?)?;
            let pending = services
                .manage_backup(&administrator, &status.encode()?)
                .map_err(|failure| format!("capacity status: {failure:?}"))?;
            assert_eq!(pending.operation.status, "pending");
            assert!(pending.verification_report.is_none());
            assert!(pending.verification_report_checksum.is_none());
        }
        drop(capacity_blocker);
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !stop.observed() && !worker.is_finished() {
            if std::time::Instant::now() >= deadline {
                cancellation.cancel();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let result = worker.join().map_err(|_| "verification worker panic")?;
        let diagnostic_request = BackupRequest::decode(&serde_json::to_vec(
            &serde_json::json!({"action":"status","operation_id":accepted.operation.id}),
        )?)?;
        let diagnostic = services.manage_backup(&administrator, &diagnostic_request.encode()?);
        assert!(
            stop.observed(),
            "verification stop not reached: worker={result:?}, operation={diagnostic:?}"
        );
        assert_eq!(result, Ok(()));
        if point == StopPoint::VerificationRemoteRangeVerified {
            let task = positron_kernel::MaintenanceTaskId::new(
                crate::services::maintenance_verification::decode_fixed_hex(&accepted.operation.id)
                    .ok_or("verification identity")?,
            )
            .map_err(|failure| format!("verification task: {failure:?}"))?;
            let status = initialized
                .maintenance_coordinator()
                .status(task)
                .map_err(|failure| format!("verification status: {failure:?}"))?;
            let publications = status
                .checkpoint()
                .ok_or("remote verification checkpoint")?
                .sequence();
            assert!(
                publications < u64::try_from(captured_source_objects)?,
                "bounded verification must avoid a durable Catalog publication for every source object: publications={publications}, source_objects={captured_source_objects}"
            );
        }
        drop(stop);
    }
    let status = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status","operation_id":accepted.operation.id}),
    )?)?;
    let before_restart = services
        .manage_backup(&administrator, &status.encode()?)
        .map_err(|failure| format!("status: {failure:?}"))?;
    if corrupt_unpublished && point != StopPoint::VerificationRemoteCheckpointDue {
        corrupt_remote_files(
            &services,
            &runtime,
            &repository_path,
            &identity,
            &created.operation.id,
            false,
        )?;
    }
    if cancel {
        let cancellation = BackupRequest::decode(&serde_json::to_vec(
            &serde_json::json!({"action":"cancel","operation_id":accepted.operation.id,"expected_operation_revision":before_restart.operation_revision,"idempotency_key":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}),
        )?)?;
        let cancelled = services
            .manage_backup(&administrator, &cancellation.encode()?)
            .map_err(|failure| format!("cancel: {failure:?}"))?;
        assert_eq!(cancelled.operation.status, "cancelled");
        assert!(!cancelled.cleanup_pending);
    }
    drop(runtime);
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
    let services = process.services().ok_or("cold services")?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint")?;
    let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
    let completed = finish(&client, &services, &administrator, &accepted.operation.id)?;
    assert_eq!(
        completed.operation.status,
        if cancel {
            "cancelled"
        } else if key_failure != 0 || corrupt_unpublished {
            "failed"
        } else {
            "succeeded"
        }
    );
    if key_failure != 0 || corrupt_unpublished {
        assert!(completed.verification_report.is_none());
        assert!(completed.verification_report_checksum.is_none());
        assert_eq!(process.health().phase(), crate::ProcessPhase::Serving);
        let outcome = services.ingest_otlp_logs(
            &ingest,
            super::super::request("healthy after wrong backup key").encode_to_vec(),
        )?;
        assert_eq!(outcome.accepted_records(), 1);
    }
    if !cancel && key_failure == 0 && !corrupt_unpublished {
        assert!(completed.verification_report.is_some());
        assert!(completed.verification_report_checksum.is_some());
        if point == StopPoint::VerificationReportPublished {
            assert_eq!(
                completed.verification_report_checksum,
                before_restart.verification_report_checksum
            );
        }
        assert_eq!(client.manage(&administrator, &request)?, completed);
    }
    let inventory = client.list(
        &administrator,
        &positron_api::backup::BackupListRequest {
            repository_id: "5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b".into(),
            limit: 128,
            cursor: None,
        },
    )?;
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(
        inventory
            .entries
            .first()
            .ok_or("retained snapshot")?
            .snapshot_id,
        created.operation.id
    );
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    fs::remove_dir_all(repository_path)?;
    Ok(())
}

fn verify_semantic_admission(
    services: &ServiceHandle,
    administrator: &str,
    operation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ServiceFailure;
    use crate::services::backup_administration::{BackupWork, complete};
    let id = positron_governance::OperationId::from_bytes(
        crate::services::maintenance_verification::decode_fixed_hex(operation)
            .ok_or("verification identity")?,
    )?;
    let task =
        positron_kernel::MaintenanceTaskId::new(id.to_bytes()).map_err(|e| format!("{e:?}"))?;
    let coordinator = services.instance.maintenance_coordinator();
    let status = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status", "operation_id":operation}),
    )?)?;
    let mut stop = Some(stop_after(
        services.instance.instance.to_bytes(),
        task.to_bytes(),
        StopPoint::VerificationMetadataVerified,
    )?);
    let mut phase = 0;
    let mut semantic_reservation = None;
    let mut execution = None;
    let mut work: Option<BackupWork> = None;
    let mut shortfall = None;
    let mut checked_shortfalls = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("semantic admission fixture deadline".into());
        }
        if execution.is_none() {
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|e| format!("{e:?}"))?;
            execution = coordinator
                .start_backup_operation_with_reservation_and_persist(
                    &catalog,
                    &services.instance._authority,
                    services
                        .maintenance_status_now()
                        .map_err(|e| format!("{e:?}"))?,
                    false,
                    task,
                )
                .map_err(|e| format!("{e:?}"))?;
        }
        let Some(owner) = execution.as_mut() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        match complete(services, owner, &mut work, None) {
            Err(ServiceFailure::Cancelled) if stop.as_ref().is_some_and(|stop| stop.observed()) => {
                drop(stop.take());
                if phase == 0 {
                    semantic_reservation = Some(owner.task().reservations());
                    stop = Some(stop_after(
                        services.instance.instance.to_bytes(),
                        task.to_bytes(),
                        StopPoint::VerificationSemanticVerified,
                    )?);
                    phase = 1;
                } else {
                    assert_eq!(
                        owner.task().reservations(),
                        semantic_reservation.ok_or("metadata reservation")?,
                        "semantic reconstruction must retain its admitted reservation"
                    );
                    phase = 2;
                }
            },
            Err(ServiceFailure::BackupControlMemoryRequired { memory_bytes }) => {
                assert_eq!(
                    phase, 0,
                    "verification requested additional memory after metadata acceptance: {memory_bytes}"
                );
                if phase == 0 {
                    assert!(!stop.as_ref().ok_or("metadata stop")?.observed());
                    let pending = services
                        .manage_backup(administrator, &status.encode()?)
                        .map_err(|e| format!("{e:?}"))?;
                    assert!(pending.verification_report.is_none());
                    assert!(pending.verification_report_checksum.is_none());
                }
                let previous = owner.task().reservations();
                let granted = previous.get(positron_kernel::ResourceDimension::MemoryBytes);
                let requested = if shortfall == Some(memory_bytes) {
                    assert_eq!(granted.checked_add(1), Some(memory_bytes));
                    checked_shortfalls += 1;
                    shortfall = None;
                    memory_bytes
                } else if phase == 0 && memory_bytes > granted.saturating_add(1) {
                    shortfall = Some(memory_bytes);
                    memory_bytes - 1
                } else {
                    memory_bytes
                };
                work = None;
                let binding = positron_kernel::RepositoryOperationBinding::from_execution(owner)
                    .map_err(|e| format!("{e:?}"))?;
                let resources = positron_kernel::ResourceAmounts::new(
                    positron_kernel::ResourceDimension::ALL.map(|dimension| {
                        if dimension == positron_kernel::ResourceDimension::MemoryBytes {
                            requested
                        } else {
                            previous.get(dimension)
                        }
                    }),
                );
                let _gate = services.catalog_operation()?;
                let catalog = services
                    .open_maintenance_catalog()
                    .map_err(|e| format!("{e:?}"))?;
                owner
                    .requeue_backup_with_resources_and_persist(
                        coordinator,
                        &catalog,
                        binding,
                        resources,
                        services
                            .maintenance_status_now()
                            .map_err(|e| format!("{e:?}"))?,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                drop(catalog);
                drop(_gate);
                execution = None;
            },
            Ok(true) => break,
            Ok(false) => {},
            Err(error) => return Err(format!("semantic verification advance: {error:?}").into()),
        }
    }
    assert_eq!(phase, 2);
    assert!(checked_shortfalls > 0);
    let completed = services
        .manage_backup(administrator, &status.encode()?)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(completed.operation.status, "succeeded");
    assert!(completed.verification_report.is_some());
    assert!(completed.verification_report_checksum.is_some());
    Ok(())
}

fn replace_remote_key(
    services: &ServiceHandle,
    runtime: &tokio::runtime::Runtime,
    path: &std::path::Path,
    identity: &RepositoryIdentity,
    snapshot: &str,
    failure: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{
        BackupCatalogIdentity, BackupKeyEnvelope, BackupManifest, BackupObject, BackupPublisher,
        BackupRetention,
    };
    let snapshot =
        crate::services::maintenance_verification::decode_fixed_hex(snapshot).ok_or("snapshot")?;
    let signer = {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&services.instance)?;
        let basis = catalog.pin()?;
        services.instance.key.backup_control_signer(
            services.instance.instance,
            basis.governance_object()?.1.protected_integrity_key(),
        )?
    };
    let repository = runtime.block_on(LocalRepository::attach(path, identity))?;
    let resources = backup_read_resources(services)?;
    let publisher = BackupPublisher::new(&repository, identity, &signer)
        .with_control_resources(&resources, 0)?;
    let proof = backup_inspection_proof(runtime, &publisher, snapshot)?;
    let publisher = publisher.with_registry_verification(&proof)?;
    runtime.block_on(async {
        let state = publisher
            .begin_snapshot_verification(snapshot, [0x91; 16], [0x92; 32])
            .await?;
        let key = publisher.read_verification_key(&state, 0).await?;
        let mut protected = if failure == 1 {
            key.protected().to_vec()
        } else {
            services.instance.key.provision_tenant_key_envelope(
                services.instance.instance,
                positron_domain::identity::TenantId::from_bytes(key.tenant())?,
                [0x97; 16],
                if failure == 2 {
                    key.epoch().checked_add(1).ok_or("key epoch")?
                } else {
                    key.epoch()
                },
            )?
        };
        if failure == 1 {
            *protected.last_mut().ok_or("protected key")? ^= 1;
        }
        let bad = BackupKeyEnvelope::new(key.tenant(), key.epoch(), key.fingerprint(), protected)?;
        // A separately signed pending reservation replaces the same context's
        // protected object reference. All checksums/signatures remain valid;
        // only native authentication of the remote envelope detects the fault.
        let keys = [bad];
        let pending = BackupManifest::new(
            [0x93; 16],
            identity.clone(),
            BackupCatalogIdentity::new(1, [0x94; 32], 2, 0, [0x95; 32])?,
            BackupRetention::new(1, 2)?,
            BackupPublisher::key_context(&keys)?,
            vec![BackupObject::new([0x95; 32], 1, 0, [0x96; 32], 1)?],
        )?;
        publisher.reserve(&pending, &keys).await?;
        publisher.prepare_key_step(&pending, &keys, 0).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

fn corrupt_remote_files(
    services: &ServiceHandle,
    runtime: &tokio::runtime::Runtime,
    path: &std::path::Path,
    identity: &RepositoryIdentity,
    snapshot: &str,
    all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::BackupPublisher;
    let snapshot = crate::services::maintenance_verification::decode_fixed_hex(snapshot)
        .ok_or("snapshot identity")?;
    let signer = {
        let _gate = services.catalog_operation()?;
        let catalog = open_catalog(&services.instance)?;
        let basis = catalog.pin()?;
        services.instance.key.backup_control_signer(
            services.instance.instance,
            basis.governance_object()?.1.protected_integrity_key(),
        )?
    };
    let repository = runtime.block_on(LocalRepository::attach(path, identity))?;
    let resources = backup_read_resources(services)?;
    let publisher = BackupPublisher::new(&repository, identity, &signer)
        .with_control_resources(&resources, 0)?;
    let proof = backup_inspection_proof(runtime, &publisher, snapshot)?;
    let publisher = publisher.with_registry_verification(&proof)?;
    let state = runtime
        .block_on(publisher.begin_snapshot_verification(snapshot, [0x91; 16], [0x92; 32]))?;
    let manifest = state.manifest();
    let objects = manifest
        .objects()
        .iter()
        .filter(|object| all || object.file() != manifest.capture_index())
        .take(if all { usize::MAX } else { 1 });
    for object in objects {
        let name = format!(
            "o-{}",
            object
                .object()
                .checksum()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let file = path.join(name);
        let mut bytes = fs::read(&file)?;
        *bytes.first_mut().ok_or("native ciphertext")? ^= 1;
        fs::write(file, bytes)?;
    }
    Ok(())
}

fn verify_pending_checkpoint_fault(
    services: &ServiceHandle,
    runtime: &tokio::runtime::Runtime,
    path: &std::path::Path,
    identity: &RepositoryIdentity,
    snapshot: &str,
    operation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::ServiceFailure;
    use crate::services::backup_administration::{BackupWork, complete};
    let task = positron_kernel::MaintenanceTaskId::new(
        crate::services::maintenance_verification::decode_fixed_hex(operation)
            .ok_or("verification operation")?,
    )
    .map_err(|failure| format!("task: {failure:?}"))?;
    let coordinator = services.instance.maintenance_coordinator();
    let stop = stop_after(
        services.instance.instance.to_bytes(),
        task.to_bytes(),
        StopPoint::VerificationRemoteCheckpointDue,
    )?;
    let mut execution = None;
    let mut work: Option<BackupWork> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("pending checkpoint fixture deadline".into());
        }
        if execution.is_none() {
            let _gate = services.catalog_operation()?;
            let catalog = services
                .open_maintenance_catalog()
                .map_err(|failure| format!("catalog: {failure:?}"))?;
            execution = coordinator
                .start_backup_operation_with_reservation_and_persist(
                    &catalog,
                    &services.instance._authority,
                    services
                        .maintenance_status_now()
                        .map_err(|failure| format!("time: {failure:?}"))?,
                    false,
                    task,
                )
                .map_err(|failure| format!("dispatch: {failure:?}"))?;
        }
        let Some(owner) = execution.as_mut() else {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        match complete(services, owner, &mut work, None) {
            Err(ServiceFailure::Cancelled) if stop.observed() => break,
            Err(ServiceFailure::BackupControlMemoryRequired { memory_bytes }) => {
                work = None;
                let binding = positron_kernel::RepositoryOperationBinding::from_execution(owner)
                    .map_err(|failure| format!("binding: {failure:?}"))?;
                let previous = owner.task().reservations();
                let resources = positron_kernel::ResourceAmounts::new(
                    positron_kernel::ResourceDimension::ALL.map(|dimension| {
                        if dimension == positron_kernel::ResourceDimension::MemoryBytes {
                            memory_bytes
                        } else {
                            previous.get(dimension)
                        }
                    }),
                );
                let _gate = services.catalog_operation()?;
                let catalog = services
                    .open_maintenance_catalog()
                    .map_err(|failure| format!("catalog: {failure:?}"))?;
                owner
                    .requeue_backup_with_resources_and_persist(
                        coordinator,
                        &catalog,
                        binding,
                        resources,
                        services
                            .maintenance_status_now()
                            .map_err(|failure| format!("time: {failure:?}"))?,
                    )
                    .map_err(|failure| format!("readmission: {failure:?}"))?;
                execution = None;
            },
            Ok(false) => {},
            result => return Err(format!("pending checkpoint preparation: {result:?}").into()),
        }
    }
    drop(stop);
    let owner = execution.as_mut().ok_or("pending owner")?;
    let before = coordinator
        .status(task)
        .map_err(|failure| format!("status: {failure:?}"))?
        .checkpoint()
        .cloned();
    let failed = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::RenameMarker,
        0,
        || complete(services, owner, &mut work, None),
    );
    assert_eq!(failed, Err(ServiceFailure::CatalogUnavailable));
    assert_eq!(
        coordinator
            .status(task)
            .map_err(|failure| format!("status: {failure:?}"))?
            .checkpoint(),
        before.as_ref()
    );
    corrupt_remote_files(services, runtime, path, identity, snapshot, true)?;
    assert_eq!(
        complete(services, owner, &mut work, None),
        Ok(false),
        "retry must flush pending proof before reading corrupted payload"
    );
    assert!(
        coordinator
            .status(task)
            .map_err(|failure| format!("status: {failure:?}"))?
            .checkpoint()
            .ok_or("retry checkpoint")?
            .sequence()
            > before
                .as_ref()
                .map_or(0, |checkpoint| checkpoint.sequence())
    );
    assert_eq!(
        complete(services, owner, &mut work, None),
        Err(ServiceFailure::BackupRepositoryRejected)
    );
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|failure| format!("catalog: {failure:?}"))?;
    let id = positron_governance::OperationId::from_bytes(task.to_bytes())?;
    assert!(
        positron_governance::DurableOperationAdministration::inspect(&catalog, id)?
            .ok_or("operation")?
            .backup_verification_report()
            .is_none()
    );
    Ok(())
}
