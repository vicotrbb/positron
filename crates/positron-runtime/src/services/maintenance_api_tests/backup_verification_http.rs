use super::*;

#[test]
fn independent_verification_http_publishes_and_replays_the_signed_report()
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
    let (_, accepted) = create_current(
        &client,
        &services,
        &administrator,
        &repository_path,
        "11111111-1111-4111-8111-111111111111",
    )?;
    assert_eq!(accepted.operation.status, "pending");
    let first = finish(&client, &services, &administrator, &accepted.operation.id)?;
    assert_eq!(first.operation.status, "succeeded");
    let first_status = BackupRequest::decode(&serde_json::to_vec(
        &serde_json::json!({"action":"status", "operation_id":accepted.operation.id}),
    )?)?;
    let first_status = client
        .manage(&administrator, &first_status)
        .map_err(|failure| format!("verification target status: {failure:?}"))?;
    let verification_generation = {
        let _gate = services.catalog_operation()?;
        open_catalog(&services.instance)?.pin()?.number()
    };
    let verification = BackupRequest::decode(&serde_json::to_vec(&serde_json::json!({
        "action":"verify", "repository_id":"5b5b5b5b-5b5b-5b5b-5b5b-5b5b5b5b5b5b", "snapshot_id":accepted.operation.id,
        "expected_manifest_checksum":first_status.receipt.ok_or("verified target receipt")?.manifest_checksum,
        "expected_catalog_generation": 1,
        "idempotency_key":"abababab-abab-4bab-8bab-abababababab"
    }))?)?;
    assert!(verification_generation > 1);
    let original = verification.clone();
    let (verification, verifying) =
        submit_verification_current(&client, &services, &administrator, verification)?;
    let mut expected = original;
    expected.expected_catalog_generation = verification.expected_catalog_generation;
    assert_eq!(verification, expected);
    assert_ne!(verification.expected_catalog_generation, Some(1));
    let verified = finish(&client, &services, &administrator, &verifying.operation.id)?;
    assert_eq!(verified.kind, "verification");
    assert_eq!(verified.operation.status, "succeeded");
    assert_eq!(
        verified.operation.irreversible_boundary,
        "verification_report_published"
    );
    assert!(!verified.cleanup_pending);
    assert!(
        verified
            .verification_report
            .as_ref()
            .is_some_and(|report| !report.is_empty())
    );
    assert!(verified.verification_report_checksum.is_some());
    assert_eq!(
        client
            .manage(&administrator, &verification)
            .map_err(|failure| format!("verification exact replay: {failure:?}"))?,
        verified
    );
    let mut foreign_repository = verification.clone();
    foreign_repository.repository_id = Some("99999999-9999-4999-8999-999999999999".into());
    assert_eq!(
        client.manage(&administrator, &foreign_repository),
        Err(BackupServiceClientFailure::SourceUnavailable)
    );
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    fs::remove_dir_all(repository_path)?;
    Ok(())
}

// Only a rejected stale Catalog selector can be refreshed; the accepted exact
// request is retained for the replay assertions above.
fn submit_verification_current(
    client: &BackupServiceClient,
    services: &ServiceHandle,
    bearer: &str,
    mut request: BackupRequest,
) -> Result<(BackupRequest, BackupResponse), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match client.manage(bearer, &request) {
            Ok(response) => return Ok((request, response)),
            Err(BackupServiceClientFailure::PreconditionFailed) => {
                let generation = {
                    let _gate = services.catalog_operation()?;
                    open_catalog(&services.instance)?.pin()?.number()
                };
                if request.expected_catalog_generation == Some(generation)
                    || std::time::Instant::now() >= deadline
                {
                    return Err(BackupServiceClientFailure::PreconditionFailed.into());
                }
                request.expected_catalog_generation = Some(generation);
            },
            Err(failure) => return Err(failure.into()),
        }
    }
}
