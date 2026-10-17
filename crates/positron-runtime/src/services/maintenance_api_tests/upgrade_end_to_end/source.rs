//! The real source admission and Process Drain fixture.
use super::*;

#[inline(never)]
pub(super) fn drain_source_case(
    http: bool,
    suspended: bool,
    crash_before_drain: bool,
    installed: bool,
) -> Result<DrainedFixture, Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = Arc::new(super::upgrade_offline::configuration(&fixture)?);
    let (instance, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let export = fixture.recovery_export_directory()?;
    let identity = age::x25519::Identity::generate();
    let recipients =
        positron_kernel::RecoveryRecipients::parse(&[identity.to_public().to_string()])?;
    let bundle = export.join("recovery.age");
    instance.create_recovery_bundle(&bundle, &recipients)?;
    instance.verify_recovery_bundle(
        &bundle,
        positron_kernel::RecoveryUnlock::Identity(&identity),
    )?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    services.ingest_otlp_logs(
        &ingest,
        request("upgrade-lifecycle-preserved").encode_to_vec(),
    )?;
    crate::services::upgrade_backup::tests::initialize_registered_repository(
        &instance,
        &services,
        &administrator,
        &export,
    )?;
    if suspended {
        let actor = instance.attribute(
            positron_governance::PresentedCredential::parse(&administrator)?,
            positron_governance::RequestedIntent::SystemAdministration,
            positron_governance::CompatibilityHints::none(),
        )?;
        instance.transition_tenant_lifecycle(
            actor,
            instance.default_tenant_id(),
            positron_domain::lifecycle::TenantLifecycleState::Suspended,
            positron_governance::ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x91; 16])?,
        )?;
        assert_eq!(
            services.query_log_bodies(
                &query,
                "logs | range query_time 0 100 | limit 1",
                QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 6)?
            ),
            Err(crate::ServiceFailure::Unauthorized)
        );
    }
    let epoch = instance
        .catalog_format_epoch()?
        .ok_or("initial epoch")?
        .value();
    drop(services);
    drop(instance);
    let executable = std::env::current_exe()?;
    let bytes = fs::read(&executable)?;
    let digest = Sha256::digest(&bytes).into();
    let source = fixture_release(
        epoch,
        ProductVersion::parse_exact(env!("CARGO_PKG_VERSION"))?,
        digest,
        bytes.len() as u64,
    )?;
    // This exercises product lifecycle with synthetic signed target metadata, not two-build qualification.
    let version = ProductVersion {
        major: 0,
        minor: 0,
        patch: 1,
    };
    let target = fixture_release(epoch, version, digest, bytes.len() as u64)?;
    drop(bytes);
    let configuration = if http || crash_before_drain || installed {
        Arc::new(installed_configuration(
            &fixture,
            &export,
            &source,
            &target,
            &executable,
            Some(&query),
        )?)
    } else {
        configuration
    };
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let native = Box::new(NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?));
    let foreground = super::super::live_key_fencing::ForegroundTasks(native.as_ref());
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(Arc::clone(&configuration)),
        if http {
            HostInputs::new(native.as_ref(), &foreground)
        } else {
            HostInputs::new(&listeners, &tasks)
        },
    )?;
    let services = process.services().ok_or("source services")?;
    let gate = services.catalog_operation()?;
    let generation = open_catalog(&services.instance)?.pin()?.number();
    assert_eq!(
        services
            .instance
            .catalog_format_epoch()?
            .ok_or("runtime epoch")?
            .value(),
        epoch,
        "configuration publication must preserve Catalog format"
    );
    drop(gate);
    drop(services);
    let artifacts = target
        .manifest()
        .artifacts
        .iter()
        .map(|artifact| UpgradeArtifactInput {
            role: artifact.role,
            platform: artifact.platform.clone(),
            path: executable.clone(),
        })
        .collect();
    let admission = UpgradeRequest::new(
        (source.clone(), target.clone()),
        artifacts,
        [44; 16],
        3600,
        generation,
        AdministrativeIdempotencyKey::new([0xe1; 16])?,
    )?;
    let accepted = if http {
        let endpoint = process
            .bound_endpoints()
            .into_iter()
            .find(|e| e.role() == crate::ListenerRole::Api)
            .and_then(|e| e.socket_address())
            .ok_or("API endpoint")?;
        let client = positron_api::upgrade::UpgradeServiceClient::new(
            positron_api::upgrade::UpgradeTransport::PlaintextOptOut { endpoint },
        )?;
        let mut body = positron_api::upgrade::UpgradeRequest {
            action: "start".into(),
            candidate_manifest: Some(super::hex(target.digest())),
            repository_id: Some("2c2c2c2c-2c2c-2c2c-2c2c-2c2c2c2c2c2c".into()),
            retention_seconds: Some(3600),
            expected_catalog_generation: Some(generation),
            idempotency_key: Some("e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1".into()),
            operation_id: None,
        };
        assert!(
            client.manage(&ingest, &body).is_err(),
            "Ingest key must not authorize native Upgrade"
        );
        let services = process.services().ok_or("fresh source services")?;
        let gate = services.catalog_operation()?;
        body.expected_catalog_generation = Some(open_catalog(&services.instance)?.pin()?.number());
        drop(gate);
        drop(services);
        let logical_request = body.clone();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut attempts = 0;
        let response = loop {
            attempts += 1;
            match client.manage(&administrator, &body) {
                Ok(response) => break response,
                Err(positron_api::upgrade::UpgradeServiceClientFailure::PreconditionFailed) => {
                    // An operator may resubmit the unchanged intent only after
                    // proving a stale basis, never after an ambiguous acceptance.
                    let services = process.services().ok_or("refresh services")?;
                    let _gate = services.catalog_operation()?;
                    let observed = services
                        .upgrade_configuration
                        .get()
                        .ok_or("installed configuration")?
                        .observed()?;
                    assert_eq!(
                        observed.effective().audit_binding_digest(),
                        configuration.audit_binding_digest(),
                        "configuration changed during intent refresh"
                    );
                    let catalog = open_catalog(&services.instance)?;
                    let generation = catalog.pin()?.number();
                    if body
                        .expected_catalog_generation
                        .is_none_or(|previous| generation <= previous)
                    {
                        return Err("precondition refusal without an advanced Catalog basis".into());
                    }
                    if positron_governance::DurableOperationAdministration::inspect_by_idempotency(
                        &catalog,
                        AdministrativeIdempotencyKey::new([0xe1; 16])?,
                    )?
                    .is_some()
                    {
                        return Err("refused request already has durable intent".into());
                    }
                    let mut unchanged = body.clone();
                    unchanged.expected_catalog_generation =
                        logical_request.expected_catalog_generation;
                    assert_eq!(
                        unchanged, logical_request,
                        "logical intent changed during basis refresh"
                    );
                    if attempts >= 4 || Instant::now() >= deadline {
                        return Err(format!(
                            "native admission PreconditionFailed after {attempts} attempts; proven advanced Catalog basis {generation}"
                        ).into());
                    }
                    body.expected_catalog_generation = Some(generation);
                },
                Err(positron_api::upgrade::UpgradeServiceClientFailure::Transport) => {
                    // Acceptance is ambiguous: inspect the same key, never send start again.
                    let lookup = positron_api::upgrade::UpgradeRequest {
                        action: "lookup".into(),
                        candidate_manifest: None,
                        repository_id: None,
                        retention_seconds: None,
                        expected_catalog_generation: None,
                        idempotency_key: body.idempotency_key.clone(),
                        operation_id: None,
                    };
                    break loop {
                        match client.manage(&administrator, &lookup) {
                            Ok(response) => {
                                let details = response.details.as_ref().ok_or("lookup details")?;
                                assert_eq!(details.target_manifest, super::hex(target.digest()));
                                assert_eq!(details.repository_id, "2c2c2c2c-2c2c-2c2c-2c2c-2c2c2c2c2c2c");
                                break response;
                            },
                            Err(positron_api::upgrade::UpgradeServiceClientFailure::Transport
                                | positron_api::upgrade::UpgradeServiceClientFailure::SourceUnavailable
                                | positron_api::upgrade::UpgradeServiceClientFailure::CapacityUnavailable)
                                if Instant::now() < deadline => {
                                    std::thread::sleep(Duration::from_millis(100));
                                },
                            Err(error) => return Err(format!("ambiguous admission lookup: {error:?}").into()),
                        }
                    };
                },
                Err(error) => {
                    return Err(
                        format!("native admission {error:?} after {attempts} attempts").into(),
                    );
                },
            }
        };
        assert!(response.details.is_some());
        let wire_operation = response.operation.ok_or("native operation")?;
        assert_eq!(
            wire_operation.phase,
            positron_api::upgrade::UpgradePhase::Preflight
        );
        let durable = process
            .pending_upgrade_operation()?
            .ok_or("durable native intent")?;
        assert_eq!(
            wire_operation.id,
            super::hex(durable.operation_id().to_bytes())
        );
        let parameters = durable.upgrade_parameters().ok_or("durable parameters")?;
        assert_eq!(parameters.target().manifest_digest(), target.digest());
        assert_eq!(parameters.backup().repository().repository_id(), [44; 16]);
        assert_eq!(parameters.backup().retention_seconds(), 3600);
        process
            .resume_configured_upgrade_drain(&configuration)?
            .ok_or("native pending token")?
    } else {
        process
            .accept_upgrade(&administrator, admission)
            .map_err(|e| format!("live accept {e:?}; source epoch={epoch}"))?
    };
    let id = if crash_before_drain {
        let id = accepted.operation().operation_id();
        let services = process.services().ok_or("crash source services")?;
        let gate = services.catalog_operation()?;
        let catalog = open_catalog(&services.instance)?;
        let now = services.instance.retention_time.security_time_seconds()?;
        let actor = Administration::resume_upgrade_actor(&catalog, id, now)?;
        // Controlled durable timestamp fixture: real public intent transitions,
        // no trusted-clock mutation and no physical Drain publication.
        let ahead = now.checked_add(10).ok_or("future intent time")?;
        Administration::begin(&catalog, actor, id, ahead)?;
        Administration::advance_upgrade(&catalog, actor, id, UpgradeStage::Draining, ahead)?;
        assert!(services.instance.graceful_shutdown_record()?.is_none());
        drop(catalog);
        drop(gate);
        drop(services);
        drop(process);
        id
    } else {
        process
            .begin_upgrade(accepted)
            .map_err(|error| format!("begin drain {error:?}"))?
            .finish(ShutdownTrigger::FirstSignal)
            .map_err(|error| format!("finish drain {error:?}"))?
    };
    Ok(DrainedFixture {
        fixture,
        configuration,
        query,
        target,
        version,
        id,
    })
}
