//! Native framing and caller authorization refuse Upgrade without durable effects.
use super::*;

#[test]
fn native_upgrade_enforces_body_bound_and_authentication_without_accepting_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let (instance, ingest, _, administrator) = fixture.initialized_with_admin()?;
    drop(instance);
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        fixture.control_socket_path(),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
    )?);
    // Native listeners execute normally; unrelated maintenance stays idle so
    // exact Catalog equality measures these refused requests alone.
    let foreground = super::live_key_fencing::ForegroundTasks(&host);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &foreground),
    )?;
    let services = process.services().ok_or("serving services")?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint")?;
    let before = open_catalog(&services.instance)?.pin()?;
    let unauthorized = post(endpoint, &ingest, b"malformed")?;
    assert!(unauthorized.starts_with("HTTP/1.1 401 "), "{unauthorized}");
    assert!(unauthorized.contains("authentication_rejected"));
    unchanged(&services, &process, before.identity())?;

    let request = positron_api::upgrade::UpgradeRequest {
        action: "start".into(),
        candidate_manifest: Some("ab".repeat(32)),
        repository_id: Some("11111111-1111-1111-1111-111111111111".into()),
        retention_seconds: Some(3600),
        expected_catalog_generation: Some(before.number()),
        idempotency_key: Some("22222222-2222-2222-2222-222222222222".into()),
        operation_id: None,
    };
    let mut body = request.encode()?;
    body.resize(positron_api::upgrade::MAX_REQUEST_BYTES, b' ');
    let bounded = post(endpoint, &administrator, &body)?;
    // Exact-limit canonical JSON reaches the installed-candidate prerequisite.
    assert!(bounded.starts_with("HTTP/1.1 409 "), "{bounded}");
    assert!(bounded.contains("precondition_failed"));
    unchanged(&services, &process, before.identity())?;

    body.push(b' ');
    let oversized = post(endpoint, &administrator, &body)?;
    assert!(oversized.starts_with("HTTP/1.1 413 "), "{oversized}");
    unchanged(&services, &process, before.identity())?;
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}

fn unchanged(
    services: &ServiceHandle,
    process: &crate::RunningProcess,
    identity: positron_kernel::CatalogGenerationId,
) -> Result<(), Box<dyn std::error::Error>> {
    let _gate = services.catalog_operation()?;
    let catalog = open_catalog(&services.instance)?;
    assert_eq!(catalog.pin()?.identity(), identity);
    assert!(
        positron_governance::DurableOperationAdministration::inspect_by_idempotency(
            &catalog,
            positron_governance::AdministrativeIdempotencyKey::new([0x22; 16])?,
        )?
        .is_none()
    );
    assert_eq!(process.health().phase(), crate::ProcessPhase::Serving);
    Ok(())
}

fn post(
    endpoint: SocketAddr,
    credential: &str,
    body: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(endpoint)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST /v1/upgrades:manage HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    let mut response = String::new();
    stream.take(8192).read_to_string(&mut response)?;
    Ok(response)
}
