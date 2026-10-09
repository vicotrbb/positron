//! Observe actual key-envelope failure while the database is serving.
use super::fencing_causes::substitute_tenant_envelope;
use super::*;

#[test]
fn online_key_mismatch_immediately_closes_data_admission() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    drop(initialized);
    let (host, mut process) = serving_process(&fixture, "online")?;
    let services = process.services().ok_or("services")?;
    let scope = log_scope(&services)?;
    assert_eq!(process.health().readiness(), crate::Readiness::Ready);
    {
        let _gate = services.catalog_operation()?;
        substitute_tenant_envelope(&services.instance)?;
    }
    let outcome = services.verify_online_integrity(
        &administrator,
        &OnlineVerificationRequest::new(
            scope.tenant_id().to_canonical_text(),
            "logs".into(),
            scope.shard_id().value(),
            None,
            None,
        )
        .encode()?,
    );
    assert!(
        matches!(
            outcome,
            Err(MaintenanceServiceFailure::AdministrationUnavailable)
        ),
        "key substitution verification outcome: {outcome:?}"
    );
    assert_eq!(
        process.health().readiness(),
        crate::Readiness::NotReady,
        "unsafe detection closes admission before returning"
    );
    assert_data_closed(&process)?;
    assert!(process.apply_pending_integrity_fence());
    assert_eq!(
        process.health().integrity_fence_reason(),
        Some(crate::IntegrityFenceReason::KeyEnvelopeMismatch)
    );
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    assert!(process.services().is_none());
    drop(services);
    assert_key_inspection("online", &administrator, &process)?;
    assert!(matches!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful | crate::ExitOutcome::Fenced
    ));
    drop(host);
    Ok(())
}

#[test]
fn native_background_key_mismatch_retains_operator_cause() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    drop(initialized);
    let (host, mut process) = serving_process(&fixture, "background")?;
    let services = process.services().ok_or("services")?;
    let scope = log_scope(&services)?;
    {
        let _gate = services.catalog_operation()?;
        substitute_tenant_envelope(&services.instance)?;
    }
    let gate = services.catalog_operation()?;
    let catalog = open_catalog(&services.instance)?;
    let snapshot = catalog.pin()?;
    let task = MaintenanceTask::integrity_scrub(
        MaintenanceTaskId::new([0xfb; 16]).map_err(|_| "task id")?,
        MaintenanceScope::segment(scope.tenant_id(), scope.signal_kind(), scope.shard_id()),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(snapshot.number(), 1).map_err(|_| "preconditions")?,
        snapshot.integrity_scope_source_identity(scope)?,
        0,
    )
    .map_err(|_| "task")?;
    services
        .instance
        .maintenance_coordinator()
        .submit_and_persist(&catalog, task, 0)
        .map_err(|_| "persist task")?;
    drop(catalog);
    drop(gate);
    services.notify_maintenance_worker();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while process.health().readiness() == crate::Readiness::Ready
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(process.health().readiness(), crate::Readiness::NotReady);
    assert_data_closed(&process)?;
    assert!(process.apply_pending_integrity_fence());
    assert_eq!(
        process.health().integrity_fence_reason(),
        Some(crate::IntegrityFenceReason::KeyEnvelopeMismatch)
    );
    assert_eq!(process.health().phase(), crate::ProcessPhase::Fenced);
    assert!(process.services().is_none());
    drop(services);
    assert_key_inspection("background", &administrator, &process)?;
    let outcome = process.shutdown(ShutdownTrigger::FirstSignal);
    assert!(matches!(
        outcome,
        crate::ExitOutcome::Graceful | crate::ExitOutcome::Fenced
    ));
    drop(host);
    Ok(())
}

fn log_scope(services: &ServiceHandle) -> Result<SegmentScope, Box<dyn std::error::Error>> {
    let _gate = services.catalog_operation()?;
    open_catalog(&services.instance)?
        .pin()?
        .reachable_ledger_scopes(services.instance.default_tenant_id(), SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or_else(|| "scope".into())
}
fn serving_process(
    fixture: &Fixture,
    label: &str,
) -> Result<(NativeHost, crate::RunningProcess), Box<dyn std::error::Error>> {
    let control = std::env::temp_dir().join(format!(
        "positron83-live-{}-{}.sock",
        std::process::id(),
        label
    ));
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new(
        control, loopback, loopback, loopback, loopback, loopback,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    Ok((host, process))
}

fn assert_key_inspection(
    label: &str,
    administrator: &str,
    process: &crate::RunningProcess,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        process
            .bound_endpoints()
            .iter()
            .map(|endpoint| endpoint.role())
            .collect::<Vec<_>>(),
        [
            crate::ListenerRole::Control,
            crate::ListenerRole::Operations
        ]
    );
    let control = std::env::temp_dir().join(format!(
        "positron83-live-{}-{}.sock",
        std::process::id(),
        label
    ));
    let mut socket = std::os::unix::net::UnixStream::connect(control)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        socket,
        "GET /control/fenced/inspection HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {administrator}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    socket.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let (_, body) = response.split_once("\r\n\r\n").ok_or("inspection")?;
    let inspection: serde_json::Value = serde_json::from_str(body)?;
    assert_eq!(inspection["reason"], "key_envelope_mismatch");
    assert_eq!(inspection["readiness"], "not_ready");
    Ok(())
}

fn assert_data_closed(process: &crate::RunningProcess) -> Result<(), Box<dyn std::error::Error>> {
    let address = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::OtlpHttp)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("OTLP HTTP")?;
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "pending unsafe-key fence must refuse data admission: {response}"
    );
    Ok(())
}
