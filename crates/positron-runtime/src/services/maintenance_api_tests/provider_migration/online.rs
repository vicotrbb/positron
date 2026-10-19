use super::*;

#[test]
fn native_admin_http_migrates_while_otlp_remains_serving() -> Result<(), Box<dyn std::error::Error>>
{
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = Fixture::new()?;
    let configuration = fixture.migration_configuration()?;
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
    let api = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::Api)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("API endpoint")?;
    let otlp = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == crate::ListenerRole::OtlpHttp)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("OTLP endpoint")?;
    let client =
        ProviderMigrationServiceClient::new(ProviderMigrationTransport::PlaintextOptOut {
            endpoint: api,
        })?;
    let status_request = ProviderMigrationRequest {
        action: "status".into(),
        expected_catalog_generation: None,
        idempotency_key: None,
        configuration_reference: None,
        operation_id: None,
    };
    assert_eq!(client.manage(&ingest, &status_request), Err(positron_api::provider_migration::ProviderMigrationServiceClientFailure::AuthenticationRejected));
    let services = process.services().ok_or("serving data services")?;
    ingest_over_http(otlp, &ingest, "before-online-cutover")?;
    for (index, action) in ["prepare", "activate"].into_iter().enumerate() {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let accepted = loop {
            let status =
                inspect_with_backpressure(&client, &administrator, &status_request, deadline)?;
            let phase = ProviderMigrationRequest {
                action: action.into(),
                expected_catalog_generation: Some(status.catalog_generation),
                idempotency_key: Some(format!("15151515-1515-4515-8515-{:012}", index + 1)),
                configuration_reference: Some(configuration.to_string_lossy().into_owned()),
                operation_id: None,
            };
            match client.manage(&administrator, &phase) {
                Ok(response) => break response,
                Err(positron_api::provider_migration::ProviderMigrationServiceClientFailure::StaleGeneration) if std::time::Instant::now() < deadline => {},
                Err(failure) => return Err(format!("{action} admission: {failure:?}").into()),
            }
        };
        let lookup = ProviderMigrationRequest {
            operation_id: accepted.operation.map(|operation| operation.id),
            ..status_request.clone()
        };
        loop {
            let current = inspect_with_backpressure(&client, &administrator, &lookup, deadline)?;
            if current
                .operation
                .as_ref()
                .is_some_and(|operation| operation.status == "succeeded")
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("online phase did not complete".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    ingest_over_http(otlp, &ingest, "after-online-cutover")?;
    let final_status = client.manage(&administrator, &status_request)?;
    assert_eq!(final_status.active_epoch, 2);
    assert_eq!(final_status.predecessor_epoch, Some(1));
    assert_eq!(process.health().readiness(), crate::Readiness::Ready);
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}

fn inspect_with_backpressure(
    client: &ProviderMigrationServiceClient,
    bearer: &str,
    request: &ProviderMigrationRequest,
    deadline: std::time::Instant,
) -> Result<positron_api::provider_migration::ProviderMigrationResponse, Box<dyn std::error::Error>>
{
    loop {
        match client.manage(bearer, request) {
            Ok(response) => return Ok(response),
            Err(positron_api::provider_migration::ProviderMigrationServiceClientFailure::CapacityUnavailable) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(failure) => return Err(failure.into()),
        }
    }
}

fn ingest_over_http(
    endpoint: SocketAddr,
    bearer: &str,
    text: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = request(text).encode_to_vec();
    let mut stream = TcpStream::connect(endpoint)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(&bytes)?;
    let mut response = String::new();
    stream.take(4096).read_to_string(&mut response)?;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "OTLP request did not succeed"
    );
    Ok(())
}
