use crate::*;
use std::io::{Read, Write};

struct Root(std::path::PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn contended_resource_observation_preserves_serving_admission_after_control_completes()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let root =
        Root(std::env::temp_dir().join(format!("positron-rc-{}-{nonce}", std::process::id())));
    std::fs::create_dir_all(root.0.join("data"))?;
    std::fs::create_dir_all(root.0.join("secrets"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.0.join("secrets"),
            std::fs::Permissions::from_mode(0o700),
        )?;
    }
    let paths = BootstrapPaths::new(
        &root.0.join("data"),
        &root.0.join("secrets"),
        positron_kernel::MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let endpoint = "127.0.0.1:0".parse()?;
    let host = NativeHost::new(NativeBindings::new(
        root.0.join("c.sock"),
        endpoint,
        endpoint,
        endpoint,
        endpoint,
        endpoint,
    )?);
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let health = process.health();
    let instance = process
        .instance
        .as_ref()
        .ok_or("instance authority")?
        .clone();
    let observed = instance._authority.with_control_contention_for_test(|| {
        assert!(matches!(
            instance._authority.observe_disk(),
            Err(positron_kernel::GovernorFailure::GovernorContended { .. })
        ));
        let observed = process.poll();
        assert_eq!(
            health.readiness(),
            Readiness::Ready,
            "healthy canonical control contention is not a readiness outage"
        );
        observed
    })?;
    assert_eq!(observed, Ok(()));
    assert!(
        health
            .operational_log_snapshot()
            .map_err(|_| "operational log unavailable")?
            .contains("resource_observation_deferred")
    );
    assert_eq!(health.phase(), ProcessPhase::Serving);
    assert_eq!(health.liveness(), Liveness::Live);
    let address = process
        .bound_endpoints()
        .into_iter()
        .find_map(|endpoint| match endpoint {
            BoundEndpoint::Tcp {
                role: ListenerRole::OtlpHttp,
                address,
            } => Some(address),
            _ => None,
        })
        .ok_or("OTLP HTTP listener")?;
    let response = ingest(address, claim.ingest_secret().ok_or("ingest credential")?)?;
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "admission after control completes: {response}"
    );
    assert_eq!(
        health.readiness(),
        Readiness::Ready,
        "completed control work is not a dependency outage: clock={:?} resources={:?} events={:?}",
        instance.retention_time.status(),
        instance.resource_governor().inspect(),
        health.operational_log_snapshot()
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(
        instance
            ._authority
            .with_volume_observation_failure_for_test(|| process.poll()),
        Ok(())
    );
    assert_eq!(health.phase(), ProcessPhase::Serving);
    assert_eq!(health.liveness(), Liveness::Live);
    assert_eq!(health.readiness(), Readiness::NotReady);
    assert!(
        health
            .operational_log_snapshot()
            .map_err(|_| "operational log unavailable")?
            .contains("dependency_resources_unavailable")
    );
    match ingest(address, claim.ingest_secret().ok_or("ingest credential")?) {
        Ok(response) => assert!(
            response.starts_with("HTTP/1.1 429 ") || response.starts_with("HTTP/1.1 503 "),
            "outage admission must refuse: {response}"
        ),
        Err(failure) => assert_eq!(
            failure.kind(),
            std::io::ErrorKind::ConnectionReset,
            "outage transport must refuse, not hang"
        ),
    }
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(
        instance
            ._authority
            .with_control_contention_for_test(|| process.poll())?,
        Ok(())
    );
    assert_eq!(
        health.readiness(),
        Readiness::NotReady,
        "a deferred observation cannot clear the earlier real outage"
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    process
        .poll()
        .map_err(|outcome| format!("restored owner: {outcome:?}"))?;
    assert_eq!(health.readiness(), Readiness::Ready);
    let response = ingest(address, claim.ingest_secret().ok_or("ingest credential")?)?;
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "restored admission: {response}"
    );
    let services = process.services().ok_or("services")?;
    assert_eq!(
        services.query_log_bodies(
            claim.query_secret().ok_or("query credential")?,
            "logs | range query_time 0 100 | limit 16",
            positron_query::QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(16)?
        )?,
        ["after-control-contention", "after-control-contention"],
        "only the two acknowledged requests are durable"
    );
    drop(services);
    drop(instance);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        ExitOutcome::Graceful
    );
    Ok(())
}

fn ingest(address: std::net::SocketAddr, credential: &str) -> Result<String, std::io::Error> {
    let body = br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"43","body":{"stringValue":"after-control-contention"}}]}]}]}"#;
    let mut stream = std::net::TcpStream::connect(address)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    write!(
        stream,
        "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        credential,
        body.len()
    )?;
    stream.write_all(body)?;
    let mut response = String::new();
    stream.take(8192).read_to_string(&mut response)?;
    Ok(response)
}
