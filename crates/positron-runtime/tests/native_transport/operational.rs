use super::*;
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use std::sync::Arc;

struct Collector(
    std::sync::mpsc::SyncSender<ExportTraceServiceRequest>,
    Duration,
);
#[tonic::async_trait]
impl TraceService for Collector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        self.0
            .try_send(request.into_inner())
            .map_err(|_| tonic::Status::resource_exhausted("bounded collector"))?;
        tokio::time::sleep(self.1).await;
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

#[test]
fn real_operational_scrape_and_external_otlp_export_are_bounded_and_secret_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("ops")?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let collector_address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let (sent, received) = std::sync::mpsc::sync_channel(32);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let collector = std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|failure| failure.to_string())?;
        runtime.block_on(async {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(
                tokio::net::TcpListener::from_std(listener)
                    .map_err(|failure| failure.to_string())?,
            );
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(Collector(sent, Duration::ZERO)))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .map_err(|failure| failure.to_string())
        })
    });
    let (process, administrator, ingest, query) =
        operational_process(&roots, collector_address, false)?;
    let operations = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Operations,
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_status(http(operations, "GET", "/metrics", &[], b"")?, 401);
    assert_status(
        http(
            api,
            "GET",
            "/telemetry-body-canary",
            &[("Authorization", &format!("Bearer {administrator}"))],
            b"",
        )?,
        404,
    );
    assert_status(
        http(
            address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::OtlpHttp,
            )?,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &format!("Bearer {ingest}")),
                ("Content-Type", "application/x-protobuf"),
            ],
            &otlp_body("stored-telemetry-canary"),
        )?,
        200,
    );
    assert_eq!(
        process
            .services()
            .ok_or("query services")?
            .query_log_bodies(
                &query,
                "logs | range query_time 0 100 | limit 16",
                QueryBudget::new(1, 16, 16, 1_048_576, 1_048_576, 60)?
            ),
        Err(positron_runtime::ServiceFailure::CapacityUnavailable)
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut completed_requests = 0;
    let mut completed_query = false;
    while completed_requests < 2 || !completed_query {
        let request =
            received.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))?;
        let encoded = request.encode_to_vec();
        assert!(encoded.len() < 4096);
        for canary in [&administrator, &ingest, &query] {
            assert!(
                !encoded
                    .windows(canary.len())
                    .any(|bytes| bytes == canary.as_bytes())
            );
        }
        let rendered = String::from_utf8_lossy(&encoded);
        assert!(!rendered.contains("telemetry-body-canary"));
        assert!(!rendered.contains("stored-telemetry-canary"));
        let resource = request
            .resource_spans
            .first()
            .and_then(|resource| resource.resource.as_ref())
            .ok_or("operational service resource")?;
        assert!(
            resource
                .attributes
                .iter()
                .any(|attribute| attribute.key == "service.name")
        );
        for span in request
            .resource_spans
            .iter()
            .flat_map(|resource| resource.scope_spans.iter())
            .flat_map(|scope| scope.spans.iter())
        {
            if span.name == "request_completed" {
                completed_requests += 1;
            }
            if span.name == "query_completed" {
                completed_query = true;
            }
        }
    }
    let scrape = http(
        operations,
        "GET",
        "/metrics",
        &[
            ("Authorization", &format!("Bearer {administrator}")),
            ("Accept", "application/openmetrics-text; version=1.0.0"),
        ],
        b"",
    )?;
    assert_status(scrape.clone(), 200);
    assert!(scrape.ends_with("# EOF\n"));
    assert!(
        scrape
            .contains("positron_requests_total{listener=\"api\",outcome=\"request_rejected\"} 1\n")
    );
    assert!(scrape.contains("positron_queries_total{outcome=\"capacity_rejected\"} 1\n"));
    assert!(
        scrape.contains("positron_query_budget_failures_total{dimension=\"scanned_bytes\"} 1\n")
    );
    assert!(scrape.contains("positron_security_warning{warning=\"otlp_http_plaintext\"} 1\n"));
    assert!(
        scrape
            .contains("positron_maintenance_tasks_by_class{class=\"compaction\",phase=\"queued\"}")
    );
    assert!(!scrape.contains(&administrator));
    assert!(!scrape.contains("telemetry-body-canary"));
    assert!(!scrape.contains("stored-telemetry-canary"));
    assert!(!scrape.contains(&ingest));
    assert!(
        scrape.contains("positron_ingest_records_total{signal=\"logs\",outcome=\"committed\"} 1\n")
    );
    shutdown_gracefully(process, &roots)?;
    stop.send(()).map_err(|_| "collector stopped early")?;
    collector
        .join()
        .map_err(|_| "collector panic")?
        .map_err(std::io::Error::other)?;
    Ok(())
}

fn operational_process(
    roots: &TestRoots,
    collector_address: SocketAddr,
    self_destination: bool,
) -> Result<(positron_runtime::RunningProcess, String, String, String), Box<dyn std::error::Error>>
{
    let configuration = format!(
        "schema_version=1\n[diagnostics]\ntrace_otlp_grpc_address=\"{collector_address}\"\n[listener]\ncontrol_path=\"{}\"\noperations_bind_address=\"127.0.0.1:0\"\napi_bind_address=\"127.0.0.1:0\"\notlp_grpc_bind_address=\"127.0.0.1:0\"\notlp_http_bind_address=\"127.0.0.1:0\"\nloki_push_bind_address=\"127.0.0.1:0\"\noperations_transport=\"plaintext\"\napi_transport=\"plaintext\"\notlp_grpc_transport=\"plaintext\"\notlp_http_transport=\"plaintext\"\nloki_push_transport=\"plaintext\"\n[storage]\ndata_directory=\"{}\"\nsecrets_directory=\"{}\"\n[security]\nlocal_key_file=\"{}\"\n",
        roots.parent.join("control.sock").display(),
        roots.data.display(),
        roots.secrets.display(),
        roots.secrets.join("local-root-key.v1").display(),
    );
    let effective = Arc::new(positron_config::resolve(
        positron_config::ConfigurationInputs::try_new(
            Some(&configuration),
            positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?,
    )?);
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let administrator = claim.secret().to_owned();
    let query = claim.query_secret().ok_or("query credential")?.to_owned();
    let ingest = claim.ingest_secret().ok_or("ingest credential")?.to_owned();
    let host = NativeHost::new(if self_destination {
        let ephemeral = "127.0.0.1:0".parse()?;
        NativeBindings::new(
            roots.parent.join("control.sock"),
            ephemeral,
            ephemeral,
            collector_address,
            ephemeral,
            ephemeral,
        )?
    } else {
        NativeBindings::from_effective(&effective)?
    });
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly)
            .with_effective_configuration(effective),
        HostInputs::new(&host, &host),
    )?;
    Ok((process, administrator, ingest, query))
}

#[test]
fn actual_bound_self_destination_is_refused_and_unreachable_collector_is_visible()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    for self_destination in [true, false] {
        let roots = TestRoots::new("ops-refusal")?;
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let destination = socket.local_addr()?;
        drop(socket);
        let (process, administrator, _, _) =
            operational_process(&roots, destination, self_destination)?;
        let operations = address(
            &process.bound_endpoints(),
            positron_runtime::ListenerRole::Operations,
        )?;
        let metric = if self_destination {
            "positron_operational_trace_refused_total"
        } else {
            "positron_operational_trace_failures_total"
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let scrape = http(
                operations,
                "GET",
                "/metrics",
                &[("Authorization", &format!("Bearer {administrator}"))],
                b"",
            )?;
            if scrape.lines().any(|line| {
                line.strip_prefix(&format!("{metric} "))
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_some_and(|value| value > 0)
            }) {
                assert!(scrape.contains("positron_operational_trace_exported_total 0\n"));
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "observable export outcome: {scrape}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        shutdown_gracefully(process, &roots)?;
    }
    Ok(())
}

#[test]
fn stalled_collector_has_bounded_deadline_and_drain_starts_no_more_exports()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("ops-deadline")?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let destination = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let (sent, received) = std::sync::mpsc::sync_channel(32);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let collector = std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(async {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(
                tokio::net::TcpListener::from_std(listener).map_err(|error| error.to_string())?,
            );
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(Collector(
                    sent,
                    Duration::from_millis(1500),
                )))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .map_err(|error| error.to_string())
        })
    });
    let (process, administrator, _, _) = operational_process(&roots, destination, false)?;
    received.recv_timeout(Duration::from_secs(2))?;
    let operations = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Operations,
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let scrape = http(
            operations,
            "GET",
            "/metrics",
            &[("Authorization", &format!("Bearer {administrator}"))],
            b"",
        )?;
        if scrape.lines().any(|line| {
            line.strip_prefix("positron_operational_trace_failures_total ")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value > 0)
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bounded stalled-collector outcome: {scrape}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_status(
        http(
            api,
            "GET",
            "/deadline-canary",
            &[("Authorization", &format!("Bearer {administrator}"))],
            b"",
        )?,
        404,
    );
    // Synchronize on the next actual send, then drain while it is in flight.
    received.recv_timeout(Duration::from_secs(2))?;
    let mut draining = process.begin_shutdown();
    assert!(received.recv_timeout(Duration::from_millis(1200)).is_err());
    draining.poll()?;
    assert_eq!(
        draining.finish(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    stop.send(()).map_err(|_| "collector stopped early")?;
    collector
        .join()
        .map_err(|_| "collector panic")?
        .map_err(std::io::Error::other)?;
    Ok(())
}

#[test]
fn fenced_metrics_preserve_authenticated_process_truth_and_explicit_owner_absence()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("ops-fenced")?;
    let (mut process, administrator, _, _) =
        operational_process(&roots, "127.0.0.1:1".parse()?, false)?;
    let operations = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Operations,
    )?;
    process
        .services()
        .ok_or("serving owner")?
        .request_integrity_fence_with(positron_runtime::IntegrityFenceReason::AmbiguousIntegrity);
    process.poll()?;
    assert_eq!(
        process.health().phase(),
        positron_runtime::ProcessPhase::Fenced
    );
    assert_status(http(operations, "GET", "/metrics", &[], b"")?, 401);
    let scrape = http(
        operations,
        "GET",
        "/metrics",
        &[("Authorization", &format!("Bearer {administrator}"))],
        b"",
    )?;
    assert_status(scrape.clone(), 200);
    assert!(scrape.contains("positron_process_phase{phase=\"fenced\"} 1\n"));
    assert!(scrape.contains("positron_process_ready 0\n"));
    assert!(scrape.contains("positron_operational_owner_available 0\n"));
    assert!(!scrape.contains("positron_resource_usage{"));
    shutdown_gracefully(process, &roots)?;
    Ok(())
}
