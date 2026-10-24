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

struct HeldExport {
    request: ExportTraceServiceRequest,
    arrived: std::time::Instant,
    release: tokio::sync::oneshot::Sender<()>,
}
struct HeldCollector(std::sync::mpsc::SyncSender<HeldExport>);
#[tonic::async_trait]
impl TraceService for HeldCollector {
    async fn export(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
        let (release, held) = tokio::sync::oneshot::channel();
        self.0
            .try_send(HeldExport {
                request: request.into_inner(),
                arrived: std::time::Instant::now(),
                release,
            })
            .map_err(|_| tonic::Status::resource_exhausted("bounded collector"))?;
        held.await
            .map_err(|_| tonic::Status::cancelled("collector response released"))?;
        Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
    }
}

fn assert_operational_status(stage: &'static str, response: String, expected: u16) {
    let actual = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok());
    assert!(
        response.starts_with(&format!("HTTP/1.1 {expected} ")),
        "operational stage={stage} expected={expected} actual={actual:?}"
    );
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
    assert_operational_status(
        "initial_metrics_authentication",
        http(operations, "GET", "/metrics", &[], b"")?,
        401,
    );
    assert_operational_status(
        "initial_api_probe",
        http(
            api,
            "GET",
            "/telemetry-body-canary",
            &[("Authorization", &format!("Bearer {administrator}"))],
            b"",
        )?,
        404,
    );
    assert_operational_status(
        "initial_ingest_probe",
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
                QueryBudget::new(1_048_576, 16, 16, 1_048_576, 20_000_000, 60)?
            ),
        Err(positron_runtime::ServiceFailure::CapacityUnavailable)
    );
    use positron_api::log_query as log_api;
    let query_client =
        log_api::LogQueryServiceClient::new(log_api::LogQueryTransport::PlaintextOptOut {
            endpoint: api,
        })?;
    let query_request = log_api::LogQueryRequest {
        pipeline: "logs | range query_time 0 100 | limit 16".into(),
        budget: Some(log_api::LogQueryBudget {
            scanned_bytes: 1,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 15,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    // A valid public request that cannot fit the initialized principal's CPU
    // authority produces a real rejected wire attempt, not a budget event.
    let mut refused_request = query_request.clone();
    refused_request
        .budget
        .as_mut()
        .ok_or("missing refusal budget")?
        .cpu_work_units = 1024;
    assert!(
        matches!(
            query_client.execute(&query, &refused_request),
            Err(log_api::LogQueryServiceClientFailure::CapacityUnavailable)
        ),
        "oversized admission request must be rejected as capacity unavailable"
    );
    let admission_scrape = http(
        operations,
        "GET",
        "/metrics",
        &[
            ("Authorization", &format!("Bearer {administrator}")),
            ("Accept", "application/openmetrics-text; version=1.0.0"),
        ],
        b"",
    )
    .map_err(|error| format!("operational admission metrics scrape: {error}"))?;
    assert_operational_status("admission_metrics", admission_scrape.clone(), 200);
    assert!(
        admission_scrape
            .lines()
            .filter(|line| line.starts_with("positron_query_budget_failures_total{"))
            .all(|line| line
                .rsplit_once(' ')
                .and_then(|(_, value)| value.parse::<u64>().ok())
                == Some(0)),
        "an admission-refused query must not be credited with an execution budget dimension"
    );

    let (budget_response, capacity_refusals) =
        super::log_query::execute_admitted_query(&query_client, &query, &query_request)
            .map_err(|failure| format!("operational scanned-budget query failed: {failure:?}"))?;
    let rendered = format!("{budget_response:?}");
    for secret in [&administrator, &ingest, &query] {
        assert!(
            !rendered.contains(secret.as_str()),
            "query response exposed a credential"
        );
    }
    let Some(log_api::log_query_event::Event::Terminal(terminal)) = budget_response
        .events
        .last()
        .and_then(|event| event.event.as_ref())
    else {
        return Err("missing actual query budget terminal".into());
    };
    assert_eq!(
        (terminal.state.as_str(), terminal.reason.as_str()),
        ("incomplete", "budget_exhausted")
    );
    assert_eq!(
        terminal
            .stats
            .as_ref()
            .ok_or("missing query budget stats")?
            .limiting_budget
            .as_deref(),
        Some("scanned_bytes")
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut completed_requests = 0;
    let mut completed_query = false;
    let mut api_requests = 1;
    let mut ingest_requests = 1;
    let mut query_requests = 2 + capacity_refusals;
    let mut fresh_probes = 0;
    let mut http_probes = 0;
    while completed_requests < 2 || !completed_query {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let request = match received.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(request) => request,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                if std::time::Instant::now() < deadline =>
            {
                // Optional export can refuse an individual event. Produce fresh
                // operations only for a missing category, without assuming that
                // every issued request is exported or crediting aggregate loss.
                if fresh_probes < 8 {
                    fresh_probes += 1;
                    if completed_requests < 2 {
                        if http_probes % 2 == 0 {
                            assert_operational_status("export_api_probe", operational_probe(
                                api, "/telemetry-body-canary", &administrator, b"", deadline,
                            )?, 404);
                            api_requests += 1;
                        } else {
                            assert_operational_status("export_ingest_probe", operational_probe(
                                address(&process.bound_endpoints(), positron_runtime::ListenerRole::OtlpHttp)?,
                                "/v1/logs", &ingest, &otlp_body("stored-telemetry-canary"), deadline,
                            )?, 200);
                            ingest_requests += 1;
                        }
                        http_probes += 1;
                    } else if !completed_query {
                        assert_eq!(
                            process.services().ok_or("query services")?.query_log_bodies(
                                &query, "logs | range query_time 0 100 | limit 16",
                                QueryBudget::new(1_048_576, 16, 16, 1_048_576, 20_000_000, 60)?
                            ),
                            Err(positron_runtime::ServiceFailure::CapacityUnavailable)
                        );
                        query_requests += 1;
                    }
                }
                continue;
            },
            Err(error) => return Err(format!(
                "operational export arrival: {error}; completed_requests={completed_requests}; completed_query={completed_query}; fresh_probes={fresh_probes}; telemetry={}",
                process.health().operational_telemetry_snapshot()
            ).into()),
        };
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
    )
    .map_err(|error| format!("operational metrics scrape: {error}"))?;
    assert_operational_status("final_metrics", scrape.clone(), 200);
    assert!(scrape.ends_with("# EOF\n"));
    assert!(scrape.contains(&format!(
        "positron_requests_total{{listener=\"api\",outcome=\"request_rejected\"}} {api_requests}\n"
    )));
    assert!(scrape.contains(&format!(
        "positron_queries_total{{outcome=\"capacity_rejected\"}} {query_requests}\n"
    )));
    assert!(scrape.contains(&format!(
        "positron_requests_total{{listener=\"api\",outcome=\"capacity_rejected\"}} {}\n",
        1 + capacity_refusals,
    )));
    assert!(scrape.contains("positron_queries_total{outcome=\"success\"} 1\n"));
    assert!(
        scrape
            .lines()
            .filter(
                |line| line.starts_with("positron_query_budget_failures_total{")
                    && !line.starts_with(
                        "positron_query_budget_failures_total{dimension=\"scanned_bytes\"}"
                    )
            )
            .all(|line| line
                .rsplit_once(' ')
                .and_then(|(_, value)| value.parse::<u64>().ok())
                == Some(0)),
        "no other execution budget dimension was exercised"
    );
    let scanned_budget_failures = scrape.lines().find_map(|line| {
        line.strip_prefix("positron_query_budget_failures_total{dimension=\"scanned_bytes\"} ")
            .and_then(|value| value.parse::<u64>().ok())
    });
    assert_eq!(
        scanned_budget_failures,
        Some(1),
        "only the proven scanned-budget execution must increment its dimension counter"
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
    assert!(scrape.contains(&format!(
        "positron_ingest_records_total{{signal=\"logs\",outcome=\"committed\"}} {ingest_requests}\n"
    )));
    shutdown_gracefully(process, &roots)?;
    stop.send(()).map_err(|_| "collector stopped early")?;
    collector
        .join()
        .map_err(|_| "collector panic")?
        .map_err(std::io::Error::other)?;
    Ok(())
}

// Fresh probes share the original observation deadline and retain a strict
// response bound; they do not extend the export or socket budget.
fn operational_probe(
    address: SocketAddr,
    path: &str,
    credential: &str,
    body: &[u8],
    deadline: std::time::Instant,
) -> Result<String, Box<dyn std::error::Error>> {
    let remaining = || {
        deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("operational probe deadline")
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)
        .map_err(|error| format!("operational probe connect: {error}"))?;
    let method = if body.is_empty() { "GET" } else { "POST" };
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(body);
    stream
        .set_write_timeout(Some(remaining()?))
        .map_err(|error| format!("operational probe write timeout: {error}"))?;
    stream
        .write_all(&request)
        .map_err(|error| format!("operational probe write: {error}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| format!("operational probe shutdown: {error}"))?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        stream
            .set_read_timeout(Some(remaining()?))
            .map_err(|error| format!("operational probe read timeout: {error}"))?;
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if bytes.len() + count > 65_536 {
                    return Err("operational probe response bound".into());
                }
                bytes.extend_from_slice(&buffer[..count]);
            },
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) => return Err(format!("operational probe read: {error}").into()),
        }
    }
    Ok(String::from_utf8(bytes)?)
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
                .add_service(TraceServiceServer::new(HeldCollector(sent)))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .map_err(|error| error.to_string())
        })
    });
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), Box<dyn std::error::Error>> {
            let (process, administrator, _, _) = operational_process(&roots, destination, false)?;
            let initial = received
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| format!("initial stalled export arrival: {error}"))?;
            let counter = |metric: &str| -> Result<u64, Box<dyn std::error::Error>> {
                process
                    .health()
                    .operational_telemetry_snapshot()
                    .lines()
                    .find_map(|line| line.strip_prefix(&format!("{metric} ")))
                    .ok_or_else(|| format!("missing counter {metric}").into())
                    .and_then(|value| Ok(value.parse()?))
            };
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while counter("positron_operational_trace_failures_total")? == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "bounded stalled export"
                );
                std::thread::yield_now();
            }
            drop(initial.release);
            let failures = counter("positron_operational_trace_failures_total")?;
            let api = address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::Api,
            )?;
            let request = |path| -> Result<(), Box<dyn std::error::Error>> {
                assert_status(
                    http(
                        api,
                        "GET",
                        path,
                        &[("Authorization", &format!("Bearer {administrator}"))],
                        b"",
                    )?,
                    404,
                );
                Ok(())
            };
            // A completed marker flushes every earlier FIFO startup export. Counter reads
            // use the public health port and generate no additional request events.
            request("/deadline-marker")?;
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                let arrival = received
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                    .map_err(|error| format!("marker export arrival: {error}"))?;
                let marker = arrival
                    .request
                    .resource_spans
                    .iter()
                    .flat_map(|resource| &resource.scope_spans)
                    .flat_map(|scope| &scope.spans)
                    .any(|span| span.name == "request_completed");
                let exported = counter("positron_operational_trace_exported_total")?;
                arrival
                    .release
                    .send(())
                    .map_err(|_| "export handler canceled before marker acknowledgment")?;
                if marker {
                    while counter("positron_operational_trace_exported_total")? == exported {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "marker response completion"
                        );
                        std::thread::yield_now();
                    }
                    break;
                }
            }
            assert_eq!(
                counter("positron_operational_trace_failures_total")?,
                failures
            );
            let canary_started = std::time::Instant::now();
            request("/deadline-canary")?;
            let canary = received
                .recv_timeout(Duration::from_secs(2))
                .map_err(|error| format!("canary export arrival: {error}"))?;
            assert!(
                canary
                    .request
                    .resource_spans
                    .iter()
                    .flat_map(|resource| &resource.scope_spans)
                    .flat_map(|scope| &scope.spans)
                    .any(|span| span.name == "request_completed")
            );
            assert!(canary_started.elapsed() < Duration::from_secs(1));
            assert!(canary.arrived.elapsed() < Duration::from_secs(1));
            assert!(
                !canary.release.is_closed(),
                "canary handler must remain pending at Drain"
            );
            assert_eq!(
                counter("positron_operational_trace_failures_total")?,
                failures
            );
            let mut draining = process.begin_shutdown();
            assert!(received.recv_timeout(Duration::from_millis(1200)).is_err());
            draining.poll()?;
            assert_eq!(
                draining.finish(ShutdownTrigger::FirstSignal),
                positron_runtime::ExitOutcome::Graceful
            );
            drop(canary.release);
            Ok(())
        },
    ));
    drop(received);
    let stopped = stop.send(()).map_err(|_| "collector stopped early");
    let joined = collector
        .join()
        .map_err(|_| "collector panic")
        .and_then(|result| result.map_err(|_| "collector server failed"));
    match outcome {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    stopped?;
    joined?;
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

#[tokio::test]
async fn controlled_collector_receipt_keeps_the_exact_rpc_pending_until_release()
-> Result<(), Box<dyn std::error::Error>> {
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let collector = HeldCollector(sent);
    let request = ExportTraceServiceRequest::default();
    let call = collector.export(tonic::Request::new(request.clone()));
    tokio::pin!(call);
    tokio::select! {
        biased;
        result = &mut call => panic!("collector completed before receipt ownership: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    let arrival = received.try_recv()?;
    assert_eq!(arrival.request, request);
    tokio::select! {
        biased;
        result = &mut call => panic!("receipt alone completed held RPC: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    arrival
        .release
        .send(())
        .map_err(|_| "held RPC ended before release")?;
    assert_eq!(
        call.await?.into_inner(),
        ExportTraceServiceResponse::default()
    );
    Ok(())
}
