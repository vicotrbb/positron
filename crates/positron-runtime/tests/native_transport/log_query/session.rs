use super::*;
use positron_sdk::log_query::{self as api, log_query_event::Event};

#[test]
fn public_query_pages_resume_the_same_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("query-session")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "query-session")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let ingest = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;
    let endpoint = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let authorization = format!("Bearer {}", claim.ingest_secret().ok_or("ingest key")?);
    let payload = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    for _ in 0..2 {
        assert_status(
            http(
                ingest,
                "POST",
                "/v1/logs",
                &[
                    ("Authorization", &authorization),
                    ("Content-Type", "application/x-protobuf"),
                ],
                &payload,
            )?,
            200,
        );
    }
    let client =
        api::LogQueryServiceClient::new(api::LogQueryTransport::PlaintextOptOut { endpoint })?;
    let bearer = claim.query_secret().ok_or("query key")?;
    let query = api::LogQueryRequest {
        pipeline: "pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2"
            .into(),
        budget: Some(api::LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 16,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    let first = admitted_session(
        &client,
        bearer,
        &api::LogQuerySessionRequest {
            operation: Some(api::log_query_session_request::Operation::Execute(
                query.clone(),
            )),
            batch_limit: 1,
        },
    )
    .map_err(|failure| format!("first page: {failure:?}"))?;
    let header = first
        .events
        .first()
        .and_then(|event| event.event.as_ref())
        .ok_or("header")?;
    let Event::Header(header) = header else {
        return Err("header missing".into());
    };
    let snapshot = header.snapshot.clone();
    let Event::Terminal(terminal) = first
        .events
        .last()
        .and_then(|event| event.event.as_ref())
        .ok_or("terminal")?
    else {
        return Err("terminal missing".into());
    };
    assert_eq!(terminal.state, "continued");
    let cursor = terminal.continuation_cursor.clone().ok_or("continuation")?;
    let second = client
        .session(
            bearer,
            &api::LogQuerySessionRequest {
                operation: Some(api::log_query_session_request::Operation::Resume(cursor)),
                batch_limit: 1,
            },
        )
        .map_err(|failure| format!("resume page: {failure:?}"))?;
    let Event::Header(header) = second
        .events
        .first()
        .and_then(|event| event.event.as_ref())
        .ok_or("resume header")?
    else {
        return Err("resume header missing".into());
    };
    assert_eq!(header.snapshot, snapshot);
    assert!(
        second
            .events
            .iter()
            .any(|event| matches!(&event.event, Some(Event::Batch(batch)) if batch.sequence >= 1))
    );
    let cancellable = admitted_session(
        &client,
        bearer,
        &api::LogQuerySessionRequest {
            operation: Some(api::log_query_session_request::Operation::Execute(query)),
            batch_limit: 1,
        },
    )?;
    let Event::Terminal(terminal) = cancellable
        .events
        .last()
        .and_then(|event| event.event.as_ref())
        .ok_or("cancellable terminal")?
    else {
        return Err("cancellable terminal missing".into());
    };
    let request = api::LogQueryCancelRequest {
        cursor: Some(api::log_query_cancel_request::Cursor::Query(
            terminal
                .continuation_cursor
                .clone()
                .ok_or("cancel cursor")?,
        )),
    };
    assert!(client.cancel(bearer, &request)?.cancelled);
    assert!(client.cancel(bearer, &request)?.cancelled);
    if let Some(api::log_query_cancel_request::Cursor::Query(cursor)) = request.cursor.as_ref() {
        assert_eq!(
            client.session(
                bearer,
                &api::LogQuerySessionRequest {
                    operation: Some(api::log_query_session_request::Operation::Resume(
                        cursor.clone()
                    )),
                    batch_limit: 1,
                }
            ),
            Err(api::LogQueryServiceClientFailure::SnapshotExpired)
        );
    }
    assert_eq!(
        client.cancel("not-a-credential", &request),
        Err(api::LogQueryServiceClientFailure::AuthenticationRejected)
    );
    shutdown_gracefully(process, &roots)?;
    Ok(())
}

fn admitted_session(
    client: &api::LogQueryServiceClient,
    bearer: &str,
    request: &api::LogQuerySessionRequest,
) -> Result<api::LogQueryResponse, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match client.session(bearer, request) {
            Err(api::LogQueryServiceClientFailure::CapacityUnavailable)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100));
            },
            result => return result.map_err(Into::into),
        }
    }
}
