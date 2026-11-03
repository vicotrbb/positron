use super::*;
use positron_sdk::log_query::{self as api, log_query_event::Event};

#[test]
fn public_tail_preserves_unacknowledged_delivery_and_can_cancel_its_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tail-session")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "tail-session")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let endpoint = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let client =
        api::LogQueryServiceClient::new(api::LogQueryTransport::PlaintextOptOut { endpoint })?;
    let bearer = claim.query_secret().ok_or("query key")?;
    let query = api::LogQueryRequest {
        pipeline: "pipeline:v1 logs | range query_time 0 100 | project commit_position | limit all"
            .into(),
        budget: Some(api::LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 15,
            wall_seconds: 60,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    let response = client
        .session(
            bearer,
            &api::LogQuerySessionRequest {
                operation: Some(api::log_query_session_request::Operation::Tail(
                    api::LogQueryTailRequest {
                        query: Some(query.clone()),
                        ..Default::default()
                    },
                )),
                batch_limit: 1,
            },
        )
        .map_err(|failure| format!("initial tail: {failure:?}"))?;
    let mut tracker = api::BatchTracker::tail();
    assert!(tracker.filter(&response)?.is_empty());
    let Event::Terminal(terminal) = response
        .events
        .last()
        .and_then(|event| event.event.as_ref())
        .ok_or("tail terminal")?
    else {
        return Err("tail terminal missing".into());
    };
    assert_eq!(
        (terminal.state.as_str(), terminal.reason.as_str()),
        ("incomplete", "disconnected")
    );
    let cursor = terminal.continuation_cursor.clone().ok_or("tail cursor")?;
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
    let authorization = format!("Bearer {}", claim.ingest_secret().ok_or("ingest key")?);
    let ingest = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;
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
    let poll = |cursor: Vec<u8>, acknowledgement| {
        client.session(
            bearer,
            &api::LogQuerySessionRequest {
                operation: Some(api::log_query_session_request::Operation::Tail(
                    api::LogQueryTailRequest {
                        query: Some(query.clone()),
                        cursor: Some(cursor),
                        acknowledgement,
                        historical_rows: None,
                    },
                )),
                batch_limit: 1,
            },
        )
    };
    let delivered = poll(cursor, None).map_err(|failure| format!("delivery: {failure:?}"))?;
    assert_eq!(tracker.filter(&delivered)?.len(), 1);
    let batch = delivered
        .events
        .iter()
        .find_map(|event| match event.event.as_ref() {
            Some(Event::Batch(batch)) => Some(batch.clone()),
            _ => None,
        })
        .ok_or("delivered tail batch")?;
    let cursor = continuation(&delivered)?;
    let replayed = poll(cursor, None).map_err(|failure| format!("replay: {failure:?}"))?;
    assert!(tracker.filter(&replayed)?.is_empty());
    let replay = replayed
        .events
        .iter()
        .find_map(|event| match event.event.as_ref() {
            Some(Event::Batch(batch)) => Some(batch),
            _ => None,
        })
        .ok_or("replayed tail batch")?;
    assert_eq!(
        (replay.sequence, &replay.digest),
        (batch.sequence, &batch.digest)
    );
    assert!(replay.rows.iter().all(|row| row.replayed));
    let acknowledged = poll(continuation(&replayed)?, tracker.acknowledgement())
        .map_err(|failure| format!("acknowledgement: {failure:?}"))?;
    assert!(tracker.filter(&acknowledged)?.is_empty());
    let Event::Terminal(terminal) = acknowledged
        .events
        .last()
        .and_then(|event| event.event.as_ref())
        .ok_or("acknowledged terminal")?
    else {
        return Err("acknowledged terminal missing".into());
    };
    assert_eq!(
        terminal
            .stats
            .as_ref()
            .ok_or("acknowledged statistics")?
            .records,
        1
    );
    let cursor = continuation(&acknowledged)?;
    let cancellation = api::LogQueryCancelRequest {
        cursor: Some(api::log_query_cancel_request::Cursor::Tail(cursor)),
    };
    assert!(
        client
            .cancel(bearer, &cancellation)
            .map_err(|failure| format!("cancellation: {failure:?}"))?
            .cancelled
    );
    assert!(
        client
            .cancel(bearer, &cancellation)
            .map_err(|failure| format!("repeated cancellation: {failure:?}"))?
            .cancelled
    );
    shutdown_gracefully(process, &roots)?;
    Ok(())
}

fn continuation(response: &api::LogQueryResponse) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    response
        .events
        .last()
        .and_then(|event| match event.event.as_ref() {
            Some(Event::Terminal(terminal)) => terminal.continuation_cursor.clone(),
            _ => None,
        })
        .ok_or_else(|| "tail continuation missing".into())
}
