use super::*;
use positron_api::log_query::{
    self as api, log_query_cell::Value as Cell, log_query_event::Event,
    log_query_value::Value as Native,
};

fn execute_admitted_query(
    client: &api::LogQueryServiceClient,
    bearer: &str,
    request: &api::LogQueryRequest,
) -> Result<api::LogQueryResponse, Box<dyn std::error::Error>> {
    // A new fixture admission window, not a total request deadline: an attempt
    // started within five seconds retains the generated client's 30-second cap.
    let admission_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::time::Instant::now() >= admission_deadline {
            return Err("typed query admission window expired".into());
        }
        match client.execute(bearer, request) {
            Ok(response) => return Ok(response),
            Err(api::LogQueryServiceClientFailure::CapacityUnavailable) => {},
            Err(failure) => return Err(failure.into()),
        }
        if admission_deadline.saturating_duration_since(std::time::Instant::now())
            <= Duration::from_secs(1)
        {
            return Err("typed query admission window expired".into());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn acknowledged_logs_have_typed_native_query_headers_rows_and_terminal_truth()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("typed-query")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "typed-query")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let otlp = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;
    let endpoint = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let authorization = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("missing ingest credential")?
    );
    for body in ["first typed record", "second typed record"] {
        assert_status(
            http(
                otlp,
                "POST",
                "/v1/logs",
                &[
                    ("Authorization", &authorization),
                    ("Content-Type", "application/x-protobuf"),
                ],
                &otlp_body(body),
            )?,
            200,
        );
    }
    let client =
        api::LogQueryServiceClient::new(api::LogQueryTransport::PlaintextOptOut { endpoint })?;
    let mut request = api::LogQueryRequest {
        pipeline: "pipeline:v1 logs | range query_time 0 100 | project body, query_time, event_time, ingest_time, commit_position | limit 2".into(),
        budget: Some(api::LogQueryBudget { scanned_bytes: 1_048_576, decoded_records: 16, output_rows: 16, output_bytes: 16_384, memory_bytes: 1_048_576, cpu_work_units: 15, wall_seconds: 5, maximum_time_range_nanoseconds: 100 }),
    };
    let response = execute_admitted_query(
        &client,
        claim.query_secret().ok_or("missing query credential")?,
        &request,
    )
    .map_err(|failure| format!("typed complete query failed: {failure:?}"))?;
    let rendered = format!("{response:?}");
    for secret in [
        Some(claim.secret()),
        claim.ingest_secret(),
        claim.query_secret(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(
            !rendered.contains(secret),
            "query response exposed a credential"
        );
    }
    let Some(Event::Header(header)) = response
        .events
        .first()
        .and_then(|event| event.event.as_ref())
    else {
        return Err("missing first query header".into());
    };
    assert_eq!(
        header
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.value_type.as_str()))
            .collect::<Vec<_>>(),
        [
            ("body", "native_value"),
            ("query_time", "query_time"),
            ("event_time", "event_time"),
            ("ingest_time", "ingest_time"),
            ("commit_position", "commit_position"),
        ]
    );
    assert_eq!(
        header
            .ordering
            .iter()
            .map(|item| (item.column.as_str(), item.direction.as_str()))
            .collect::<Vec<_>>(),
        [
            ("query_time", "ascending"),
            ("commit_position", "ascending"),
            ("record_ordinal", "ascending")
        ]
    );
    let snapshot = header.snapshot.as_ref().ok_or("missing snapshot")?;
    assert!(snapshot.identity.iter().any(|byte| *byte != 0));
    assert!(snapshot.generation > 0);
    assert!(snapshot.frontier >= 2);
    let lease = header.lease.as_ref().ok_or("missing lease")?;
    assert!(lease.identity.iter().any(|byte| *byte != 0));
    assert!(lease.expiry_unix_seconds > 0);
    assert_eq!(header.effective_budget, request.budget);
    let batches = response
        .events
        .iter()
        .filter_map(|event| match event.event.as_ref() {
            Some(Event::Batch(batch)) => Some(batch),
            _ => None,
        })
        .collect::<Vec<_>>();
    let rows = batches
        .iter()
        .flat_map(|batch| &batch.rows)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    for (row, expected) in rows
        .iter()
        .zip(["first typed record", "second typed record"])
    {
        assert!(!row.replayed);
        let cells = row
            .cells
            .iter()
            .map(|cell| cell.value.as_ref().ok_or("missing cell"))
            .collect::<Result<Vec<_>, _>>()?;
        let [
            Cell::NativeValue(body),
            Cell::Timestamp(query),
            Cell::Timestamp(event),
            Cell::Timestamp(ingest),
            Cell::UnsignedInteger(commit),
        ] = cells.as_slice()
        else {
            return Err("unexpected typed query row".into());
        };
        assert_eq!(body.value, Some(Native::TextValue(expected.into())));
        assert_eq!(
            (query.unix_nanoseconds, query.provenance.as_str()),
            (Some(42), "event")
        );
        assert_eq!(
            (
                event.unix_nanoseconds,
                event.quality.as_str(),
                event.source_value
            ),
            (Some(42), "usable", Some(42))
        );
        assert!(ingest.unix_nanoseconds.is_some());
        assert_eq!(ingest.provenance, "kernel");
        assert!(*commit > 0);
    }
    let Some(Event::Terminal(terminal)) = response
        .events
        .last()
        .and_then(|event| event.event.as_ref())
    else {
        return Err("missing final query terminal".into());
    };
    assert_eq!(terminal.state, "complete");
    let stats = terminal.stats.as_ref().ok_or("missing terminal stats")?;
    assert_eq!(stats.records, 2);
    assert_eq!(stats.decoded_records, 2);
    assert_eq!(stats.limiting_budget, None);
    let final_batch = batches.last().ok_or("missing result batch")?;
    assert_eq!(stats.result_digest, final_batch.digest);
    assert_eq!(stats.last_sequence, Some(final_batch.sequence));
    for pair in batches.windows(2) {
        assert_eq!(pair[1].prior_digest, pair[0].digest);
        assert_eq!(pair[1].sequence, pair[0].sequence + 1);
    }
    request
        .budget
        .as_mut()
        .ok_or("missing request budget")?
        .scanned_bytes = 1;
    let incomplete = execute_admitted_query(
        &client,
        claim.query_secret().ok_or("missing query credential")?,
        &request,
    )
    .map_err(|failure| format!("typed scanned-budget query failed: {failure:?}"))?;
    let rendered = format!("{incomplete:?}");
    for secret in [
        Some(claim.secret()),
        claim.ingest_secret(),
        claim.query_secret(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(
            !rendered.contains(secret),
            "incomplete query response exposed a credential"
        );
    }
    let Some(Event::Terminal(terminal)) = incomplete
        .events
        .last()
        .and_then(|event| event.event.as_ref())
    else {
        return Err("missing incomplete terminal".into());
    };
    assert_eq!(
        (terminal.state.as_str(), terminal.reason.as_str()),
        ("incomplete", "budget_exhausted")
    );
    assert_eq!(
        terminal
            .stats
            .as_ref()
            .ok_or("missing incomplete stats")?
            .limiting_budget
            .as_deref(),
        Some("scanned_bytes")
    );
    shutdown_gracefully(process, &roots)?;
    Ok(())
}

#[path = "log_query/projections.rs"]
mod projections;
