use super::*;

#[test]
fn acknowledged_absent_attribute_is_missing_in_the_public_query_response()
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
    assert_status(
        http(
            otlp,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &authorization),
                ("Content-Type", "application/x-protobuf"),
            ],
            &otlp_body("typed projection record"),
        )?,
        200,
    );
    let client =
        api::LogQueryServiceClient::new(api::LogQueryTransport::PlaintextOptOut { endpoint })?;
    let projected_request = api::LogQueryRequest {
        pipeline:
            r#"pipeline:v1 logs | range query_time 0 100 | project record["absent"] | limit 2"#
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
    let absent = client.execute(
        claim.query_secret().ok_or("missing query credential")?,
        &projected_request,
    )?;
    let rendered = format!("{absent:?}");
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
            "absent attribute response exposed a credential"
        );
    }
    let Some(Event::Header(header)) = absent.events.first().and_then(|event| event.event.as_ref())
    else {
        return Err("missing absent attribute header".into());
    };
    assert_eq!(
        header
            .columns
            .iter()
            .map(|column| (
                column.name.as_str(),
                column.value_type.as_str(),
                column.nullable
            ))
            .collect::<Vec<_>>(),
        [(r#"record["absent"]"#, "attribute_occurrence_set", true)]
    );
    let cells = absent
        .events
        .iter()
        .filter_map(|event| match event.event.as_ref() {
            Some(Event::Batch(batch)) => Some(batch),
            _ => None,
        })
        .flat_map(|batch| &batch.rows)
        .flat_map(|row| &row.cells)
        .collect::<Vec<_>>();
    assert_eq!(cells.len(), 1);
    assert!(
        cells
            .iter()
            .all(|cell| matches!(cell.value, Some(Cell::Missing(_)))),
        "absent attribute must be Missing, not null or an empty occurrence set"
    );
    let Some(Event::Terminal(terminal)) =
        absent.events.last().and_then(|event| event.event.as_ref())
    else {
        return Err("missing absent attribute terminal".into());
    };
    assert_eq!(terminal.state, "complete");
    shutdown_gracefully(process, &roots)?;
    Ok(())
}
