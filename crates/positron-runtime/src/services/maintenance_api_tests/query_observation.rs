use super::*;

#[test]
fn malformed_public_query_keeps_its_response_and_reports_a_closed_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (instance, _, query, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(instance)?;
    let state = crate::health::ProcessState::starting();
    state.transition(crate::ProcessPhase::Serving);
    let health = state.health();
    services.attach_health(health.clone());
    let body = br#"{protected-query-canary"#;
    assert!(matches!(
        services.execute_log_query(&query, body),
        Err((400, "invalid_request"))
    ));
    let output = health
        .operational_logs_json()
        .map_err(|_| "operational ring unavailable")?;
    assert!(!output.contains("protected-query-canary"));
    let value: serde_json::Value = serde_json::from_str(&output)?;
    let event = value
        .as_array()
        .ok_or("event array")?
        .iter()
        .find(|event| {
            event.get("event").and_then(serde_json::Value::as_str) == Some("query_completed")
        })
        .ok_or("query event")?;
    assert_eq!(
        event.get("failure").and_then(serde_json::Value::as_str),
        Some("invalid_request")
    );
    let stages = event
        .get("finite_stage_millis")
        .and_then(serde_json::Value::as_array)
        .ok_or("finite Execute stage timing missing")?;
    assert_eq!(stages.len(), 14);
    assert!(stages.iter().all(|value| value.as_u64().is_some()));
    // Decode failure occurs before the gate, Catalog, ledger and execution.
    assert!(stages.iter().skip(2).all(|value| value.as_u64() == Some(0)));
    assert_eq!(event["finite_terminal"], 0);
    assert_eq!(event["finite_wall_seconds"], 0);
    assert_eq!(event["finite_limiting_budget"], 0);
    assert!(event.to_string().len() < 510);
    assert!(matches!(
        services.execute_log_query_session(&query, body),
        Err((400, "invalid_request"))
    ));
    let output = health
        .operational_logs_json()
        .map_err(|_| "operational ring unavailable")?;
    let events: serde_json::Value = serde_json::from_str(&output)?;
    let last = events
        .as_array()
        .and_then(|values| values.last())
        .ok_or("Session event")?;
    assert_eq!(
        last.get("event").and_then(serde_json::Value::as_str),
        Some("query_completed")
    );
    assert!(last.get("finite_stage_millis").is_none());
    assert!(last.get("finite_terminal").is_none());
    assert!(last.get("finite_wall_seconds").is_none());
    assert!(last.get("finite_limiting_budget").is_none());
    Ok(())
}

#[test]
fn public_finite_query_reports_eager_stages_and_native_terminal_without_changing_response()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::log_query as api;
    let fixture = Fixture::new()?;
    let (instance, _, query, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(instance)?;
    let state = crate::health::ProcessState::starting();
    state.transition(crate::ProcessPhase::Serving);
    let health = state.health();
    services.attach_health(health.clone());
    let request = api::LogQueryRequest {
        pipeline: "pipeline:v1 logs | range query_time 0 100 | limit 16".into(),
        budget: Some(api::LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 16_384,
            memory_bytes: 1_048_576,
            cpu_work_units: 15,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    };
    let (bytes, reservation) = services
        .execute_log_query(&query, &request.encode()?)
        .map_err(|(status, reason)| format!("query refused {status} {reason}"))?;
    let response = api::LogQueryResponse::decode(&bytes)?;
    assert!(response.events.last().is_some_and(|event| matches!(
        event.event,
        Some(api::log_query_event::Event::Terminal(_))
    )));
    drop(reservation);
    let output = health
        .operational_logs_json()
        .map_err(|_| "operational ring unavailable")?;
    assert!(!output.contains(&query));
    assert!(!output.contains(&request.pipeline));
    let events: serde_json::Value = serde_json::from_str(&output)?;
    let event = events
        .as_array()
        .ok_or("events")?
        .iter()
        .find(|event| {
            event.get("event").and_then(serde_json::Value::as_str) == Some("query_completed")
        })
        .ok_or("query event")?;
    assert_eq!(
        event.get("outcome").and_then(serde_json::Value::as_str),
        Some("success")
    );
    let stages = event
        .get("finite_stage_millis")
        .and_then(serde_json::Value::as_array)
        .ok_or("finite stages")?;
    assert_eq!(stages.len(), 14);
    assert!(
        stages
            .iter()
            .all(|value| value.as_u64().is_some_and(|value| value <= 999_999))
    );
    assert_eq!(event["finite_terminal"], 1);
    assert!(event["finite_wall_seconds"].as_u64().is_some());
    assert_eq!(event["finite_limiting_budget"], 0);
    Ok(())
}
