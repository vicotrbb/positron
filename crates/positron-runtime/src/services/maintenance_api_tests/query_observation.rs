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
    Ok(())
}
