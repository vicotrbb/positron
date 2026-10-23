use super::*;
use positron_api::log_query::query_rejection;

fn rejection(status: u16, code: &str) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_slice(&query_rejection(status, code)?)?)
}

#[test]
fn query_authentication_refusal_waits_for_explicit_capacity_then_requires_typed_401() -> TestResult
{
    let body = br#"{"pipeline":"logs"}"#;
    let (result, requests) = scripted_requests(
        &[
            (429, rejection(429, "capacity_unavailable")?),
            (401, rejection(401, "authentication_rejected")?),
        ],
        |endpoint| {
            super::super::super::archive::query_authentication_refusal(
                endpoint,
                body,
                "administrator-canary",
                ["query-canary", "administrator-canary", "ingest-canary"],
                1,
            )?;
            Ok("rejected".into())
        },
    )?;
    assert_eq!(result?, "rejected");
    assert_eq!(requests, vec![serde_json::json!({"pipeline":"logs"}); 2]);
    Ok(())
}

#[test]
fn query_authentication_refusal_does_not_retry_other_failures() -> TestResult {
    for response in [
        (0, serde_json::Value::Null),
        (503, rejection(503, "query_unavailable")?),
        (429, serde_json::json!({"code":"unknown"})),
        (401, serde_json::json!({"code":"unknown"})),
    ] {
        let (result, requests) = scripted_requests(
            &[response, (401, rejection(401, "authentication_rejected")?)],
            |endpoint| {
                super::super::super::archive::query_authentication_refusal(
                    endpoint,
                    br#"{"pipeline":"logs"}"#,
                    "administrator-canary",
                    ["query-canary", "administrator-canary", "ingest-canary"],
                    1,
                )?;
                Ok("rejected".into())
            },
        )?;
        assert!(result.is_err());
        assert_eq!(requests.len(), 1);
    }
    Ok(())
}

#[test]
fn query_authentication_refusal_keeps_the_existing_five_second_capacity_budget() -> TestResult {
    let mut responses = vec![(429, rejection(429, "capacity_unavailable")?); 8];
    responses.push((401, rejection(401, "authentication_rejected")?));
    let started = Instant::now();
    let (result, requests) = scripted_requests(&responses, |endpoint| {
        super::super::super::archive::query_authentication_refusal(
            endpoint,
            br#"{"pipeline":"logs"}"#,
            "administrator-canary",
            ["query-canary", "administrator-canary", "ingest-canary"],
            1,
        )?;
        Ok("rejected".into())
    })?;
    assert!(
        result
            .expect_err("capacity cannot extend the existing budget")
            .to_string()
            .contains("HTTP/1.1 429 ")
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(requests.len() < responses.len());
    assert!(
        requests
            .iter()
            .all(|request| request == &serde_json::json!({"pipeline":"logs"}))
    );
    Ok(())
}

fn budget_query() -> positron_api::log_query::LogQueryRequest {
    use positron_api::log_query::*;
    LogQueryRequest {
        pipeline: "logs | range query_time 0 100 | limit 16".into(),
        budget: Some(LogQueryBudget {
            scanned_bytes: 1_048_576,
            decoded_records: 16,
            output_rows: 16,
            output_bytes: 1,
            memory_bytes: 1_048_576,
            cpu_work_units: 15,
            wall_seconds: 5,
            maximum_time_range_nanoseconds: 100,
        }),
    }
}

fn encoded_budget_incomplete() -> TestResult<serde_json::Value> {
    use positron_api::log_query::*;
    let budget = budget_query().budget.ok_or("query budget")?;
    let response = LogQueryResponse {
        events: vec![
            LogQueryEvent {
                event: Some(log_query_event::Event::Header(LogQueryHeader {
                    columns: vec![LogQueryColumn {
                        name: "body".into(),
                        value_type: "native_value".into(),
                        nullable: false,
                    }],
                    snapshot: Some(LogQuerySnapshot {
                        identity: vec![1; 32],
                        generation: 1,
                        frontier: 0,
                    }),
                    ordering: vec![LogQueryOrdering {
                        column: "query_time".into(),
                        value_type: "query_time".into(),
                        direction: "ascending".into(),
                    }],
                    effective_budget: Some(budget),
                    lease: Some(LogQueryLease {
                        identity: vec![1; 16],
                        expiry_unix_seconds: 1,
                    }),
                    initial_cursor: None,
                })),
            },
            LogQueryEvent {
                event: Some(log_query_event::Event::Terminal(LogQueryTerminal {
                    state: "incomplete".into(),
                    reason: "budget_exhausted".into(),
                    stats: Some(LogQueryStats {
                        result_digest: vec![0; 32],
                        cumulative_budget: Some(budget),
                        limiting_budget: Some("output_bytes".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            },
        ],
    };
    Ok(serde_json::from_slice(&response.encode()?)?)
}

#[test]
fn budget_query_waits_for_explicit_capacity_then_requires_typed_incomplete() -> TestResult {
    let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = std::sync::Arc::clone(&bodies);
    let request = budget_query();
    let expected = request.encode()?;
    let (result, _, write_error) = scripted_requests_with_writer(
        &[
            (429, rejection(429, "capacity_unavailable")?),
            (200, encoded_budget_incomplete()?),
        ],
        |endpoint| {
            super::super::super::archive::query_output_bytes_incomplete(
                endpoint,
                "query-canary",
                &request,
            )?;
            Ok("incomplete".into())
        },
        move |stream, response, body| {
            recorded
                .lock()
                .map_err(|_| std::io::Error::other("request capture"))?
                .push(body.to_vec());
            stream.write_all(response)
        },
    )?;
    if let Some(error) = write_error {
        return Err(error.into());
    }
    assert_eq!(result?, "incomplete");
    assert_eq!(
        *bodies.lock().map_err(|_| "request capture")?,
        vec![expected; 2]
    );
    Ok(())
}

#[test]
fn budget_query_does_not_retry_authentication_transport_or_unknown_refusals() -> TestResult {
    let request = budget_query();
    for response in [
        (0, serde_json::Value::Null),
        (401, rejection(401, "authentication_rejected")?),
        (503, rejection(503, "query_unavailable")?),
        (429, serde_json::json!({"code": "unknown"})),
        (200, serde_json::json!({"events": []})),
    ] {
        let (result, requests) = scripted_requests(
            &[response, (200, encoded_budget_incomplete()?)],
            |endpoint| {
                super::super::super::archive::query_output_bytes_incomplete(
                    endpoint,
                    "query-canary",
                    &request,
                )?;
                Ok("incomplete".into())
            },
        )?;
        assert!(result.is_err());
        assert_eq!(requests.len(), 1);
    }
    Ok(())
}

#[test]
fn budget_query_capacity_does_not_extend_the_original_five_second_budget() -> TestResult {
    let request = budget_query();
    let mut responses = vec![(429, rejection(429, "capacity_unavailable")?); 8];
    responses.push((200, encoded_budget_incomplete()?));
    let started = Instant::now();
    let (result, requests) = scripted_requests(&responses, |endpoint| {
        super::super::super::archive::query_output_bytes_incomplete(
            endpoint,
            "query-canary",
            &request,
        )?;
        Ok("incomplete".into())
    })?;
    assert_eq!(
        result
            .expect_err("capacity cannot become a budget execution")
            .to_string(),
        "budget query did not execute successfully"
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(!requests.is_empty());
    assert!(requests.len() < responses.len());
    let expected: serde_json::Value = serde_json::from_slice(&request.encode()?)?;
    assert!(requests.iter().all(|actual| actual == &expected));
    Ok(())
}
