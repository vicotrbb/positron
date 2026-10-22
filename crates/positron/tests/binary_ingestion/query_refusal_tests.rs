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
