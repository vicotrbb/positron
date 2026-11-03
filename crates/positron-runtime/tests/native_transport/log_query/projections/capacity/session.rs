use super::*;
use positron_sdk::log_query as sdk;

fn session_fixture(
    replies: &[(u16, Vec<u8>)],
    request: &sdk::LogQuerySessionRequest,
) -> TestResult<(Option<sdk::LogQueryResponse>, Vec<Vec<u8>>)> {
    use positron_sdk::{api_keys::protobuf::CapabilityResponse, log_query as sdk};
    let capability = serde_json::to_vec(&CapabilityResponse {
        api_major: 1,
        schema_digest: positron_sdk::generated::SchemaDigest::canonical()
            .as_str()
            .into(),
        capability: if matches!(
            request.operation,
            Some(sdk::log_query_session_request::Operation::Tail(_))
        ) {
            positron_sdk::generated::Capability::QueryTail
        } else {
            positron_sdk::generated::Capability::QuerySessions
        } as i32,
        availability: positron_sdk::generated::CapabilityAvailability::Implemented as i32,
        ..Default::default()
    })?;
    let exchanges = replies
        .iter()
        .flat_map(|(status, body)| {
            [
                (reply(200, &capability, false), false),
                (reply(*status, body, *status == 429), false),
            ]
        })
        .collect();
    let (result, bodies) = scripted(exchanges, |endpoint| {
        let client =
            sdk::LogQueryServiceClient::new(sdk::LogQueryTransport::PlaintextOptOut { endpoint })?;
        Ok(
            crate::log_query::session::admitted_session(&client, "fixture-session-key", request)
                .ok(),
        )
    })?;
    Ok((result?, bodies))
}

fn session_requests() -> TestResult<Vec<sdk::LogQuerySessionRequest>> {
    use sdk::log_query_session_request::Operation;
    let query = sdk::LogQueryRequest::decode(&request().encode()?)?;
    let mut tail = query.clone();
    tail.pipeline = tail.pipeline.replace("limit 2", "limit all");
    Ok(vec![
        Operation::Execute(query),
        Operation::Resume(vec![1]),
        Operation::Tail(sdk::LogQueryTailRequest {
            query: Some(tail),
            cursor: Some(vec![1]),
            ..Default::default()
        }),
    ]
    .into_iter()
    .map(|operation| sdk::LogQuerySessionRequest {
        operation: Some(operation),
        batch_limit: 1,
    })
    .collect())
}

#[test]
fn session_capacity_backoff_keeps_the_exact_cursor_and_preserves_the_next_page() -> TestResult<()> {
    let expected = missing_response()?.encode_session()?;
    for request in session_requests()?.into_iter().take(2) {
        let started = Instant::now();
        let (response, bodies) = session_fixture(
            &[
                (429, api::query_rejection(429, "capacity_unavailable")?),
                (200, expected.clone()),
            ],
            &request,
        )?;
        assert_eq!(
            response.ok_or("missing admitted page")?.encode_session()?,
            expected
        );
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "canonical AfterBackoff requires one second"
        );
        assert_eq!(bodies.len(), 4);
        assert_eq!(
            bodies[1], bodies[3],
            "only the same request can be reconciled"
        );
    }
    Ok(())
}

#[test]
fn session_admission_never_repeats_uncertain_or_forged_refusals() -> TestResult<()> {
    let mut forged: serde_json::Value =
        serde_json::from_slice(&api::query_rejection(429, "capacity_unavailable")?)?;
    forged["completionState"] = serde_json::json!("COMPLETION_STATE_AMBIGUOUS");
    for request in session_requests()? {
        for (status, body) in [
            (429, serde_json::to_vec(&forged)?),
            (503, api::query_rejection(503, "query_unavailable")?),
            (200, b"{}".to_vec()),
        ] {
            let (response, bodies) = session_fixture(&[(status, body)], &request)?;
            assert!(response.is_none());
            assert_eq!(
                bodies.len(),
                2,
                "one capability check and session, never a replay"
            );
        }
    }
    Ok(())
}

#[test]
fn session_repeated_capacity_cannot_reset_the_admission_window() -> TestResult<()> {
    for request in session_requests()? {
        let started = Instant::now();
        let (response, bodies) = session_fixture(
            &vec![(429, api::query_rejection(429, "capacity_unavailable")?); 10],
            &request,
        )?;
        assert!(response.is_none());
        assert!(started.elapsed() < Duration::from_secs(6));
        assert!(
            (2..=10).contains(&bodies.len()),
            "one-second backoff bounds attempts in the original five-second window"
        );
        assert!(
            bodies
                .iter()
                .skip(1)
                .step_by(2)
                .collect::<Vec<_>>()
                .windows(2)
                .all(|pair| pair[0] == pair[1])
        );
    }
    Ok(())
}
