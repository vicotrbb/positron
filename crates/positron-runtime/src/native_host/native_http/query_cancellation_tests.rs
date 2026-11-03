use super::*;
use positron_api::log_query as api;
use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn with_fixture(
    test: impl FnOnce(&ServiceHandle, &HealthState, &str, &crate::InitializedInstance) -> TestResult,
) -> TestResult {
    let roots = crate::process_lifecycle::TestRoots::new("query-cancellation")?;
    let paths = roots.bootstrap_paths()?;
    drop(crate::InstanceBootstrap::initialize(
        &paths,
        crate::InitializationPlan::non_interactive(),
    )?);
    let claim = crate::InstanceBootstrap::claim(&paths)?;
    let bearer = claim.query_secret().ok_or("query credential")?;
    let instance = Arc::new(crate::InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let state = crate::health::ProcessState::starting();
    state.set_inspection_authority(Arc::clone(&instance))?;
    state.transition(crate::ProcessPhase::Serving);
    test(&services, &state.health(), bearer, &instance)
}

fn poll(
    services: &ServiceHandle,
    bearer: &str,
    cursor: Option<Vec<u8>>,
) -> TestResult<(
    api::LogQueryResponse,
    positron_kernel::TransferredResourceReservation,
)> {
    let request = api::LogQuerySessionRequest {
        operation: Some(api::log_query_session_request::Operation::Tail(api::LogQueryTailRequest {
            query: Some(api::LogQueryRequest {
                pipeline: "pipeline:v1 logs | range query_time 0 100 | project commit_position | limit all".into(),
                budget: Some(api::LogQueryBudget { scanned_bytes: 1_048_576, decoded_records: 16,
                    output_rows: 16, output_bytes: 16_384, memory_bytes: 1_048_576,
                    cpu_work_units: 15, wall_seconds: 60, maximum_time_range_nanoseconds: 100 }),
            }),
            cursor,
            ..Default::default()
        })),
        batch_limit: 1,
    };
    let (body, reservation) = services
        .execute_log_query_session(bearer, &request.encode()?)
        .map_err(|failure| format!("tail poll: {failure:?}"))?;
    Ok((api::LogQueryResponse::decode_tail(&body)?, reservation))
}

fn continuation(response: &api::LogQueryResponse) -> TestResult<Vec<u8>> {
    response
        .events
        .iter()
        .find_map(|event| match event.event.as_ref() {
            Some(api::log_query_event::Event::Terminal(terminal)) => {
                terminal.continuation_cursor.clone()
            },
            _ => None,
        })
        .ok_or_else(|| "tail continuation".into())
}

fn cancel(
    services: &ServiceHandle,
    health: &HealthState,
    bearer: &str,
    cursor: Vec<u8>,
) -> TestResult<Response> {
    let body = api::LogQueryCancelRequest {
        cursor: Some(api::log_query_cancel_request::Cursor::Tail(cursor)),
    }
    .encode()?;
    let mut raw = Cursor::new(format!("POST {} HTTP/1.1\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", api::CANCEL_HTTP_PATH, body.len()).into_bytes());
    let head = io::read_head(&mut raw).map_err(|_| "cancellation head")?;
    Ok(route_buffered_api(
        head,
        body,
        "127.0.0.1:1".parse()?,
        None,
        health,
        Some(services),
        Instant::now() + Duration::from_secs(30),
    ))
}

#[test]
fn contended_cancellation_is_rejected_before_mutation_and_can_be_explicitly_reconciled()
-> TestResult {
    with_fixture(|services, health, bearer, instance| {
        let (initial, reservation) = poll(services, bearer, None)?;
        let cursor = continuation(&initial)?;
        drop(reservation);
        let response = instance._authority.with_control_contention_for_test(|| {
            cancel(services, health, bearer, cursor.clone())
        })??;
        use positron_api::api_keys::protobuf::{
            CompletionState, PublicError, PublicErrorCode, RetryClass,
        };
        let error: PublicError = serde_json::from_slice(response.body())?;
        assert_eq!(response.status(), 429);
        assert_eq!(error.code, PublicErrorCode::CapacityUnavailable as i32);
        assert_eq!(error.completion_state, CompletionState::Rejected as i32);
        assert_eq!(error.retry_class, RetryClass::AfterBackoff as i32);
        let (resumed, reservation) = poll(services, bearer, Some(cursor.clone()))?;
        assert!(continuation(&resumed).is_ok());
        drop(reservation);
        assert_eq!(cancel(services, health, bearer, cursor)?.status(), 200);
        Ok(())
    })
}

#[test]
fn rejected_cancellation_does_not_retry_through_drop_and_keeps_the_cursor_resumable() -> TestResult
{
    with_fixture(|services, health, bearer, _| {
        let (initial, reservation) = poll(services, bearer, None)?;
        let cursor = continuation(&initial)?;
        drop(reservation);
        let response = with_catalog_publication_fault_after(
            CatalogPublicationFault::PartialObjectWrite,
            0,
            || cancel(services, health, bearer, cursor.clone()),
        )?;
        assert_eq!(response.status(), 503);
        let error: positron_api::api_keys::protobuf::PublicError =
            serde_json::from_slice(response.body())?;
        assert_eq!(
            error.completion_state,
            positron_api::api_keys::protobuf::CompletionState::Rejected as i32
        );
        let (resumed, _reservation) = poll(services, bearer, Some(cursor))?;
        assert!(continuation(&resumed).is_ok());
        Ok(())
    })
}

#[test]
fn uncertain_cancellation_publication_keeps_its_cause_and_never_claims_rejection() -> TestResult {
    with_fixture(|services, health, bearer, _| {
        let (initial, reservation) = poll(services, bearer, None)?;
        let cursor = continuation(&initial)?;
        drop(reservation);
        let response = positron_kernel::with_catalog_publication_fault_sequence_after(
            &[
                (CatalogPublicationFault::SynchronizeCommit, 0),
                (CatalogPublicationFault::ReadGenerationDirectory, 0),
            ],
            || cancel(services, health, bearer, cursor),
        )?;
        assert_eq!(response.status(), 503);
        use positron_api::api_keys::protobuf::{
            CompletionState, PublicError, PublicErrorCode, RetryClass,
        };
        let error: PublicError = serde_json::from_slice(response.body())?;
        assert_eq!(error.code, PublicErrorCode::StoreUnavailable as i32);
        assert_eq!(error.completion_state, CompletionState::Ambiguous as i32);
        assert_eq!(error.retry_class, RetryClass::Never as i32);
        assert_eq!(response.retry_after_seconds(), None);
        Ok(())
    })
}

#[test]
fn bounded_cancellation_fits_while_three_query_responses_still_own_their_buffers() -> TestResult {
    with_fixture(|services, health, bearer, _| {
        let mut held = Vec::new();
        let mut cursor = None;
        for _ in 0..3 {
            let (response, reservation) = poll(services, bearer, None)?;
            cursor = Some(continuation(&response)?);
            held.push((response, reservation));
        }
        let cursor = cursor.ok_or("tail cursor")?;
        let while_held = cancel(services, health, bearer, cursor.clone())?;
        drop(held);
        let after_release = cancel(services, health, bearer, cursor)?;
        assert_eq!(
            after_release.status(),
            200,
            "same cursor works after response ownership releases"
        );
        assert_eq!(
            while_held.status(),
            200,
            "the bounded cancellation workspace must fit alongside three in-flight query responses"
        );
        Ok(())
    })
}

#[test]
fn cancellation_authentication_and_cursor_refusals_are_definite_and_leave_original_lease()
-> TestResult {
    with_fixture(|services, health, bearer, _| {
        let (initial, reservation) = poll(services, bearer, None)?;
        let cursor = continuation(&initial)?;
        drop(reservation);
        for (credential, submitted, status) in [
            ("invalid-credential", cursor.clone(), 401),
            (bearer, vec![1], 400),
        ] {
            let response = cancel(services, health, credential, submitted)?;
            assert_eq!(response.status(), status);
            let error: positron_api::api_keys::protobuf::PublicError =
                serde_json::from_slice(response.body())?;
            assert_eq!(
                error.completion_state,
                positron_api::api_keys::protobuf::CompletionState::Rejected as i32
            );
        }
        let (resumed, _reservation) = poll(services, bearer, Some(cursor))?;
        assert!(continuation(&resumed).is_ok());
        Ok(())
    })
}
