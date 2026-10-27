use super::*;

fn fixture() -> TestResult<Fixture> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "positron-query-launch-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ));
    fs::create_dir(&root)?;
    let fixture = Fixture { root, child: None };
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700))?;
    Ok(fixture)
}

fn complete() -> TestResult<serde_json::Value> {
    use positron_api::log_query::*;
    let mut response =
        LogQueryResponse::decode(&serde_json::to_vec(&encoded_budget_incomplete()?)?)?;
    let Some(log_query_event::Event::Terminal(terminal)) = response
        .events
        .last_mut()
        .and_then(|event| event.event.as_mut())
    else {
        return Err("canonical terminal".into());
    };
    terminal.state = "complete".into();
    terminal.reason.clear();
    terminal
        .stats
        .as_mut()
        .ok_or("canonical statistics")?
        .limiting_budget = None;
    Ok(serde_json::from_slice(&response.encode()?)?)
}

fn query(
    fixture: &Fixture,
    endpoint: std::net::SocketAddr,
    parent: Option<Instant>,
) -> TestResult<String> {
    let response = super::super::super::super::archive::query_response(
        std::path::Path::new(env!("CARGO_BIN_EXE_positron")),
        &fixture.root,
        endpoint,
        "query-launch-credential-canary",
        &budget_query(),
        parent,
    )?;
    Ok(String::from_utf8(response.encode()?)?)
}

#[test]
fn actual_cli_capacity_backoff_preserves_request_and_complete_or_incomplete_truth() -> TestResult {
    for response in [complete()?, encoded_budget_incomplete()?] {
        let fixture = fixture()?;
        let (result, requests) = scripted_requests(
            &[
                (429, rejection(429, "capacity_unavailable")?),
                (200, response.clone()),
            ],
            |endpoint| query(&fixture, endpoint, None),
        )?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&result?)?,
            response
        );
        assert_eq!(
            requests,
            vec![serde_json::from_slice::<serde_json::Value>(&budget_query().encode()?)?; 2]
        );
    }
    Ok(())
}

#[test]
fn actual_cli_never_retries_authentication_unavailable_transport_or_unknown_capacity() -> TestResult
{
    for response in [
        (401, rejection(401, "authentication_rejected")?),
        (503, rejection(503, "query_unavailable")?),
        (0, serde_json::Value::Null),
        (429, serde_json::json!({"code":"unknown"})),
    ] {
        let fixture = fixture()?;
        let (result, requests) = scripted_requests(&[response, (200, complete()?)], |endpoint| {
            query(&fixture, endpoint, None)
        })?;
        assert_eq!(
            result
                .expect_err("only canonical capacity may retry")
                .to_string(),
            "public query refused outside its capacity launch policy"
        );
        assert_eq!(requests.len(), 1);
    }
    Ok(())
}

#[test]
fn capacity_observed_after_the_launch_window_does_not_start_another_child() -> TestResult {
    let fixture = fixture()?;
    let (result, requests, delivery) = scripted_requests_with_writer(
        &[
            (429, rejection(429, "capacity_unavailable")?),
            (200, complete()?),
        ],
        |endpoint| query(&fixture, endpoint, None),
        |stream, bytes, _| {
            std::thread::sleep(Duration::from_secs(6));
            stream.write_all(bytes)
        },
    )?;
    if let Some(error) = delivery {
        return Err(error.into());
    }
    assert_eq!(
        result
            .expect_err("late refusal cannot reopen launch window")
            .to_string(),
        "public query refused outside its capacity launch policy"
    );
    assert_eq!(requests.len(), 1);
    Ok(())
}

#[test]
fn repeated_capacity_refusal_exhausts_the_original_launch_window() -> TestResult {
    let fixture = fixture()?;
    let responses = vec![(429, rejection(429, "capacity_unavailable")?); 8];
    let (result, requests) =
        scripted_requests(&responses, |endpoint| query(&fixture, endpoint, None))?;
    let error = result
        .expect_err("capacity cannot create a fresh launch window")
        .to_string();
    // Scheduling can exhaust the same window during the permitted backoff.
    assert!(matches!(
        error.as_str(),
        "public query refused outside its capacity launch policy"
            | "public query capacity launch window expired"
    ));
    assert!(!requests.is_empty());
    assert!(requests.len() < responses.len());
    let expected = serde_json::from_slice::<serde_json::Value>(&budget_query().encode()?)?;
    assert!(requests.iter().all(|request| request == &expected));
    Ok(())
}

#[test]
fn original_parent_deadline_refuses_launch_and_reaps_an_inflight_child() -> TestResult {
    let fixture = fixture()?;
    let (expired, requests) = scripted_requests(&[(200, complete()?)], |endpoint| {
        query(&fixture, endpoint, Some(Instant::now()))
    })?;
    assert_eq!(
        expired
            .expect_err("expired parent cannot launch")
            .to_string(),
        "public query capacity launch window expired"
    );
    assert!(requests.is_empty());
    let elapsed = std::cell::Cell::new(Duration::ZERO);
    let (result, requests, delivery) = scripted_requests_with_writer(
        &[(200, complete()?)],
        |endpoint| {
            let started = Instant::now();
            let result = query(&fixture, endpoint, Some(started + Duration::from_secs(5)));
            elapsed.set(started.elapsed());
            result
        },
        |stream, bytes, _| {
            std::thread::sleep(Duration::from_secs(6));
            stream.write_all(bytes)
        },
    )?;
    if let Some(error) = delivery {
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
        ));
    }
    assert_eq!(
        result
            .expect_err("inflight request cannot extend parent")
            .to_string(),
        "public query exceeded its fixture completion deadline"
    );
    assert_eq!(requests.len(), 1);
    assert!(elapsed.get() >= Duration::from_secs(5));
    Ok(())
}
