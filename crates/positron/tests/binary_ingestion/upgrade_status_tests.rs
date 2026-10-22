use super::*;

fn succeeded() -> serde_json::Value {
    let digest = "a".repeat(64);
    serde_json::json!({"catalog_generation":12,"operation":{
        "id":"11111111111111111111111111111111","status":"succeeded","phase":"succeeded",
        "progress_percent":100,"retry":"inspect_by_operation_id",
        "cancellation":"unavailable_after_publication","irreversible_boundary":"catalog_generation_published"
    },"details":{
        "source_version":"0.0.0","target_version":"0.0.1",
        "source_manifest":digest,"target_manifest":digest,"source_artifact":digest,
        "target_artifact":digest,"configuration":digest,"format_epoch":2,
        "repository_id":"22222222-2222-4222-8222-222222222222","rollback_available":false
    }})
}

#[test]
fn candidate_status_capacity_inspects_the_same_operation_until_succeeded() -> TestResult {
    let (result, requests) = scripted_requests(
        &[
            (503, serde_json::json!({"code":"capacity_unavailable"})),
            (200, succeeded()),
        ],
        |endpoint| {
            super::super::super::upgrade::inspect_succeeded(
                &native_binary::executable(),
                endpoint,
                "test-administrator",
                "11111111111111111111111111111111",
                Instant::now() + Duration::from_secs(30),
            )
        },
    )?;
    assert_eq!(result?, "11111111111111111111111111111111");
    assert_eq!(
        requests,
        vec![
            serde_json::json!({"action":"status","operation_id":"11111111111111111111111111111111"});
            2
        ]
    );
    Ok(())
}

#[test]
fn candidate_status_does_not_retry_wrong_identity_or_terminal_failure() -> TestResult {
    let mut wrong = succeeded();
    wrong["operation"]["id"] = serde_json::json!("33333333333333333333333333333333");
    let mut failed = succeeded();
    failed["operation"]["status"] = serde_json::json!("failed");
    failed["operation"]["phase"] = serde_json::json!("verifying");
    for response in [wrong, failed] {
        let (result, requests) =
            scripted_requests(&[(200, response), (200, succeeded())], |endpoint| {
                super::super::super::upgrade::inspect_succeeded(
                    &native_binary::executable(),
                    endpoint,
                    "test-administrator",
                    "11111111111111111111111111111111",
                    Instant::now() + Duration::from_secs(30),
                )
            })?;
        assert!(result.is_err());
        assert_eq!(requests.len(), 1);
    }
    Ok(())
}

#[test]
fn candidate_status_does_not_retry_transport_or_other_refusals() -> TestResult {
    for response in [
        (0, serde_json::Value::Null),
        (
            503,
            serde_json::json!({"code":"administration_unavailable"}),
        ),
        (401, serde_json::json!({"code":"authentication_rejected"})),
    ] {
        let (result, requests) = scripted_requests(&[response, (200, succeeded())], |endpoint| {
            super::super::super::upgrade::inspect_succeeded(
                &native_binary::executable(),
                endpoint,
                "test-administrator",
                "11111111111111111111111111111111",
                Instant::now() + Duration::from_secs(30),
            )
        })?;
        assert!(result.is_err());
        assert_eq!(requests.len(), 1);
    }
    Ok(())
}

#[test]
fn candidate_status_exhausts_the_supplied_publication_watchdog() -> TestResult {
    let responses = vec![(503, serde_json::json!({"code":"capacity_unavailable"})); 512];
    let started = Instant::now();
    let outcome = scripted_requests_with_writer(
        &responses,
        |endpoint| {
            super::super::super::upgrade::inspect_succeeded(
                &native_binary::executable(),
                endpoint,
                "test-administrator",
                "11111111111111111111111111111111",
                Instant::now() + Duration::from_secs(5),
            )
        },
        |stream, bytes| stream.write_all(bytes),
    )?;
    let (result, requests) = publication_expiry(outcome)?;
    assert_eq!(
        result
            .expect_err("the supplied watchdog must expire")
            .to_string(),
        "candidate Upgrade status exceeded its publication watchdog"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(requests.iter().all(|request| request
        == &serde_json::json!({
            "action":"status", "operation_id":"11111111111111111111111111111111"
        })));
    Ok(())
}

#[test]
fn publication_watchdog_preserves_expiry_after_recorded_request_is_cancelled() -> TestResult {
    for (kind, operation_id, caller_error, accepted) in [
        (
            std::io::ErrorKind::BrokenPipe,
            "11111111111111111111111111111111",
            "candidate Upgrade status exceeded its publication watchdog",
            true,
        ),
        (
            std::io::ErrorKind::ConnectionReset,
            "11111111111111111111111111111111",
            "candidate Upgrade status exceeded its publication watchdog",
            true,
        ),
        (
            std::io::ErrorKind::TimedOut,
            "11111111111111111111111111111111",
            "candidate Upgrade status exceeded its publication watchdog",
            false,
        ),
        (
            std::io::ErrorKind::BrokenPipe,
            "33333333333333333333333333333333",
            "candidate Upgrade status exceeded its publication watchdog",
            false,
        ),
        (
            std::io::ErrorKind::BrokenPipe,
            "11111111111111111111111111111111",
            "unrelated caller failure",
            false,
        ),
    ] {
        let (entered, writing) = std::sync::mpsc::channel();
        let (cancelled, cancellation) = std::sync::mpsc::channel();
        let outcome = scripted_requests_with_writer(
            &[(503, serde_json::json!({"code":"capacity_unavailable"}))],
            |endpoint| {
                let mut stream = TcpStream::connect(endpoint)?;
                let body = serde_json::to_vec(
                    &serde_json::json!({"action":"status", "operation_id":operation_id}),
                )?;
                write!(
                    stream,
                    "POST /fixture HTTP/1.1\r\nHost: fixture\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )?;
                stream.write_all(&body)?;
                writing.recv_timeout(Duration::from_secs(2))?;
                drop(stream);
                cancelled.send(())?;
                Err(caller_error.into())
            },
            move |_, _| {
                entered.send(()).map_err(std::io::Error::other)?;
                cancellation
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(std::io::Error::other)?;
                Err(kind.into())
            },
        )?;
        let inspected = publication_expiry(outcome);
        if accepted {
            let (result, requests) = inspected?;
            assert_eq!(
                result.expect_err("watchdog expired").to_string(),
                caller_error
            );
            assert_eq!(
                requests,
                vec![serde_json::json!({"action":"status","operation_id":operation_id})]
            );
        } else {
            assert!(
                inspected.is_err(),
                "unrelated response failure must remain strict"
            );
        }
    }
    Ok(())
}

fn publication_expiry(
    (result, requests, response_error): (
        TestResult<String>,
        Vec<serde_json::Value>,
        Option<std::io::Error>,
    ),
) -> TestResult<(TestResult<String>, Vec<serde_json::Value>)> {
    if let Some(error) = response_error {
        let expected_expiry = result.as_ref().err().is_some_and(|error| {
            error.to_string() == "candidate Upgrade status exceeded its publication watchdog"
        });
        let same_operation = !requests.is_empty() && requests.iter().all(|request|
            request == &serde_json::json!({"action":"status","operation_id":"11111111111111111111111111111111"}));
        if !expected_expiry
            || !same_operation
            || !matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )
        {
            return Err(error.into());
        }
    }
    Ok((result, requests))
}
