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
    let (result, requests) = scripted_requests(&responses, |endpoint| {
        super::super::super::upgrade::inspect_succeeded(
            &native_binary::executable(),
            endpoint,
            "test-administrator",
            "11111111111111111111111111111111",
            Instant::now() + Duration::from_secs(5),
        )
    })?;
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
