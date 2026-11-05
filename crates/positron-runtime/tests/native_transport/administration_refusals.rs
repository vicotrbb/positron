use super::*;

#[test]
fn administrative_routes_refuse_missing_authority_and_malformed_intents_without_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("administrative-route-refusals")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "administrative-route-refusals")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let tenants = positron_api::tenant_service::TenantServiceClient::new(
        positron_api::tenant_service::TenantServiceTransport::PlaintextOptOut { endpoint },
    )?;
    let list = positron_api::tenant_service::TenantListRequest::new();
    let tenants_before = tenants.list(claim.secret(), &list)?;
    let keys = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::PlaintextOptOut { endpoint },
    )?;
    let list_keys = positron_api::api_keys::ApiKeyRequest::decode(br#"{"action":"list"}"#)?;
    let keys_before = keys.manage(claim.secret(), &list_keys)?;
    for path in [
        positron_api::api_keys::HTTP_PATH,
        positron_api::tenant_lifecycle::HTTP_PATH,
        positron_api::provider_migration::HTTP_PATH,
        positron_api::tenant_purge::HTTP_PATH,
        positron_api::upgrade::HTTP_PATH,
        positron_api::backup::LIST_HTTP_PATH,
        positron_api::backup::HTTP_PATH,
        positron_api::repository::HTTP_PATH,
        positron_api::maintenance::ABANDON_HTTP_PATH,
        positron_api::tenant_aliases::HTTP_PATH,
        positron_api::tenant_service::CREATE_HTTP_PATH,
        positron_api::tenant_service::INSPECT_HTTP_PATH,
        positron_api::tenant_service::LIST_HTTP_PATH,
    ] {
        for (authorized, status, code) in [
            (false, 401, "authentication_rejected"),
            (true, 400, "invalid_request"),
        ] {
            let authorization = format!("Bearer {}", claim.secret());
            let mut headers = vec![("Content-Type", "application/json")];
            if authorized {
                headers.push(("Authorization", authorization.as_str()));
            }
            let response = http(endpoint, "POST", path, &headers, b"{")?;
            assert!(
                !response.contains(claim.secret()),
                "response exposed a credential"
            );
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status} ")),
                "route={path} authorized={authorized} response={response}"
            );
            let (_, body) = response.split_once("\r\n\r\n").ok_or("response body")?;
            let body: serde_json::Value = serde_json::from_str(body)?;
            assert_eq!(body, serde_json::json!({"code": code}), "{path}");
        }
    }
    assert_eq!(
        tenants.list(claim.secret(), &list)?,
        tenants_before,
        "refused intents must not change the tenant inventory"
    );
    assert_eq!(
        keys.manage(claim.secret(), &list_keys)?.keys,
        keys_before.keys,
        "refused intents must not mint or revoke credentials"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn tenant_purge_admission_uses_its_canonical_route_and_body_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-purge-admission")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "tenant-purge-admission")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let tenants = positron_api::tenant_service::TenantServiceClient::new(
        positron_api::tenant_service::TenantServiceTransport::PlaintextOptOut { endpoint },
    )?;
    let list = positron_api::tenant_service::TenantListRequest::new();
    let before = tenants.list(claim.secret(), &list)?;
    let path = positron_api::tenant_purge::HTTP_PATH;
    let body = br#"{"action":"status","operation_id":"11111111111111111111111111111111"}"#;
    positron_api::tenant_purge::TenantPurgeRequest::decode(body)?;
    assert!(body.len() > 64);
    let mut maximum = body.to_vec();
    maximum.resize(positron_api::tenant_purge::MAX_REQUEST_BYTES, b' ');
    for payload in [body.as_slice(), maximum.as_slice()] {
        let response = http(
            endpoint,
            "POST",
            path,
            &[("Content-Type", "application/json")],
            payload,
        )?;
        assert_status(response.clone(), 401);
        let (_, response_body) = response.split_once("\r\n\r\n").ok_or("response body")?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(response_body)?,
            serde_json::json!({"code": "authentication_rejected"})
        );
    }
    let authorization = format!("Bearer {}", claim.secret());
    let response = http(
        endpoint,
        "POST",
        path,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        &maximum,
    )?;
    assert_status(response.clone(), 404);
    let (_, response_body) = response.split_once("\r\n\r\n").ok_or("response body")?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(response_body)?,
        serde_json::json!({"code": "source_unavailable"})
    );
    maximum.push(b' ');
    assert_status(http(endpoint, "POST", path, &[], &maximum)?, 413);
    assert_status(http(endpoint, "GET", path, &[], &[])?, 405);
    assert_eq!(tenants.list(claim.secret(), &list)?, before);
    shutdown_gracefully(process, &roots)?;
    Ok(())
}
