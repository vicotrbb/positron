use super::*;
#[test]
fn upgrade_online_authenticates_before_decode_and_refuses_unconfigured_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (instance, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let before = services
        .open_maintenance_catalog()
        .map_err(|_| "catalog")?
        .pin()?
        .number();
    assert!(matches!(
        services.manage_upgrade(&ingest, b"malformed"),
        Err(crate::services::maintenance_api::MaintenanceServiceFailure::AuthenticationRejected)
    ));
    let body = format!(
        r#"{{"action":"start","candidate_manifest":"{}","repository_id":"11111111-1111-1111-1111-111111111111","retention_seconds":3600,"expected_catalog_generation":1,"idempotency_key":"22222222-2222-2222-2222-222222222222"}}"#,
        "ab".repeat(32)
    );
    assert!(
        services
            .manage_upgrade(&administrator, body.as_bytes())
            .is_err()
    );
    assert_eq!(
        services
            .open_maintenance_catalog()
            .map_err(|_| "catalog")?
            .pin()?
            .number(),
        before
    );
    Ok(())
}
#[test]
fn upgrade_online_exact_replay_uses_durable_intent_after_installed_candidate_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = super::upgrade_offline::configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = super::upgrade_offline::accept(&instance, &services, &administrator, &configuration)?;
    let catalog = services.open_maintenance_catalog().map_err(|_| "catalog")?;
    let actor = services
        .authorize_system_administration(&administrator)
        .map_err(|_| "actor")?;
    let accepted = positron_governance::DurableOperationAdministration::inspect_authorized(
        &catalog, actor, id,
    )?
    .ok_or("operation")?;
    let generation = accepted.request().accepted_generation();
    let before = catalog.pin()?.identity();
    drop(catalog);
    let request = positron_api::upgrade::UpgradeRequest {
        action: "start".into(),
        candidate_manifest: Some("4d".repeat(32)),
        repository_id: Some("48484848-4848-4848-4848-484848484848".into()),
        retention_seconds: Some(3600),
        expected_catalog_generation: Some(generation),
        idempotency_key: Some("4f4f4f4f-4f4f-4f4f-4f4f-4f4f4f4f4f4f".into()),
        operation_id: None,
    };
    let replay = services
        .manage_upgrade(&administrator, &request.encode()?)
        .map_err(|e| format!("replay {e:?}"))?;
    assert_eq!(
        replay.details.as_ref().ok_or("details")?.target_version,
        "0.0.1"
    );
    assert_eq!(
        replay.operation.as_ref().ok_or("operation")?.phase,
        positron_api::upgrade::UpgradePhase::Draining
    );
    assert_eq!(
        replay.operation.ok_or("receipt")?.id,
        super::super::hex(id.to_bytes())
    );
    assert_eq!(
        services
            .open_maintenance_catalog()
            .map_err(|_| "catalog")?
            .pin()?
            .identity(),
        before
    );
    Ok(())
}
#[test]
fn upgrade_startup_probe_executes_the_existing_bounded_query_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (instance, ingest, query, _) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(instance)?;
    let mut logs = request("startup-probe-readable");
    let seconds = services
        .instance
        .retention_time
        .governance_now_seconds()?
        .checked_sub(60)
        .ok_or("time")?;
    for record in logs
        .resource_logs
        .iter_mut()
        .flat_map(|r| &mut r.scope_logs)
        .flat_map(|s| &mut s.log_records)
    {
        record.time_unix_nano = seconds.checked_mul(1_000_000_000).ok_or("time")?;
    }
    services.ingest_otlp_logs(&ingest, logs.encode_to_vec())?;
    let source = crate::upgrade::startup::upgrade_query_source(&services.instance)?;
    let result = services.query_log_bodies(
        &query,
        &source,
        QueryBudget::new(4_194_304, 1024, 1024, 4_194_304, 1_048_576, 5)?,
    );
    assert_eq!(result?, ["startup-probe-readable"]);
    Ok(())
}
