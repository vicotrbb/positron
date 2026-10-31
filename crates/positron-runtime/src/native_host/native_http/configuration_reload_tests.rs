//! Privileged reload must use the current administrator in addition to socket ownership.
#![cfg(unix)]
use super::*;
use crate::{
    BootstrapPaths, InitializationPlan, InstanceBootstrap, ServiceHandle, health::ProcessState,
};
use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_kernel::MountQualification;
use std::{
    fs,
    io::Cursor,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn control_reload_rejects_missing_administrator_without_queueing()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-reload-authorization-{nonce}"));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let local_key = secrets.join("local-root-key.v1");
    let configuration = format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:0\"\napi_bind_address = \"127.0.0.1:0\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_http_bind_address = \"127.0.0.1:0\"\nloki_push_bind_address = \"127.0.0.1:0\"\noperations_transport = \"plaintext\"\napi_transport = \"plaintext\"\notlp_grpc_transport = \"plaintext\"\notlp_http_transport = \"plaintext\"\nloki_push_transport = \"plaintext\"\n[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n",
        root.join("control.sock").display(),
        data.display(),
        secrets.display(),
        local_key.display(),
    );
    let effective = Arc::new(resolve(ConfigurationInputs::try_new(
        Some(&configuration),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)?);
    let generation =
        crate::CatalogConfigurationPublication::new(Arc::clone(&instance)).establish(&effective)?;
    let state = ProcessState::starting();
    state.set_configuration_runtime(Arc::new(crate::RuntimeConfiguration::new_at_generation(
        effective, generation,
    )))?;
    state.set_inspection_authority(Arc::clone(&instance))?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    state.set_catalog_operation(services.catalog_operation_gate())?;
    state.transition(crate::ProcessPhase::Serving);
    assert_eq!(request(&state, ListenerRole::Control, None, &[]), 401);
    assert!(!state.health().take_configuration_reload_request());
    let unavailable = instance._authority.with_control_contention_for_test(|| {
        request(&state, ListenerRole::Control, Some(claim.secret()), &[])
    })?;
    assert_eq!(unavailable, 503);
    assert!(!state.health().take_configuration_reload_request());
    let diagnostics = state
        .health()
        .operational_logs_json()
        .map_err(|_| "operational diagnostics unavailable")?;
    let records: Vec<serde_json::Value> = serde_json::from_str(&diagnostics)?;
    assert_eq!(
        records
            .iter()
            .filter(|record| record["event"] == "owner_inspection_unavailable")
            .count(),
        1,
        "{diagnostics}"
    );
    assert!(records.iter().any(|record| {
        record["event"] == "owner_inspection_unavailable"
            && record["reason"] == "resource_admission"
    }));
    for rejected in [
        "invalid-credential",
        claim.query_secret().ok_or("query credential missing")?,
        claim.ingest_secret().ok_or("ingest credential missing")?,
    ] {
        assert_eq!(
            request(&state, ListenerRole::Control, Some(rejected), &[]),
            401
        );
        assert!(!state.health().take_configuration_reload_request());
    }
    for role in [ListenerRole::Api, ListenerRole::Operations] {
        assert_eq!(request(&state, role, Some(claim.secret()), &[]), 404);
        assert!(!state.health().take_configuration_reload_request());
    }
    assert_eq!(
        request(&state, ListenerRole::Control, Some(claim.secret()), b"x"),
        400
    );
    assert!(!state.health().take_configuration_reload_request());
    let records: Vec<serde_json::Value> = serde_json::from_str(
        &state
            .health()
            .operational_logs_json()
            .map_err(|_| "operational diagnostics unavailable")?,
    )?;
    let refusals = records
        .iter()
        .filter(|record| record["event"] == "owner_inspection_unavailable")
        .collect::<Vec<_>>();
    assert_eq!(
        refusals.len(),
        1,
        "authentication rejection adds no owner diagnostic"
    );
    assert_eq!(
        request(&state, ListenerRole::Control, Some(claim.secret()), &[]),
        202
    );
    assert!(state.health().take_configuration_reload_request());
    state.transition(crate::ProcessPhase::Fenced);
    assert_eq!(
        request(&state, ListenerRole::Control, Some(claim.secret()), &[]),
        503
    );
    assert!(!state.health().take_configuration_reload_request());
    let records: Vec<serde_json::Value> = serde_json::from_str(
        &state
            .health()
            .operational_logs_json()
            .map_err(|_| "operational diagnostics unavailable")?,
    )?;
    assert_eq!(
        records
            .iter()
            .filter(|record| record["event"] == "owner_inspection_unavailable")
            .count(),
        2
    );
    assert!(records.iter().any(|record| {
        record["event"] == "owner_inspection_unavailable" && record["reason"] == "phase"
    }));
    drop(services);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn request(state: &ProcessState, role: ListenerRole, bearer: Option<&str>, body: &[u8]) -> u16 {
    let mut stream = Cursor::new(body.to_vec());
    let head = RequestHead {
        openmetrics: false,
        method: "POST".to_owned(),
        path: "/control/configuration/reload".to_owned(),
        content_length: body.len(),
        bearer: bearer.map(str::to_owned),
        content_type: None,
        content_encoding: None,
        tenant_hint: None,
        forwarded_for: None,
        forwarded_actor: None,
    };
    match route(
        &mut stream,
        role,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        None,
        head,
        &state.health(),
        super::super::RouteDependencies::new(None, None),
    ) {
        Ok(response) | Err(response) => response.status(),
    }
}
