use positron_api::maintenance::{
    AuthenticatedTimeRangeDescriptor, IntegrityQuarantineDescriptor, MAX_INTEGRITY_FINDINGS,
    MAX_PAUSE_DURATION_SECONDS, MAX_TASKS, MAX_WINDOW_REQUEST_BYTES, MaintenanceExplainResponse,
    MaintenancePauseRequest, MaintenanceResourceReservations, MaintenanceResumeRequest,
    MaintenanceRunRequest, MaintenanceRunResponse, MaintenanceServiceClient,
    MaintenanceStatusRequest, MaintenanceStatusResponse, MaintenanceTaskAcknowledgement,
    MaintenanceTaskStatus, MaintenanceTransport, MaintenanceWindowRequest,
    MaintenanceWindowResponse, OnlineVerificationReport, OnlineVerificationRequest,
};

#[test]
fn online_verification_wire_requires_an_explicit_scope_and_never_marks_partial_work_complete() {
    let continuation = "ab".repeat(56);
    let request = OnlineVerificationRequest::new(
        "00000000-0000-0000-0000-000000000001".to_owned(),
        "logs".to_owned(),
        1,
        Some(7),
        Some(continuation.clone()),
    );
    assert_eq!(
        OnlineVerificationRequest::decode(&request.encode().expect("request")),
        Ok(request)
    );
    assert!(
        OnlineVerificationRequest::new(
            "00000000-0000-0000-0000-000000000001".to_owned(),
            "logs".to_owned(),
            1,
            None,
            Some(continuation),
        )
        .encode()
        .is_err()
    );
    let partial = OnlineVerificationReport {
        report_version: 1,
        tenant: "00000000-0000-0000-0000-000000000001".to_owned(),
        signal: "logs".to_owned(),
        shard: 1,
        catalog_generation: 7,
        examined_segments: 1,
        examined_bytes: 42,
        omitted_segments: 1,
        outcome: "incomplete".to_owned(),
        verification_complete: true,
        report_checksum: "0".repeat(64),
        continuation: Some("ab".repeat(56)),
        findings: Vec::new(),
    };
    assert!(partial.encode().is_err());
}

#[test]
fn online_verification_report_checksum_is_deterministic_and_rejects_tampering() {
    let mut report = OnlineVerificationReport {
        report_version: 1,
        tenant: "00000000-0000-0000-0000-000000000001".to_owned(),
        signal: "logs".to_owned(),
        shard: 1,
        catalog_generation: 7,
        examined_segments: 1,
        examined_bytes: 42,
        omitted_segments: 0,
        outcome: "verified".to_owned(),
        verification_complete: true,
        report_checksum: String::new(),
        continuation: None,
        findings: Vec::new(),
    };
    report.report_checksum = report.checksum();
    let first = report.encode().expect("checksummed report encodes");
    let second = report
        .encode()
        .expect("canonical checksum is deterministic");
    assert_eq!(first, second);
    report.examined_bytes = 43;
    assert!(
        report.encode().is_err(),
        "covered report facts cannot be altered"
    );
}

#[test]
fn integrity_findings_preserve_provenance_and_enforce_the_catalog_bound() {
    let finding = IntegrityQuarantineDescriptor {
        tenant: "00000000-0000-0000-0000-000000000001".to_owned(),
        signal: "logs".to_owned(),
        shard: 1,
        segment: "00000000000000000000000000000001".to_owned(),
        base_position: 1,
        event_range: AuthenticatedTimeRangeDescriptor {
            provenance: "missing_source_time".to_owned(),
            earliest_unix_nanos: None,
            latest_unix_nanos: None,
        },
        ingest_range: AuthenticatedTimeRangeDescriptor {
            provenance: "known".to_owned(),
            earliest_unix_nanos: Some(10),
            latest_unix_nanos: Some(10),
        },
    };
    let response = |integrity_findings| MaintenanceStatusResponse {
        tasks: Vec::new(),
        returned: 0,
        total: 0,
        next_cursor: None,
        queued: 0,
        running: 0,
        deferred: 0,
        terminal: 0,
        integrity_findings,
    };
    assert!(
        response(vec![finding.clone(); MAX_INTEGRITY_FINDINGS])
            .encode()
            .is_ok()
    );
    assert!(
        response(vec![finding; MAX_INTEGRITY_FINDINGS + 1])
            .encode()
            .is_err()
    );
}

#[test]
fn maintenance_window_contract_accepts_only_optional_classes_and_server_derived_expiry() {
    let request = MaintenanceWindowRequest::new(
        vec!["compaction".to_owned(), "durable_export".to_owned()],
        1,
        60,
        "00000000-0000-0000-0000-000000000001".to_owned(),
    );
    assert!(request.encode().is_ok());
    let maximum = MaintenanceWindowRequest::new(
        vec![
            "backup_snapshot".to_owned(),
            "compaction".to_owned(),
            "durable_export".to_owned(),
            "repository_verification".to_owned(),
            "schema_demotion".to_owned(),
            "schema_promotion".to_owned(),
        ],
        u64::MAX,
        MAX_PAUSE_DURATION_SECONDS,
        "ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned(),
    );
    let encoded = maximum.encode().expect("maximum window request encodes");
    assert_eq!(encoded.len(), MAX_WINDOW_REQUEST_BYTES);
    assert_eq!(MaintenanceWindowRequest::decode(&encoded), Ok(maximum));
    assert!(
        MaintenanceWindowRequest::new(
            vec!["tenant_purge".to_owned()],
            1,
            60,
            "00000000-0000-0000-0000-000000000001".to_owned(),
        )
        .encode()
        .is_err()
    );
    assert!(
        MaintenanceWindowRequest::new(
            vec!["compaction".to_owned()],
            0,
            60,
            "00000000-0000-0000-0000-000000000001".to_owned(),
        )
        .encode()
        .is_err()
    );
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("canonical HTTP mapping");
    let window = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["rpc"] == "positron.v1.MaintenanceService/Window")
        .expect("maintenance window route");
    assert_eq!(window["max_request_bytes"], MAX_WINDOW_REQUEST_BYTES);
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("canonical OpenAPI document");
    assert_eq!(
        openapi["paths"]["/v1/maintenance:window"]["post"]["x-positron-max-request-bytes"],
        MAX_WINDOW_REQUEST_BYTES
    );
}

#[test]
fn maintenance_window_client_uses_the_canonical_generation_fenced_route()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/maintenance:window HTTP/1.1\r\n"));
        assert!(request.contains(r#""expected_catalog_generation":7"#));
        assert!(request.contains(r#""deferred_classes":["compaction","durable_export"]"#));
        let body = r#"{"deferred_classes":["compaction","durable_export"],"until_unix_seconds":60,"catalog_generation":8,"audit_position":9}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client = MaintenanceServiceClient::new(MaintenanceTransport::PlaintextOptOut { endpoint })?;
    let request = MaintenanceWindowRequest::new(
        vec!["compaction".to_owned(), "durable_export".to_owned()],
        7,
        60,
        "00000000-0000-0000-0000-000000000001".to_owned(),
    );
    assert_eq!(
        client.window("system-administrator", &request)?,
        MaintenanceWindowResponse {
            deferred_classes: vec!["compaction".to_owned(), "durable_export".to_owned()],
            until_unix_seconds: 60,
            catalog_generation: 8,
            audit_position: 9,
        }
    );
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_status_client_uses_the_canonical_bounded_system_administration_route()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/maintenance:status HTTP/1.1\r\n"));
        assert!(request.contains(r#""cursor":"00000000000000000000000000000001""#));
        assert!(request.contains(r#""limit":1"#));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer system-administrator\r\n")
        );
        let body = r#"{"tasks":[{"identity":"00000000000000000000000000000001","class":"compaction","scope":"segment:00000000-0000-0000-0000-000000000001:logs:1","phase":"deferred","submitted_at_unix_seconds":1,"checkpoint_sequence":2,"automatic_resume_at_unix_seconds":61,"capacity_risk":"foreground_reservation","retention_impact":"unaffected","recovery_impact":"unaffected","pause_until_unix_seconds":61,"cancellation_requested":false,"resource_generation":1,"reservations":{"memory_bytes":0,"queue_slots":0,"task_slots":1,"buffer_cache_bytes":0,"batch_items":0,"lease_slots":0,"retry_slots":0,"io_permits":0,"cpu_work_units":0,"file_descriptors":0,"disk_headroom_bytes":0},"expected_foreground_impact":{"memory_bytes":0,"queue_slots":0,"task_slots":1,"buffer_cache_bytes":0,"batch_items":0,"lease_slots":0,"retry_slots":0,"io_permits":0,"cpu_work_units":0,"file_descriptors":0,"disk_headroom_bytes":0},"blocked_precondition":"maintenance_pause_active","safe_actions":["resume"],"backlog_age_seconds":3,"checkpoint_completed_inputs":0,"input_object_count":1,"output_object_count":0}],"returned":1,"total":1,"queued":0,"running":0,"deferred":1,"terminal":0}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client = MaintenanceServiceClient::new(MaintenanceTransport::PlaintextOptOut { endpoint })?;
    let response = client.status(
        "system-administrator",
        &MaintenanceStatusRequest::page_after("00000000000000000000000000000001".to_owned(), 1),
    )?;
    assert_eq!(response.returned, 1);
    assert_eq!(response.total, 1);
    assert_eq!(response.next_cursor, None);
    assert_eq!(response.queued, 0);
    assert_eq!(response.running, 0);
    assert_eq!(response.deferred, 1);
    assert_eq!(response.terminal, 0);
    let task = response.tasks.first().ok_or("missing maintenance task")?;
    assert_eq!(task.resource_generation, Some(1));
    assert_eq!(
        task.reservations.as_ref().map(|value| value.task_slots),
        Some(1)
    );
    assert_eq!(
        task.expected_foreground_impact
            .as_ref()
            .map(|value| value.task_slots),
        Some(1)
    );
    assert_eq!(
        task.blocked_precondition.as_deref(),
        Some("maintenance_pause_active")
    );
    assert_eq!(task.safe_actions, ["resume"]);
    assert_eq!(task.backlog_age_seconds, Some(3));
    assert_eq!(task.checkpoint_completed_inputs, Some(0));
    assert_eq!(task.input_object_count, 1);
    assert_eq!(task.output_object_count, 0);
    assert_eq!(task.estimated_output_object_amplification_milli, None);
    assert_eq!(
        task.capacity_risk.as_deref(),
        Some("foreground_reservation")
    );
    assert_eq!(task.retention_impact.as_deref(), Some("unaffected"));
    assert_eq!(task.recovery_impact.as_deref(), Some("unaffected"));
    assert_eq!(task.automatic_resume_at_unix_seconds, Some(61));
    assert_eq!(task.terminal_outcome, None);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_status_and_explain_preserve_an_epoch_progress_instant() {
    let task = r#"{"identity":"00000000000000000000000000000001","class":"compaction","scope":"system","phase":"running","submitted_at_unix_seconds":1,"last_progress_at_unix_seconds":0,"no_durable_progress_slo_breached":false,"no_durable_progress_slo_seconds":60,"cancellation_requested":false,"input_object_count":0,"output_object_count":0}"#;
    let status = format!(
        r#"{{"tasks":[{task}],"returned":1,"total":1,"queued":0,"running":1,"deferred":0,"terminal":0}}"#
    );
    let explain = format!(r#"{{"task":{task}}}"#);

    let status = MaintenanceStatusResponse::decode(status.as_bytes())
        .expect("an epoch lifecycle instant is a valid running-status progress timestamp");
    let explained = MaintenanceExplainResponse::decode(explain.as_bytes())
        .expect("an epoch lifecycle instant is a valid running-explain progress timestamp");

    assert_eq!(status.tasks[0].last_progress_at_unix_seconds, Some(0));
    assert_eq!(
        status.tasks[0].no_durable_progress_slo_breached,
        Some(false)
    );
    assert_eq!(explained.task.last_progress_at_unix_seconds, Some(0));
    assert_eq!(explained.task.no_durable_progress_slo_breached, Some(false));
    assert_eq!(
        MaintenanceStatusResponse::decode(&status.encode().expect("status encodes"))
            .expect("status round trip decodes"),
        status
    );
    assert_eq!(
        MaintenanceExplainResponse::decode(&explained.encode().expect("explain encodes"))
            .expect("explain round trip decodes"),
        explained
    );

    let unknown_task = r#"{"identity":"00000000000000000000000000000001","class":"compaction","scope":"system","phase":"running","submitted_at_unix_seconds":1,"no_durable_progress_slo_seconds":60,"cancellation_requested":false,"input_object_count":0,"output_object_count":0}"#;
    let unknown = format!(
        r#"{{"tasks":[{unknown_task}],"returned":1,"total":1,"queued":0,"running":1,"deferred":0,"terminal":0}}"#
    );
    let unknown = MaintenanceStatusResponse::decode(unknown.as_bytes())
        .expect("a missing trusted progress instant represents an unknown SLO outcome");
    assert_eq!(unknown.tasks[0].last_progress_at_unix_seconds, None);
    assert_eq!(unknown.tasks[0].no_durable_progress_slo_breached, None);

    let untrusted = r#"{"identity":"00000000000000000000000000000001","class":"compaction","scope":"system","phase":"running","submitted_at_unix_seconds":1,"no_durable_progress_slo_breached":false,"no_durable_progress_slo_seconds":60,"cancellation_requested":false,"input_object_count":0,"output_object_count":0}"#;
    let untrusted = format!(
        r#"{{"tasks":[{untrusted}],"returned":1,"total":1,"queued":0,"running":1,"deferred":0,"terminal":0}}"#
    );
    assert!(
        MaintenanceStatusResponse::decode(untrusted.as_bytes()).is_err(),
        "a response without a trusted progress instant cannot assert a healthy SLO"
    );
}

#[test]
fn maintenance_status_and_explain_reject_unknown_nested_task_fields() {
    let task = r#"{"identity":"00000000000000000000000000000001","class":"compaction","scope":"system","phase":"running","submitted_at_unix_seconds":1,"cancellation_requested":false,"input_object_count":0,"output_object_count":0,"unexpected":true}"#;
    let status = format!(
        r#"{{"tasks":[{task}],"returned":1,"total":1,"queued":0,"running":1,"deferred":0,"terminal":0}}"#
    );
    let explain = format!(r#"{{"task":{task}}}"#);

    assert!(
        MaintenanceStatusResponse::decode(status.as_bytes()).is_err(),
        "status must reject fields the canonical task schema does not publish"
    );
    assert!(
        MaintenanceExplainResponse::decode(explain.as_bytes()).is_err(),
        "explain must reject fields the canonical task schema does not publish"
    );
}

#[test]
fn maintenance_status_decoder_rejects_overflowing_phase_counts() {
    let overflowing = br#"{"tasks":[],"returned":0,"total":0,"queued":4294967295,"running":1,"deferred":0,"terminal":0}"#;
    assert_eq!(
        MaintenanceStatusResponse::decode(overflowing),
        Err(positron_api::maintenance::MaintenanceWireFailure),
        "a peer-provided count sum that overflows u32 is malformed wire data"
    );

    let bounded_total = br#"{"tasks":[],"returned":0,"total":128,"queued":128,"running":0,"deferred":0,"terminal":0}"#;
    assert!(
        MaintenanceStatusResponse::decode(bounded_total).is_ok(),
        "the configured bounded registry maximum remains a valid exact count"
    );
}

#[test]
fn full_valid_maintenance_registry_page_fits_the_bounded_response() {
    let tasks = (0..positron_api::maintenance::MAX_STATUS_PAGE_TASKS)
        .map(|index| MaintenanceTaskStatus {
            identity: format!("{index:032x}"),
            class: "catalog_reclamation".to_owned(),
            scope: "segment:00000000-0000-0000-0000-000000000001:traces:4294967295".to_owned(),
            phase: "running".to_owned(),
            submitted_at_unix_seconds: u64::MAX,
            checkpoint_sequence: Some(u64::MAX),
            last_progress_at_unix_seconds: Some(u64::MAX),
            no_durable_progress_slo_breached: Some(true),
            no_durable_progress_slo_seconds: Some(u64::MAX),
            capacity_risk: Some("foreground_reservation".to_owned()),
            retention_impact: Some("unaffected".to_owned()),
            recovery_impact: Some("unaffected".to_owned()),
            automatic_resume_at_unix_seconds: Some(u64::MAX),
            pause_until_unix_seconds: None,
            cancellation_requested: false,
            resource_generation: Some(u64::MAX),
            reservations: Some(MaintenanceResourceReservations {
                memory_bytes: u64::MAX,
                queue_slots: u64::MAX,
                task_slots: u64::MAX,
                buffer_cache_bytes: u64::MAX,
                batch_items: u64::MAX,
                lease_slots: u64::MAX,
                retry_slots: u64::MAX,
                io_permits: u64::MAX,
                cpu_work_units: u64::MAX,
                file_descriptors: u64::MAX,
                disk_headroom_bytes: u64::MAX,
            }),
            expected_foreground_impact: Some(MaintenanceResourceReservations {
                memory_bytes: u64::MAX,
                queue_slots: u64::MAX,
                task_slots: u64::MAX,
                buffer_cache_bytes: u64::MAX,
                batch_items: u64::MAX,
                lease_slots: u64::MAX,
                retry_slots: u64::MAX,
                io_permits: u64::MAX,
                cpu_work_units: u64::MAX,
                file_descriptors: u64::MAX,
                disk_headroom_bytes: u64::MAX,
            }),
            blocked_precondition: Some("maintenance_window_active".to_owned()),
            maintenance_window_until_unix_seconds: Some(u64::MAX),
            safe_actions: vec!["pause".to_owned()],
            backlog_age_seconds: Some(u64::MAX),
            conflict_owner: Some(format!("{:032x}", (index + 1) % MAX_TASKS)),
            checkpoint_completed_inputs: Some(16),
            input_object_count: 16,
            output_object_count: 16,
            estimated_output_object_amplification_milli: Some(1_000),
            terminal_outcome: None,
            terminal_failure_class: None,
        })
        .collect();
    assert!(
        MaintenanceStatusResponse {
            tasks,
            returned: positron_api::maintenance::MAX_STATUS_PAGE_TASKS as u32,
            total: MAX_TASKS as u32,
            next_cursor: Some(format!(
                "{:032x}",
                positron_api::maintenance::MAX_STATUS_PAGE_TASKS - 1
            )),
            queued: 0,
            running: MAX_TASKS as u32,
            deferred: 0,
            terminal: 0,
            integrity_findings: Vec::new(),
        }
        .encode()
        .is_ok(),
        "a full valid registry has a bounded, explicitly continued status page"
    );
}

#[test]
fn maintenance_control_contract_is_bounded_and_rejects_caller_expiry() {
    let pause = MaintenancePauseRequest::new(
        "00000000000000000000000000000001".to_owned(),
        1,
        MAX_PAUSE_DURATION_SECONDS,
        "00000000-0000-0000-0000-000000000001".to_owned(),
    );
    assert!(pause.encode().is_ok());
    assert!(
        MaintenancePauseRequest::new(
            "00000000000000000000000000000001".to_owned(),
            1,
            MAX_PAUSE_DURATION_SECONDS + 1,
            "00000000-0000-0000-0000-000000000001".to_owned(),
        )
        .encode()
        .is_err()
    );
    assert!(
        MaintenanceResumeRequest::new(
            "00000000000000000000000000000001".to_owned(),
            "00000000-0000-0000-0000-000000000001".to_owned(),
        )
        .encode()
        .is_ok()
    );
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("canonical HTTP mapping");
    let pause_fields = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["rpc"] == "positron.v1.MaintenanceService/Pause")
        .expect("maintenance pause route")["request_fields"]
        .as_array()
        .expect("pause request fields");
    assert!(
        pause_fields
            .iter()
            .all(|field| field["json"] != "pause_until_unix_seconds")
    );
}

#[test]
fn maintenance_status_contract_is_canonical_and_bounded() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("canonical HTTP mapping");
    let route = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["rpc"] == "positron.v1.MaintenanceService/Status")
        .expect("maintenance status route");
    assert_eq!(route["path"], "/v1/maintenance:status");
    assert_eq!(route["authentication"], "Bearer SystemAdministration");
    assert_eq!(route["max_request_bytes"], 128);
    assert_eq!(route["max_response_bytes"], 65_536);
    let fields = route["request_fields"]
        .as_array()
        .expect("status request fields");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0]["json"], "cursor");
    assert_eq!(fields[1]["json"], "limit");
    let response_fields = route["response_fields"]
        .as_array()
        .expect("status response fields");
    assert!(
        response_fields
            .iter()
            .any(|field| field["json"] == "returned")
    );
    assert!(response_fields.iter().any(|field| field["json"] == "total"));
    assert!(
        response_fields
            .iter()
            .any(|field| field["json"] == "next_cursor")
    );
    assert!(MaintenanceStatusRequest::decode(br#"{"limit":33}"#).is_err());
    assert!(MaintenanceStatusRequest::decode(br#"{"cursor":"not-a-task"}"#).is_err());
    let run = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["rpc"] == "positron.v1.MaintenanceService/Run")
        .expect("maintenance run route");
    assert_eq!(run["path"], "/v1/maintenance:run");
    assert_eq!(run["authentication"], "Bearer SystemAdministration");
    assert_eq!(run["max_request_bytes"], 256);
    assert_eq!(run["max_response_bytes"], 2048);

    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("canonical OpenAPI document");
    let task = &openapi["components"]["schemas"]["MaintenanceTaskStatus"];
    assert_eq!(task["additionalProperties"], false);
    assert_eq!(
        task["properties"]["last_progress_at_unix_seconds"]["minimum"], 0,
        "the Unix epoch is a valid trusted durable-progress instant"
    );
}

#[test]
fn maintenance_run_client_uses_the_canonical_explicit_scope_route()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/maintenance:run HTTP/1.1\r\n"));
        assert!(request.contains(r#""class":"compaction""#));
        assert!(request.contains(r#""signal":"logs""#));
        let body = r#"{"task":{"identity":"00000000000000000000000000000001","class":"compaction","scope":"segment:00000000-0000-0000-0000-000000000001:logs:1","submitted_at_unix_seconds":1},"resource_generation":1}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client = MaintenanceServiceClient::new(MaintenanceTransport::PlaintextOptOut { endpoint })?;
    assert_eq!(
        client.run(
            "system-administrator",
            &MaintenanceRunRequest::new(
                "compaction".to_owned(),
                "00000000-0000-0000-0000-000000000001".to_owned(),
                "logs".to_owned(),
                1,
                "00000000-0000-0000-0000-000000000001".to_owned(),
            ),
        )?,
        MaintenanceRunResponse {
            task: MaintenanceTaskAcknowledgement {
                identity: "00000000000000000000000000000001".to_owned(),
                class: "compaction".to_owned(),
                scope: "segment:00000000-0000-0000-0000-000000000001:logs:1".to_owned(),
                submitted_at_unix_seconds: 1,
            },
            resource_generation: 1,
        }
    );
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_control_client_uses_the_canonical_bounded_routes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        for (path, expected, body) in [
            (
                "/v1/maintenance:pause",
                "\"resource_generation\":1",
                r#"{"task":{"identity":"00000000000000000000000000000001","class":"compaction","scope":"segment:00000000-0000-0000-0000-000000000001:logs:1","submitted_at_unix_seconds":1},"audit_position":3,"action":"pause","resource_generation":1,"pause_until_unix_seconds":61}"#,
            ),
            (
                "/v1/maintenance:resume",
                "\"idempotency_key\":\"00000000-0000-0000-0000-000000000002\"",
                r#"{"task":{"identity":"00000000000000000000000000000001","class":"compaction","scope":"segment:00000000-0000-0000-0000-000000000001:logs:1","submitted_at_unix_seconds":1},"audit_position":4,"action":"resume"}"#,
            ),
        ] {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 4096];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
            assert!(request.contains(expected));
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    });
    let client = MaintenanceServiceClient::new(MaintenanceTransport::PlaintextOptOut { endpoint })?;
    let identity = "00000000000000000000000000000001".to_owned();
    let paused = client.pause(
        "system-administrator",
        &MaintenancePauseRequest::new(
            identity.clone(),
            1,
            60,
            "00000000-0000-0000-0000-000000000002".to_owned(),
        ),
    )?;
    assert_eq!(paused.action, "pause");
    assert_eq!(paused.resource_generation, Some(1));
    assert_eq!(paused.audit_position, 3);
    let resumed = client.resume(
        "system-administrator",
        &MaintenanceResumeRequest::new(identity, "00000000-0000-0000-0000-000000000002".to_owned()),
    )?;
    assert_eq!(resumed.action, "resume");
    assert_eq!(resumed.resource_generation, None);
    assert_eq!(resumed.audit_position, 4);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}
