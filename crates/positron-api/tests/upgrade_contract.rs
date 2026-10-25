use positron_api::upgrade::UpgradeRequest;
#[test]
fn upgrade_request_selects_configured_candidate_without_remote_trust_or_paths() {
    let valid = format!(
        r#"{{"action":"start","candidate_manifest":"{}","repository_id":"{}","retention_seconds":3600,"expected_catalog_generation":1,"idempotency_key":"{}"}}"#,
        "ab".repeat(32),
        "cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd",
        "efefefef-efef-efef-efef-efefefefefef"
    );
    assert!(UpgradeRequest::decode(valid.as_bytes()).is_ok());
    for field in [
        r#", "project_trust_root":"attacker""#,
        r#", "artifact_path":"/tmp/attacker""#,
    ] {
        let hostile = format!("{}{}{}", &valid[..valid.len() - 1], field, "}");
        assert!(UpgradeRequest::decode(hostile.as_bytes()).is_err());
    }
    assert!(UpgradeRequest::decode(valid.replace(&"ab".repeat(32), "bad").as_bytes()).is_err());
    assert!(UpgradeRequest::decode(valid.replace("\"start\"", "\"install\"").as_bytes()).is_err());
}
#[test]
fn upgrade_status_decodes_snapshot_progress_and_publication_cancellation() {
    let body = serde_json::json!({"catalog_generation":5,"operation":{"id":"ab".repeat(16),"status":"running","phase":"snapshot","progress_percent":30,"retry":"inspect_by_operation_id","cancellation":"allowed_before_publication","irreversible_boundary":"not_crossed"},"details":{"source_version":"0.0.0","target_version":"0.0.1","source_manifest":"11".repeat(32),"target_manifest":"22".repeat(32),"source_artifact":"33".repeat(32),"target_artifact":"44".repeat(32),"configuration":"55".repeat(32),"format_epoch":2,"repository_id":"66666666-6666-6666-6666-666666666666","rollback_available":false}});
    assert!(
        positron_api::upgrade::UpgradeResponse::decode(&serde_json::to_vec(&body).expect("body"))
            .is_ok()
    );
    for version in ["+1.0.0", "01.0.0", "1.0.-1", "1.0.4294967296"] {
        let mut hostile = body.clone();
        hostile["details"]["source_version"] = version.into();
        assert!(
            positron_api::upgrade::UpgradeResponse::decode(
                &serde_json::to_vec(&hostile).expect("body")
            )
            .is_err(),
            "noncanonical version {version}"
        );
    }
    let mut hostile = body;
    hostile["operation"]["phase"] = "invented_phase".into();
    assert!(
        positron_api::upgrade::UpgradeResponse::decode(
            &serde_json::to_vec(&hostile).expect("body")
        )
        .is_err()
    );
}
#[test]
fn upgrade_client_preserves_capacity_refusal() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        let header = String::from_utf8_lossy(&request);
        let length = header
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body)?;
        let body = r#"{"code":"capacity_unavailable"}"#;
        write!(
            stream,
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        )?;
        Ok(())
    });
    let transport = positron_api::upgrade::UpgradeTransport::PlaintextOptOut { endpoint: address };
    let client = positron_api::upgrade::UpgradeServiceClient::new(transport)?;
    let request = UpgradeRequest {
        action: "status".into(),
        candidate_manifest: None,
        repository_id: None,
        retention_seconds: None,
        expected_catalog_generation: None,
        idempotency_key: None,
        operation_id: Some("ab".repeat(16)),
    };
    assert_eq!(
        client.manage("pos_test", &request),
        Err(positron_api::upgrade::UpgradeServiceClientFailure::CapacityUnavailable)
    );
    server.join().map_err(|_| "server")??;
    Ok(())
}

#[path = "upgrade_contract/transport_deadline.rs"]
mod transport_deadline;
