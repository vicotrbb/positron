use positron_api::backup::{
    BackupListRequest, BackupRequest, BackupServiceClient, BackupServiceClientFailure,
    BackupTransport,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

#[test]
fn backup_manage_preserves_explicit_capacity_refusal() -> Result<(), Box<dyn std::error::Error>> {
    check_capacity_response(false)
}
#[test]
fn backup_list_preserves_explicit_capacity_refusal() -> Result<(), Box<dyn std::error::Error>> {
    check_capacity_response(true)
}
fn check_capacity_response(list: bool) -> Result<(), Box<dyn std::error::Error>> {
    for (status, code, expected) in [
        (
            503,
            "capacity_unavailable",
            BackupServiceClientFailure::CapacityUnavailable,
        ),
        (
            503,
            "administration_unavailable",
            BackupServiceClientFailure::AdministrationUnavailable,
        ),
        (503, "unknown", BackupServiceClientFailure::Transport),
        (503, "malformed", BackupServiceClientFailure::Transport),
        (
            500,
            "capacity_unavailable",
            BackupServiceClientFailure::Transport,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            assert_eq!(
                line,
                format!(
                    "POST /v1/backups:{} HTTP/1.1\r\n",
                    if list { "list" } else { "manage" }
                )
            );
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line)?;
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.strip_prefix("content-length: ") {
                    length = value
                        .trim()
                        .parse::<usize>()
                        .map_err(std::io::Error::other)?;
                }
            }
            assert!(length <= 4096);
            reader.read_exact(&mut vec![0; length])?;
            let body = if code == "malformed" {
                "[".into()
            } else {
                format!("{{\"code\":\"{code}\"}}")
            };
            write!(
                stream,
                "HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
            Ok(())
        });
        let client = BackupServiceClient::new(BackupTransport::PlaintextOptOut { endpoint })?;
        let result = if list {
            client
                .list(
                    "fixture",
                    &BackupListRequest {
                        repository_id: "11111111-1111-4111-8111-111111111111".into(),
                        limit: 1,
                        cursor: None,
                    },
                )
                .map(|_| ())
        } else {
            let request = BackupRequest::decode(
                br#"{"action":"status","operation_id":"11111111111111111111111111111111"}"#,
            )?;
            client.manage("fixture", &request).map(|_| ())
        };
        server.join().map_err(|_| "fixture server panic")??;
        assert_eq!(
            result,
            Err(expected),
            "list={list}, status={status}, code={code}"
        );
    }
    Ok(())
}

#[test]
fn canonical_backup_capacity_responses_match_the_client_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let http: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))?;
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))?;
    for path in ["/v1/backups:manage", "/v1/backups:list"] {
        let operation = http
            .get("mappings")
            .and_then(serde_json::Value::as_array)
            .ok_or("operations")?
            .iter()
            .find(|operation| {
                operation.get("path").and_then(serde_json::Value::as_str) == Some(path)
            })
            .ok_or("backup operation")?;
        assert_eq!(
            operation
                .pointer("/responses/503")
                .and_then(serde_json::Value::as_str),
            Some("administration_unavailable or capacity_unavailable")
        );
        let codes = openapi
            .get("paths")
            .and_then(|paths| paths.get(path))
            .and_then(|operation| {
                operation.pointer(
                    "/post/responses/503/content/application~1json/schema/properties/code/enum",
                )
            })
            .ok_or("503 codes")?;
        assert_eq!(
            codes,
            &serde_json::json!(["administration_unavailable", "capacity_unavailable"])
        );
    }
    Ok(())
}
