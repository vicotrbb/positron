use positron_api::backup::BackupListRequest;
#[test]
fn list_reads_one_registered_repository_with_bounded_pagination() {
    let request = BackupListRequest::decode(
        br#"{"repository_id":"11111111-1111-4111-8111-111111111111","limit":128}"#,
    )
    .expect("list request");
    assert_eq!(request.limit, 128);
    assert!(request.encode().is_ok());
}
#[test]
fn list_rejects_mutation_fields_and_malformed_cursors() {
    for wire in [
        r#"{"repository_id":"11111111-1111-4111-8111-111111111111","limit":0}"#,
        r#"{"repository_id":"11111111-1111-4111-8111-111111111111","limit":129}"#,
        r#"{"repository_id":"bad","limit":1}"#,
        r#"{"repository_id":"11111111-1111-4111-8111-111111111111","limit":1,"idempotency_key":"11111111-1111-4111-8111-111111111111"}"#,
    ] {
        assert!(BackupListRequest::decode(wire.as_bytes()).is_err());
    }
    let mut request = BackupListRequest {
        repository_id: "11111111-1111-4111-8111-111111111111".into(),
        limit: 1,
        cursor: None,
    };
    for cursor in [
        "x".repeat(176),
        "0".repeat(176),
        format!(
            "504f53424c533031{}{}{}",
            "0".repeat(64),
            "2".repeat(64),
            "3".repeat(32)
        ),
        "504f53424c533031".into(),
    ] {
        request.cursor = Some(cursor);
        assert!(request.encode().is_err());
    }
    request.cursor = Some(format!(
        "504f53424c533031{}{}{}",
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(32)
    ));
    assert!(request.encode().is_ok());
    assert!(BackupListRequest::decode(&vec![b' '; 4097]).is_err());
}
fn page() -> positron_api::backup::BackupListResponse {
    use positron_api::{
        backup::{BackupListEntry, BackupListResponse},
        repository::RepositoryIdentity,
    };
    BackupListResponse {
        repository: RepositoryIdentity {
            repository_id: "11111111-1111-4111-8111-111111111111".into(),
            instance_id: "22222222-2222-4222-8222-222222222222".into(),
            provider_kind: "local_filesystem".into(),
            format_epoch: 1,
            integrity_fingerprint: "1".repeat(64),
            prefix_commitment: "2".repeat(64),
        },
        registry_generation_checksum: Some("3".repeat(64)),
        entries: vec![BackupListEntry {
            snapshot_id: "4".repeat(32),
            manifest_checksum: "5".repeat(64),
            created_unix_seconds: 100,
            retain_until_unix_seconds: 200,
        }],
        next_cursor: Some(format!(
            "504f53424c533031{}{}{}",
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(32)
        )),
    }
}
#[test]
fn pages_bind_cursor_and_entries_to_one_registry_generation() {
    use positron_api::backup::BackupListResponse;
    let page = page();
    assert_eq!(
        BackupListResponse::decode(&page.encode().expect("page")).expect("decode"),
        page
    );
    let mut invalid = page.clone();
    invalid.registry_generation_checksum = None;
    assert!(invalid.encode().is_err());
    invalid = page.clone();
    invalid.registry_generation_checksum = Some("0".repeat(64));
    assert!(invalid.encode().is_err());
    invalid = page.clone();
    invalid.entries.push(invalid.entries[0].clone());
    assert!(invalid.encode().is_err());
    invalid = page.clone();
    invalid.entries[0].snapshot_id = "a".repeat(32);
    assert!(invalid.encode().is_err());
    invalid = page.clone();
    invalid.entries[0].created_unix_seconds = 0;
    assert!(invalid.encode().is_err());
    invalid = page.clone();
    invalid.entries[0].retain_until_unix_seconds = 99;
    assert!(invalid.encode().is_err());
    invalid = page.clone();
    invalid.entries[0].manifest_checksum = "0".repeat(64);
    assert!(invalid.encode().is_err());
    let mut empty = page;
    empty.entries.clear();
    empty.next_cursor = None;
    assert!(empty.encode().is_ok());
    empty.registry_generation_checksum = None;
    assert!(empty.encode().is_ok());
    assert!(BackupListResponse::decode(&vec![b' '; 65537]).is_err());
}
#[test]
fn largest_allowed_page_fits_the_published_bound() {
    let mut value = page();
    let entry = value.entries[0].clone();
    value.next_cursor = None;
    value.entries = (1..=128)
        .map(|id| {
            let mut entry = entry.clone();
            entry.snapshot_id = format!("{id:032x}");
            entry
        })
        .collect();
    let encoded = value.encode().expect("full page");
    assert!(encoded.len() < positron_api::backup::MAX_LIST_RESPONSE_BYTES);
    value.entries.push(entry);
    assert!(value.encode().is_err());
}
