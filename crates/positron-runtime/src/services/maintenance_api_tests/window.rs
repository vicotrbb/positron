use super::*;

#[test]
fn maintenance_window_authenticates_before_decode_and_replays_its_atomic_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services.set_maintenance_window("not-a-credential", br#"{\"unexpected\":true}"#),
        Err(MaintenanceServiceFailure::AuthenticationRejected),
        "authentication must precede untrusted window decoding"
    );
    let expected = open_catalog(&initialized)?.pin()?.number();
    let request = MaintenanceWindowRequest::new(
        vec!["backup_snapshot".to_owned(), "compaction".to_owned()],
        expected,
        60,
        "00000000-0000-0000-0000-000000000021".to_owned(),
    );
    let first = services
        .set_maintenance_window(&administrator, &request.encode()?)
        .map_err(|failure| format!("window publication: {failure:?}"))?;
    assert_eq!(first.catalog_generation, expected + 1);
    assert!(first.until_unix_seconds >= 60);
    assert_ne!(first.audit_position, 0);
    assert_eq!(
        services
            .set_maintenance_window(&administrator, &request.encode()?)
            .map_err(|failure| format!("window replay: {failure:?}"))?,
        first,
        "exact retries return the same acknowledged publication"
    );
    let conflict = MaintenanceWindowRequest::new(
        vec!["compaction".to_owned()],
        expected,
        60,
        "00000000-0000-0000-0000-000000000021".to_owned(),
    );
    assert_eq!(
        services.set_maintenance_window(&administrator, &conflict.encode()?),
        Err(MaintenanceServiceFailure::IdempotencyConflict)
    );
    let stale = MaintenanceWindowRequest::new(
        vec!["compaction".to_owned()],
        expected,
        60,
        "00000000-0000-0000-0000-000000000022".to_owned(),
    );
    assert_eq!(
        services.set_maintenance_window(&administrator, &stale.encode()?),
        Err(MaintenanceServiceFailure::PreconditionFailed),
        "the actual committed Catalog generation fences the global window"
    );
    Ok(())
}
