use super::*;

#[test]
fn repository_rejection_preserves_result_and_emits_only_bounded_closed_details()
-> Result<(), Box<dyn std::error::Error>> {
    let remaining = std::sync::atomic::AtomicU8::new(32);
    let mut contents = Vec::new();
    for _ in 0..33 {
        assert_eq!(
            provider_failure_with(
                RepositoryFailure::PermissionDenied,
                &remaining,
                |diagnostic| {
                    crate::render_operational_diagnostic(&mut contents, false, diagnostic)
                }
            ),
            ServiceFailure::BackupRepositoryRejected
        );
    }
    assert_eq!(
        provider_failure_with(RepositoryFailure::Busy, &remaining, |_| {
            panic!("capacity rejection must not emit a repository diagnostic")
        }),
        ServiceFailure::CapacityUnavailable
    );
    assert!(contents.len() <= 16_384);
    let records = String::from_utf8(contents)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(records.len(), 32);
    for record in records {
        assert_eq!(
            record,
            serde_json::json!({
                "component": "runtime",
                "event": "backup_repository_rejected",
                "severity": "error",
                "repository_failure": "PermissionDenied",
            })
        );
    }
    Ok(())
}

#[test]
fn repository_rejection_retains_primary_failure_when_output_is_unavailable() {
    let remaining = std::sync::atomic::AtomicU8::new(1);
    let mut attempted = false;
    assert_eq!(
        provider_failure_with(RepositoryFailure::PermissionDenied, &remaining, |_| {
            attempted = true;
            Err(std::io::Error::other("closed output"))
        }),
        ServiceFailure::BackupRepositoryRejected
    );
    assert!(attempted);
}
