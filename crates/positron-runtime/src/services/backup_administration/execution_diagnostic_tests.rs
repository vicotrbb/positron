use super::*;

#[test]
fn repository_rejection_preserves_result_and_emits_only_bounded_closed_details()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "POSITRON_BACKUP_REJECTION_DIAGNOSTIC_CHILD";
    if std::env::var_os(CHILD).is_some() {
        for _ in 0..33 {
            assert_eq!(
                provider_failure(RepositoryFailure::PermissionDenied),
                ServiceFailure::BackupRepositoryRejected
            );
        }
        assert_eq!(
            provider_failure(RepositoryFailure::Busy),
            ServiceFailure::CapacityUnavailable
        );
        return Ok(());
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .env(CHILD, "1")
        .args([
            "--exact",
            "services::backup_administration::execution::diagnostic_tests::repository_rejection_preserves_result_and_emits_only_bounded_closed_details",
            "--nocapture",
        ])
        .output()?;
    assert!(output.status.success());
    let records = String::from_utf8(output.stderr)?
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
