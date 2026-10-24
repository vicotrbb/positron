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
    let executable = std::env::current_exe()?;
    let path = std::env::temp_dir().join(format!(
        "positron-backup-diagnostic-{}-{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let sink = options.open(&path)?;
    let output = std::process::Command::new(executable)
        .env(CHILD, "1")
        .args([
            "--exact",
            "services::backup_administration::execution::diagnostic_tests::repository_rejection_preserves_result_and_emits_only_bounded_closed_details",
            "--nocapture",
        ])
        .stderr(sink)
        .output();
    let contents = (|| -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(&path)?
            .take(16_385)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    let cleanup = std::fs::remove_file(&path);
    let output = output?;
    let contents = contents?;
    cleanup?;
    assert!(output.status.success());
    assert!(
        contents.len() <= 16_384,
        "diagnostic capture exceeded its fixture bound"
    );
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
