use super::*;

#[test]
fn pseudonyms_are_stable_within_one_bundle_and_separate_across_bundles() {
    let first = super::privacy::Pseudonymizer::new();
    let second = super::privacy::Pseudonymizer::new();
    assert_eq!(
        first.pseudonymize("tenant-a").expect("pseudonym"),
        first.pseudonymize("tenant-a").expect("pseudonym")
    );
    assert_ne!(
        first.pseudonymize("tenant-a").expect("pseudonym"),
        first.pseudonymize("tenant-b").expect("pseudonym")
    );
    assert_ne!(
        first.pseudonymize("tenant-a").expect("pseudonym"),
        second.pseudonymize("tenant-a").expect("pseudonym")
    );
}

#[test]
fn sanitized_crash_record_excludes_panic_payload_and_caps_backtrace_identity() {
    let record =
        super::crash_record::SanitizedCrashRecord::new("serving", "catalog_unavailable", "catalog")
            .expect("typed crash record");
    let rendered = record.render();
    assert!(rendered.contains("phase=serving"));
    assert!(rendered.contains("finding_code=catalog_unavailable"));
    assert!(!rendered.contains("panic_payload"));
    assert!(rendered.len() <= 512);
    let bundle = SupportBundle::build(
        [BundleMember::sanitized_crash_record(record)],
        BundleLimits::new(1, 12_000).expect("limits"),
    )
    .expect("bundle");
    assert!(
        bundle
            .archive()
            .windows(b"catalog_unavailable".len())
            .any(|entry| entry == b"catalog_unavailable")
    );
}

#[test]
fn captured_backtrace_is_persisted_only_as_a_safe_fingerprint()
-> Result<(), Box<dyn std::error::Error>> {
    let record = super::crash_record::SanitizedCrashRecord::new(
        "draining",
        "joined_task_panic",
        "serving_loop",
    )
    .map_err(|_| "typed crash record")?
    .with_backtrace(&std::backtrace::Backtrace::force_capture());
    let rendered = record.render();
    assert!(rendered.contains("backtrace_identity=sha256-"));
    assert!(!rendered.contains("backtrace::"));
    assert!(!rendered.contains("joined task panic payload"));
    Ok(())
}

#[test]
fn persisted_crash_record_reopens_as_bounded_sanitized_support_input()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-crash-record-{nonce}"));
    fs::create_dir_all(&root)?;
    super::capture_process_failure(&root, "starting", "runtime_startup_failed", "runtime")
        .map_err(|_| "capture failed")?;
    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .read_recent(
            std::time::Duration::from_secs(60),
            1,
            512,
            SystemTime::now(),
        )
        .map_err(|_| "readout failed")?;
    let rendered = readout.render();
    assert!(rendered.contains("finding_code=runtime_startup_failed"));
    assert!(!rendered.contains("panic_payload"));
    assert!(!rendered.contains(root.to_string_lossy().as_ref()));
    #[cfg(unix)]
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(
            &fs::metadata(
                root.join("diagnostics/crash-records")
                    .read_dir()?
                    .next()
                    .ok_or("record missing")??
                    .path()
            )?
            .permissions()
        ) & 0o777,
        0o600,
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn joined_task_panic_capture_reopens_only_owned_safe_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let marker = "joined-task-panic-private-canary";
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-joined-panic-{nonce}"));
    fs::create_dir_all(&root)?;
    super::capture_process_failure_with_catalog_generation(
        &root,
        "draining",
        "joined_task_panicked",
        "runtime",
        Some(7),
    )
    .map_err(|_| "capture failed")?;
    let rendered = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .read_recent(
            std::time::Duration::from_secs(60),
            1,
            384,
            SystemTime::now(),
        )
        .map_err(|_| "readout failed")?
        .render();
    assert!(rendered.contains("phase=draining"));
    assert!(rendered.contains("finding_code=joined_task_panicked"));
    assert!(rendered.contains("catalog_generation=7"));
    assert!(rendered.contains("backtrace_identity="));
    assert!(!rendered.contains(marker));
    assert!(!rendered.contains("panic_payload"));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn crash_readout_declares_file_count_truncation_without_exporting_unread_records()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-crash-bound-{nonce}"));
    fs::create_dir_all(&root)?;
    super::capture_process_failure(&root, "starting", "first_failure", "runtime")
        .map_err(|_| "first capture")?;
    super::capture_process_failure(&root, "starting", "second_failure", "runtime")
        .map_err(|_| "second capture")?;
    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .read_recent(
            std::time::Duration::from_secs(60),
            1,
            512,
            SystemTime::now(),
        )
        .map_err(|_| "bounded readout")?;
    let rendered = readout.render();
    assert!(rendered.contains("first_failure") || rendered.contains("second_failure"));
    assert!(readout.omissions().contains(&"crash_record_file_limit"));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn crash_readout_declares_records_outside_the_log_window() -> Result<(), Box<dyn std::error::Error>>
{
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-crash-window-{nonce}"));
    fs::create_dir_all(&root)?;
    super::capture_process_failure(&root, "starting", "window_failure", "runtime")
        .map_err(|_| "capture")?;
    let later = SystemTime::now()
        .checked_add(std::time::Duration::from_secs(60))
        .ok_or("clock")?;
    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .read_recent(std::time::Duration::from_secs(1), 4, 512, later)
        .map_err(|_| "readout")?;
    assert_eq!(readout.render(), "record_count=0\n");
    assert!(readout.omissions().contains(&"crash_record_log_window"));
    fs::remove_dir_all(root)?;
    Ok(())
}
