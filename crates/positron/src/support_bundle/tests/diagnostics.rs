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
        .map_err(|_| "store")?
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

#[cfg(unix)]
#[test]
fn crash_store_retains_the_owned_root_after_path_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-crash-owned-root-{nonce}"));
    let retained = root.with_extension("retained");
    let outside = root.with_extension("outside");
    fs::create_dir_all(&root)?;
    fs::create_dir_all(outside.join("diagnostics/crash-records"))?;
    let store =
        super::crash_record::CrashRecordStore::under_data_directory(&root).map_err(|_| "store")?;
    store
        .persist(
            &super::crash_record::SanitizedCrashRecord::new(
                "starting",
                "runtime_startup_failed",
                "runtime",
            )
            .map_err(|_| "record")?,
        )
        .map_err(|_| "initial persist")?;
    let outside_record = outside.join("diagnostics/crash-records/record-00000000000000000000.txt");
    fs::write(
        &outside_record,
        b"record_version=1\nproduct=positron\nbuild_identity=0.0.0\nphase=starting\ncomponent=runtime\nfinding_code=catalog_unavailable\nbacktrace_identity=unavailable\ncatalog_generation=unavailable\noperation_generation=unavailable\n",
    )?;
    let outside_before = fs::read(&outside_record)?;

    fs::rename(&root, &retained)?;
    symlink(&outside, &root)?;

    let readout = store
        .read_recent(
            std::time::Duration::from_secs(60),
            4,
            1_536,
            SystemTime::now(),
        )
        .map_err(|_| "readout")?
        .render();
    assert!(readout.contains("runtime_startup_failed"));
    assert!(!readout.contains("catalog_unavailable"));
    store
        .persist(
            &super::crash_record::SanitizedCrashRecord::new(
                "serving",
                "runtime_poll_panicked",
                "runtime",
            )
            .map_err(|_| "record")?,
        )
        .map_err(|_| "retained persist")?;
    assert_eq!(fs::read(&outside_record)?, outside_before);
    assert_eq!(
        fs::read_dir(retained.join("diagnostics/crash-records"))?.count(),
        2,
        "writes remain under the originally owned root"
    );

    drop(store);
    fs::remove_file(&root)?;
    fs::remove_dir_all(&retained)?;
    fs::remove_dir_all(&outside)?;
    Ok(())
}

#[test]
fn persisted_noncanonical_crash_record_is_omitted_before_a_support_bundle_can_export_a_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-crash-canary-{nonce}"));
    fs::create_dir_all(&root)?;
    super::capture_process_failure(&root, "starting", "runtime_startup_failed", "runtime")
        .map_err(|_| "capture failed")?;
    let record = root
        .join("diagnostics/crash-records")
        .read_dir()?
        .next()
        .ok_or("record missing")??
        .path();
    fs::write(
        record,
        b"record_version=1\nproduct=positron\nbuild_identity=0.0.0\nphase=starting\ncomponent=runtime\nfinding_code=runtime_startup_failed\nbacktrace_identity=unavailable\ncatalog_generation=unavailable\noperation_generation=unavailable\nauthorization=api_key_secret_canary\n",
    )?;
    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .map_err(|_| "store")?
        .read_recent(
            std::time::Duration::from_secs(60),
            1,
            512,
            SystemTime::now(),
        )
        .map_err(|_| "readout failed")?;
    assert_eq!(readout.render(), "record_count=0\n");
    assert!(readout.omissions().contains(&"malformed_crash_record"));
    assert!(!readout.render().contains("api_key_secret_canary"));
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
        .map_err(|_| "store")?
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
    super::capture_process_failure(&root, "starting", "runtime_startup_failed", "runtime")
        .map_err(|_| "first capture")?;
    super::capture_process_failure(&root, "starting", "catalog_unavailable", "runtime")
        .map_err(|_| "second capture")?;
    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .map_err(|_| "store")?
        .read_recent(
            std::time::Duration::from_secs(60),
            1,
            512,
            SystemTime::now(),
        )
        .map_err(|_| "bounded readout")?;
    let rendered = readout.render();
    assert!(
        rendered.contains("runtime_startup_failed") || rendered.contains("catalog_unavailable")
    );
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
    super::capture_process_failure(&root, "starting", "runtime_startup_failed", "runtime")
        .map_err(|_| "capture")?;
    let later = SystemTime::now()
        .checked_add(std::time::Duration::from_secs(60))
        .ok_or("clock")?;
    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .map_err(|_| "store")?
        .read_recent(std::time::Duration::from_secs(1), 4, 512, later)
        .map_err(|_| "readout")?;
    assert_eq!(readout.render(), "record_count=0\n");
    assert!(readout.omissions().contains(&"crash_record_log_window"));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn crash_readout_bounds_invalid_directory_entries_and_declares_unknown_omissions()
-> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-crash-invalid-bound-{nonce}"));
    let records = root.join("diagnostics/crash-records");
    fs::create_dir_all(&records)?;
    for index in 0..65 {
        fs::write(
            records.join(format!("invalid-{index:03}")),
            b"not a crash record",
        )?;
    }

    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .map_err(|_| "store")?
        .read_recent(
            std::time::Duration::from_secs(60),
            32,
            12_288,
            SystemTime::now(),
        )
        .map_err(|_| "bounded readout")?;

    assert_eq!(readout.render(), "record_count=0\n");
    assert_eq!(
        readout.omissions(),
        [
            "unknown_crash_record_file",
            "crash_record_enumeration_limit"
        ]
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn controlled_process_restart_preserves_each_crash_record() -> Result<(), Box<dyn std::error::Error>>
{
    const PHASE: &str = "POSITRON_CRASH_RESTART_PHASE";
    const ROOT: &str = "POSITRON_CRASH_RESTART_ROOT";
    const NAME: &str = "support_bundle::tests::diagnostics::controlled_process_restart_preserves_each_crash_record";
    if let Ok(phase) = std::env::var(PHASE) {
        let root = std::path::PathBuf::from(std::env::var(ROOT)?);
        fs::create_dir_all(&root)?;
        let finding = if phase == "first" {
            "runtime_startup_failed"
        } else {
            "catalog_unavailable"
        };
        return super::capture_process_failure(&root, "starting", finding, "runtime")
            .map_err(|_| "crash record capture failed".into());
    }

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-crash-restart-{nonce}"));
    let binary = std::env::current_exe()?;
    for phase in ["first", "second"] {
        let status = std::process::Command::new(&binary)
            .args(["--exact", NAME])
            .env(PHASE, phase)
            .env(ROOT, &root)
            .status()?;
        if !status.success() {
            let _ = fs::remove_dir_all(&root);
            return Err(format!("{phase} process failed to capture its crash record").into());
        }
    }
    let readout = super::crash_record::CrashRecordStore::under_data_directory(&root)
        .map_err(|_| "store")?
        .read_recent(
            std::time::Duration::from_secs(60),
            2,
            768,
            SystemTime::now(),
        )
        .map_err(|_| "readout")?;
    let rendered = readout.render();
    assert!(rendered.contains("runtime_startup_failed"));
    assert!(rendered.contains("catalog_unavailable"));
    fs::remove_dir_all(root)?;
    Ok(())
}
