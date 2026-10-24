use super::*;

#[test]
fn status_capture_drains_both_streams_before_waiting_for_exit() -> TestResult {
    let child = output_pressure::child()?;
    let output = wait_before(child, Instant::now() + Duration::from_secs(5))?;
    assert!(output.status.success());
    assert!(
        output.stdout == vec![b'x'; 256 * 1024],
        "stdout capture changed"
    );
    assert!(
        output.stderr == vec![b'x'; 256 * 1024],
        "stderr capture changed"
    );
    Ok(())
}

#[test]
fn status_capture_drains_overflow_before_reporting_the_bound() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "positron-output-overflow-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    let fixture = Fixture { root, child: None };
    let marker = fixture.root.join("completed");
    let chunk = "x".repeat(1024);
    let script = format!(
        "i=0; while [ $i -lt 1025 ]; do printf '%s' '{chunk}'; printf '%s' '{chunk}' >&2; i=$((i+1)); done; printf done > \"$1\""
    );
    let child = Command::new("/bin/sh")
        .args(["-c", &script, "output-overflow"])
        .arg(&marker)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let error = wait_before(child, Instant::now() + Duration::from_secs(5))
        .expect_err("oversized capture must be refused after draining");
    assert_eq!(
        error.to_string(),
        "child output exceeded fixture capture bound"
    );
    assert!(
        fs::read(&marker)? == b"done",
        "overflow child did not finish writing both streams"
    );
    Ok(())
}

#[test]
fn binary_doctor_capture_drains_both_streams_before_waiting_for_exit() -> TestResult {
    let output = super::super::collect_doctor(
        output_pressure::child()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    assert!(output.status.success());
    assert!(
        output.stdout == vec![b'x'; 256 * 1024],
        "stdout capture changed"
    );
    assert!(
        output.stderr == vec![b'x'; 256 * 1024],
        "stderr capture changed"
    );
    Ok(())
}

#[test]
fn archive_query_capture_drains_both_streams_before_waiting_for_exit() -> TestResult {
    let output = archive::collect_query(
        output_pressure::child()?,
        Instant::now() + Duration::from_secs(5),
    )?;
    assert!(output.status.success());
    assert!(
        output.stdout == vec![b'x'; 256 * 1024],
        "stdout capture changed"
    );
    assert!(
        output.stderr == vec![b'x'; 256 * 1024],
        "stderr capture changed"
    );
    Ok(())
}
