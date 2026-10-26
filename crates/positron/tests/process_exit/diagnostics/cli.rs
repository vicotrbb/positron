//! Focused process-exit diagnostics coverage.

use super::*;

#[test]
fn invalid_configuration_has_a_stable_nonzero_exit_without_echoing_input()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_marker = "must-not-appear";
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "serve",
            "--set",
            &format!("storage.data_directory={secret_marker}"),
        ])
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    let diagnostic: serde_json::Value = serde_json::from_str(&stderr)?;
    assert_eq!(diagnostic["event"], "configuration_rejected");
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["component"], "runtime");
    assert!(!stderr.contains(secret_marker));
    Ok(())
}

#[test]
fn unknown_command_has_the_usage_exit() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("unknown")
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(diagnostic["event"], "invalid_command_line");
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["component"], "runtime");
    Ok(())
}

#[cfg(unix)]
#[test]
fn doctor_verify_and_bundle_report_stdout_failure_without_panicking()
-> Result<(), Box<dyn std::error::Error>> {
    for arguments in [
        vec!["doctor", "--offline"],
        vec!["verify", "--offline"],
        vec!["support", "bundle"],
    ] {
        let output = command_with_closed_stdout(&arguments)?;
        assert_eq!(
            output.status.code(),
            Some(3),
            "{} reports the failed locked stdout write as an explicit failure",
            arguments.join(" "),
        );
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            !stderr.contains("panicked"),
            "{} must not panic when stdout is unavailable: {stderr}",
            arguments.join(" "),
        );
    }
    Ok(())
}

#[cfg(unix)]
fn command_with_closed_stdout(
    arguments: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let (writer, reader) = UnixStream::pair()?;
    drop(reader);
    // The peer is closed before spawn. Ownership transfers exactly one socket
    // descriptor to the child so its fallible locked stdout write sees EPIPE.
    let descriptor: OwnedFd = writer.into();
    let stdout = Stdio::from(descriptor);
    Ok(Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(arguments)
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()?)
}

#[cfg(unix)]
#[test]
fn native_diagnostic_preserves_the_callers_pipe_flags_and_delivers_json()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, writer) = std::io::pipe()?;
    let before = rustix::fs::fcntl_getfl(&writer)? & rustix::fs::OFlags::NONBLOCK;
    let status = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--set", "storage.data_directory=relative"])
        .stdout(Stdio::null())
        .stderr(Stdio::from(writer.try_clone()?))
        .status()?;
    assert_eq!(status.code(), Some(2));
    assert_eq!(
        rustix::fs::fcntl_getfl(&writer)? & rustix::fs::OFlags::NONBLOCK,
        before,
        "a child diagnostic must not change its caller's shared pipe flags"
    );
    drop(writer);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let diagnostic: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(diagnostic["event"], "configuration_rejected");
    Ok(())
}
