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
    assert_eq!(stderr, "positron: configuration rejected\n");
    assert!(!stderr.contains(secret_marker));
    Ok(())
}

#[test]
fn unknown_command_has_the_usage_exit() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("unknown")
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "positron: invalid command line\n"
    );
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
