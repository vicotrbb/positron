//! Focused process-exit diagnostics coverage.

use super::*;

#[cfg(unix)]
use std::os::unix::net::UnixListener;

#[cfg(unix)]
#[test]
fn live_control_support_bundle_is_signed_encrypted_and_reports_serving_facts()
-> Result<(), Box<dyn std::error::Error>> {
    use age::{Decryptor, Identity};

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-live-support-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let ports = available_ports()?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, ports),
    )?;
    let control = std::path::Path::new("/tmp")
        .join(root.file_name().ok_or("live support root name")?)
        .with_extension("sock");
    let server = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--config"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_ready(ports[0])?;

    let mut status = TcpStream::connect(("127.0.0.1", ports[0]))?;
    status.write_all(
        format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            claim.secret(),
        )
        .as_bytes(),
    )?;
    let mut status_response = Vec::new();
    status.read_to_end(&mut status_response)?;
    assert!(
        status_response.starts_with(b"HTTP/1.1 200 "),
        "serving status must accept the current system administrator: {}",
        String::from_utf8_lossy(&status_response),
    );

    let identity = age::x25519::Identity::generate();
    let output = root.join("live-support.age");
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["support", "bundle", "create", "--config"])
        .arg(&config)
        .arg("--control-path")
        .arg(&control)
        .arg("--output")
        .arg(&output)
        .arg("--recipient")
        .arg(identity.to_public().to_string())
        .arg("--credential-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = command.stdin.take().ok_or("live bundle stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let result = command.wait_with_output()?;

    let _ = Command::new("/bin/kill")
        .args(["-TERM", &server.id().to_string()])
        .status()?;
    let server_output = server.wait_with_output()?;

    assert!(
        result.status.success(),
        "live support command failed: {}; server stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&server_output.stderr),
    );
    let report = String::from_utf8(result.stdout)?;
    assert!(report.contains("artifact_authentication=unverified_control_response\n"));
    assert!(report.contains("signature=unverified\n"));
    let encrypted = fs::read(&output)?;
    let decryptor = Decryptor::new(&encrypted[..])?;
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?;
    let mut archive = Vec::new();
    reader.read_to_end(&mut archive)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let actor = instance.attribute(
        positron_governance::PresentedCredential::parse(claim.secret())?,
        positron_governance::RequestedIntent::SystemAdministration,
        positron_governance::CompatibilityHints::none(),
    )?;
    let expected_identity = instance.support_bundle_manifest_signer(actor)?.identity();
    verify_authenticated_bundle_archive(&archive, expected_identity)?;
    assert!(
        archive
            .windows(b"manifest-signature.txt".len())
            .any(|bytes| bytes == b"manifest-signature.txt")
    );
    assert!(
        archive
            .windows(b"inspection_mode=online".len())
            .any(|bytes| bytes == b"inspection_mode=online")
    );
    assert!(
        archive
            .windows(b"process_phase=serving".len())
            .any(|bytes| bytes == b"process_phase=serving")
    );
    assert!(
        archive
            .windows(b"inspection_owner=process_lifecycle".len())
            .any(|bytes| bytes == b"inspection_owner=process_lifecycle")
    );
    assert!(
        archive
            .windows(b"process_serving".len())
            .any(|bytes| bytes == b"process_serving")
    );
    assert!(
        !archive
            .windows(b"availability=not_persisted".len())
            .any(|bytes| bytes == b"availability=not_persisted")
    );
    assert!(
        !archive
            .windows(claim.secret().len())
            .any(|bytes| bytes == claim.secret().as_bytes())
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn live_control_support_bundle_does_not_authenticate_an_arbitrary_control_response()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-untrusted-support-{nonce}"));
    let roots = ChildRoots::new(&root)?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let config = root.join("positron.toml");
    fs::write(
        &config,
        process_configuration(
            &root,
            &roots.data,
            &roots.secrets,
            [42_001, 42_002, 42_003, 42_004, 42_005],
        ),
    )?;
    let control =
        std::path::Path::new("/tmp").join(format!("p-us-{}-{nonce}.sock", std::process::id()));
    let listener = UnixListener::bind(&control)?;
    let expected_bearer = claim.secret().as_bytes().to_vec();
    let body = b"arbitrary unsigned control response".to_vec();
    let response_body = body.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let mut request = [0_u8; 4_096];
        let read = stream
            .read(&mut request)
            .map_err(|error| error.to_string())?;
        let request = &request[..read];
        if !request.starts_with(b"POST /control/support-bundle HTTP/1.1\r\n") {
            return Err("support bundle did not issue the control request".to_owned());
        }
        let authorization = format!(
            "Authorization: Bearer {}\r\n",
            String::from_utf8_lossy(&expected_bearer)
        );
        if !request
            .windows(authorization.len())
            .any(|candidate| candidate == authorization.as_bytes())
        {
            return Err("support bundle did not pass the supplied credential".to_owned());
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .and_then(|()| stream.write_all(&response_body))
            .map_err(|error| error.to_string())
    });

    let output_path = root.join("untrusted-control-response.age");
    let identity = age::x25519::Identity::generate();
    let mut command = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["support", "bundle", "create", "--config"])
        .arg(&config)
        .args(["--control-path"])
        .arg(&control)
        .args(["--output"])
        .arg(&output_path)
        .args(["--recipient"])
        .arg(identity.to_public().to_string())
        .arg("--credential-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = command.stdin.take().ok_or("untrusted bundle stdin")?;
    input.write_all(claim.secret().as_bytes())?;
    input.write_all(b"\n")?;
    drop(input);
    let result = command.wait_with_output()?;
    server
        .join()
        .map_err(|_| "untrusted control server panicked")?
        .map_err(|error| format!("untrusted control server failed: {error}"))?;

    assert!(
        result.status.success(),
        "support bundle command failed: {}",
        String::from_utf8_lossy(&result.stdout),
    );
    let report = String::from_utf8(result.stdout)?;
    assert!(
        !report.contains("signature=signed\n"),
        "an arbitrary control response cannot be reported as signed instance evidence: {report}"
    );
    assert!(
        !report.contains("artifact_authentication=authenticated_instance_evidence\n"),
        "an arbitrary control response cannot be reported as authenticated instance evidence: {report}"
    );
    assert!(report.contains("artifact_authentication=unverified_control_response\n"));
    assert!(report.contains("signature=unverified\n"));
    assert_eq!(fs::read(&output_path)?, body);
    fs::remove_file(&control)?;
    fs::remove_dir_all(root)?;
    Ok(())
}
