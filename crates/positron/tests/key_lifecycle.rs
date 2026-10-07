use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

#[test]
fn cli_manages_keys_through_authenticated_running_api_without_redisplay()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "p-key-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("data"))?;
    std::fs::create_dir_all(root.join("secrets"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.join("secrets"), std::fs::Permissions::from_mode(0o700))?;
    }
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        positron_kernel::MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let ephemeral = "127.0.0.1:0".parse()?;
    let host = NativeHost::new(NativeBindings::new(
        root.join("control.sock"),
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let address = process
        .bound_endpoints()
        .iter()
        .find(|endpoint| endpoint.role() == positron_runtime::ListenerRole::Api)
        .and_then(positron_runtime::BoundEndpoint::socket_address)
        .ok_or("API absent")?
        .to_string();
    let create = [
        "create",
        "--scope",
        "query",
        "--expected-generation",
        "1",
        "--idempotency-key",
        "11111111-1111-1111-1111-111111111111",
    ];
    assert_eq!(raw_status(&address, &[], b"not-json")?, 401);
    assert_eq!(raw_status(&address, &[claim.secret()], b"not-json")?, 400);
    assert_eq!(
        raw_status(
            &address,
            &[claim.secret(), claim.secret()],
            br#"{"action":"list"}"#
        )?,
        400
    );
    assert_eq!(
        raw_status(
            &address,
            &[claim.secret()],
            br#"{"action":"list","tenant":"forged"}"#
        )?,
        400
    );
    assert_eq!(
        raw_status(
            &address,
            &[claim.secret()],
            br#"{"action":"create","scope":"system_administration","expected_generation":1,"idempotency_key":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#
        )?,
        400
    );
    let first = invoke(&address, claim.secret(), &create)?;
    assert!(first.status.success());
    let first = String::from_utf8(first.stdout)?;
    let principal = first
        .lines()
        .find_map(|line| line.strip_prefix("principal="))
        .ok_or("principal absent")?;
    let secret = first
        .lines()
        .find_map(|line| line.strip_prefix("secret="))
        .ok_or("secret absent")?;
    let retry = invoke(&address, claim.secret(), &create)?;
    assert!(retry.status.success());
    assert!(!String::from_utf8(retry.stdout)?.contains(secret));
    let listed = invoke(&address, claim.secret(), &["list"])?;
    assert!(listed.status.success());
    let listed = String::from_utf8(listed.stdout)?;
    assert!(listed.contains(principal));
    assert!(!listed.contains(secret));
    assert!(!invoke(&address, secret, &["list"])?.status.success());
    assert_eq!(raw_status(&address, &[claim.secret()], br#"{"action":"create","scope":"query","expected_generation":1,"idempotency_key":"44444444-4444-4444-4444-444444444444"}"#)?, 409);
    let rotated = invoke(
        &address,
        claim.secret(),
        &[
            "rotate",
            "--principal",
            principal,
            "--expected-generation",
            "2",
            "--idempotency-key",
            "22222222-2222-2222-2222-222222222222",
        ],
    )?;
    assert!(rotated.status.success());
    assert!(String::from_utf8(rotated.stdout)?.contains("secret="));
    let revoked = invoke(
        &address,
        claim.secret(),
        &[
            "revoke",
            "--principal",
            principal,
            "--expected-generation",
            "3",
            "--idempotency-key",
            "33333333-3333-3333-3333-333333333333",
        ],
    )?;
    assert!(revoked.status.success());
    let inspected = invoke(
        &address,
        claim.secret(),
        &["scope-inspect", "--principal", principal],
    )?;
    assert!(inspected.status.success());
    assert!(String::from_utf8(inspected.stdout)?.contains("active=false"));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn native_operations_status_authenticates_and_reports_current_doctor_facts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "p-doctor-status-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let data = root.join("data");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&data)?;
    std::fs::create_dir_all(&secrets)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
    let control = root.join("control.sock");
    let local_key = secrets.join("local-root-key.v1");
    let configuration = format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:0\"\napi_bind_address = \"127.0.0.1:0\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_http_bind_address = \"127.0.0.1:0\"\nloki_push_bind_address = \"127.0.0.1:0\"\noperations_transport = \"plaintext\"\napi_transport = \"plaintext\"\notlp_grpc_transport = \"plaintext\"\notlp_http_transport = \"plaintext\"\nloki_push_transport = \"plaintext\"\n[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n",
        control.display(),
        data.display(),
        secrets.display(),
        local_key.display(),
    );
    let effective = std::sync::Arc::new(resolve(ConfigurationInputs::try_new(
        Some(&configuration),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)?);
    let paths = BootstrapPaths::with_local_key(
        &data,
        &secrets,
        effective.local_key_file().as_path(),
        positron_kernel::MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly)
            .with_effective_configuration(std::sync::Arc::clone(&effective)),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = process
        .bound_endpoints()
        .into_iter()
        .find(|endpoint| endpoint.role() == positron_runtime::ListenerRole::Operations)
        .and_then(|endpoint| endpoint.socket_address())
        .ok_or("operations listener absent")?;

    let unauthorized = doctor_status(endpoint, "forged-credential")?;
    assert!(unauthorized.starts_with("HTTP/1.1 401"));
    let sources_before = source_listing(&data, &secrets)?;
    let response = doctor_status(endpoint, claim.secret())?;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("\"key_custody\":\"verified\""));
    assert!(response.contains("\"catalog_bootstrap\":\"verified\""));
    assert!(response.contains("\"backup_repository\":\"not_configured\""));
    assert!(
        response
            .contains("\"listener_topology\":{\"control\":true,\"operations\":true,\"api\":true")
    );
    assert!(!response.contains(claim.secret()));
    let sources_after = source_listing(&data, &secrets)?;
    assert_eq!(
        sources_after,
        sources_before,
        "{}",
        source_listing_difference(&sources_before, &sources_after, &data, &secrets)
    );

    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn compiled_doctor_reads_fenced_owner_control_facts_without_mutating_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "p-fenced-doctor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let data = root.join("data");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&data)?;
    std::fs::create_dir_all(&secrets)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
    let control = root.join("control.sock");
    let local_key = secrets.join("local-root-key.v1");
    let configuration = format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:0\"\napi_bind_address = \"127.0.0.1:0\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_http_bind_address = \"127.0.0.1:0\"\nloki_push_bind_address = \"127.0.0.1:0\"\noperations_transport = \"plaintext\"\napi_transport = \"plaintext\"\notlp_grpc_transport = \"plaintext\"\notlp_http_transport = \"plaintext\"\nloki_push_transport = \"plaintext\"\n[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n",
        control.display(),
        data.display(),
        secrets.display(),
        local_key.display(),
    );
    let effective = std::sync::Arc::new(resolve(ConfigurationInputs::try_new(
        Some(&configuration),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)?);
    let paths = BootstrapPaths::with_local_key(
        &data,
        &secrets,
        effective.local_key_file().as_path(),
        positron_kernel::MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let mut process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly)
            .with_effective_configuration(std::sync::Arc::clone(&effective)),
        HostInputs::new(&host, &host),
    )?;
    process
        .services()
        .ok_or("services absent")?
        .request_integrity_fence();
    assert!(process.apply_pending_integrity_fence());
    assert_eq!(
        process.health().phase(),
        positron_runtime::ProcessPhase::Fenced
    );
    assert!(
        process.configuration().is_none(),
        "a fence must retire the published configuration with its mutable authority"
    );
    assert!(process.bound_endpoints().iter().all(|endpoint| matches!(
        endpoint.role(),
        positron_runtime::ListenerRole::Control | positron_runtime::ListenerRole::Operations
    )));
    assert!(control_status(control.as_path(), "forged-credential")?.starts_with("HTTP/1.1 401"));
    let authorized_control = control_status(control.as_path(), claim.secret())?;
    assert!(
        authorized_control.starts_with("HTTP/1.1 200"),
        "current SystemAdministrator credential must authorize fenced inspection: {authorized_control}"
    );
    let sources_before = source_listing(&data, &secrets)?;
    let output = invoke_doctor_control(control.as_path(), claim.secret())?;
    assert_eq!(output.status.code(), Some(3));
    let report = String::from_utf8(output.stdout)?;
    assert!(
        report.contains("status=fenced\nfinding_code=DOCTOR_RUNTIME_FENCED"),
        "unexpected Doctor report: {report}"
    );
    assert!(report.contains("evidence_scope=owner_local_control"));
    assert!(report.contains("key_custody=verified"));
    assert!(report.contains("data_listeners_retired=true"));
    assert!(!report.contains(claim.secret()));
    assert_eq!(source_listing(&data, &secrets)?, sources_before);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn invoke_doctor_control(
    control: &std::path::Path,
    credential: &str,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["doctor", "--online", "--control-path"])
        .arg(control)
        .arg("--credential-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("doctor stdin absent")?;
    stdin.write_all(credential.as_bytes())?;
    stdin.write_all(b"\n")?;
    drop(stdin);
    Ok(child.wait_with_output()?)
}

#[cfg(unix)]
fn control_status(
    control: &std::path::Path,
    credential: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(control)?;
    stream.write_all(format!("GET /control/fenced/inspection HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[cfg(unix)]
fn doctor_status(
    endpoint: std::net::SocketAddr,
    credential: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = std::net::TcpStream::connect(endpoint)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.write_all(
        format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[cfg(unix)]
fn source_listing(
    data: &std::path::Path,
    secrets: &std::path::Path,
) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, std::io::Error> {
    let mut listing = Vec::new();
    collect_regular_files(data, &mut listing)?;
    collect_regular_files(secrets, &mut listing)?;
    listing.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(listing)
}

#[cfg(unix)]
fn source_listing_difference(
    before: &[(std::path::PathBuf, Vec<u8>)],
    after: &[(std::path::PathBuf, Vec<u8>)],
    data: &std::path::Path,
    secrets: &std::path::Path,
) -> String {
    let before = source_listing_digests(before);
    let after = source_listing_digests(after);
    let paths = before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>();
    let mut differences = Vec::new();
    for path in paths.into_iter().take(16) {
        let label = source_path_label(path, data, secrets);
        match (before.get(path), after.get(path)) {
            (Some(before), Some(after)) if before != after => {
                differences.push(format!("modified {label}: sha256 {before} -> {after}"));
            },
            (Some(before), None) => {
                differences.push(format!("removed {label}: sha256 {before}"));
            },
            (None, Some(after)) => {
                differences.push(format!("added {label}: sha256 {after}"));
            },
            _ => {},
        }
    }
    if differences.is_empty() {
        "source listing changed without a file-level digest difference".to_owned()
    } else {
        differences.join("; ")
    }
}

#[cfg(unix)]
fn source_listing_digests(
    listing: &[(std::path::PathBuf, Vec<u8>)],
) -> BTreeMap<&std::path::Path, String> {
    listing
        .iter()
        .map(|(path, bytes)| (path.as_path(), format!("{:x}", Sha256::digest(bytes))))
        .collect()
}

#[cfg(unix)]
fn source_path_label(
    path: &std::path::Path,
    data: &std::path::Path,
    secrets: &std::path::Path,
) -> String {
    if let Ok(relative) = path.strip_prefix(data) {
        return format!("data/{}", relative.display());
    }
    if let Ok(relative) = path.strip_prefix(secrets) {
        return format!("secrets/{}", relative.display());
    }
    "outside-configured-source-root".to_owned()
}

#[cfg(unix)]
fn collect_regular_files(
    root: &std::path::Path,
    listing: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_regular_files(&path, listing)?;
        } else if file_type.is_file() {
            listing.push((path, std::fs::read(entry.path())?));
        }
    }
    Ok(())
}

#[test]
fn cli_reports_a_typed_idempotency_conflict_without_echoing_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        let body = "{\"code\":\"idempotency_conflict\"}";
        stream.write_all(
            format!(
                "HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let output = invoke(&endpoint, "credential-canary", &["list"])?;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(
        stderr,
        "positron: idempotency conflict; inspect current state before retrying\n"
    );
    assert!(!stderr.contains("credential-canary"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn cli_reports_invalid_request_without_echoing_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        let body = r#"{"code":"invalid_request"}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let output = invoke(&endpoint, "credential-canary", &["list"])?;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(
        stderr,
        "positron: invalid key request; correct the request before retrying\n"
    );
    assert!(!stderr.contains("credential-canary"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

fn raw_status(
    endpoint: &str,
    credentials: &[&str],
    body: &[u8],
) -> Result<u16, Box<dyn std::error::Error>> {
    let mut stream = std::net::TcpStream::connect(endpoint)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut head = format!(
        "POST /v1/api-keys:manage HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
        body.len()
    );
    for credential in credentials {
        head.push_str(&format!("Authorization: Bearer {credential}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    let mut response = String::new();
    // A rejected header may close without consuming the request body.
    match stream.read_to_string(&mut response) {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        Err(error) => return Err(error.into()),
    }
    Ok(response
        .split_whitespace()
        .nth(1)
        .ok_or("status absent")?
        .parse()?)
}

fn invoke(
    endpoint: &str,
    credential: &str,
    arguments: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("key")
        .args(arguments)
        .args([
            "--endpoint",
            endpoint,
            "--credential-stdin",
            "--allow-plaintext",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin unavailable")?
        .write_all(credential.as_bytes())?;
    Ok(child.wait_with_output()?)
}
