//! Installed archive behavior through the real executable.
use std::{fs, process::Command};
#[path = "support/archive_binary.rs"]
mod archive_binary;
#[path = "support/native_binary.rs"]
mod native_binary;

#[test]
fn archive_cli_builds_an_installable_exact_host_payload_and_refuses_replacement() {
    let root = std::env::temp_dir().join(format!(
        "p-archive-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let output = root.join("native.tar.gz");
    let target = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let payload = archive_binary::executable().unwrap();
    let payload = payload.to_str().unwrap();
    let args = [
        "release",
        "archive",
        "--target",
        &target,
        "--binary",
        payload,
        "--out",
        output.to_str().unwrap(),
    ];
    let result = Command::new(native_binary::executable())
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(
        fs::File::open(&output).unwrap(),
    ));
    archive.unpack(&root).unwrap();
    let installed = root.join("positron/bin/positron");
    assert_eq!(fs::read(&installed).unwrap(), fs::read(payload).unwrap());
    let result = Command::new(&installed)
        .args(["release", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let result = Command::new(native_binary::executable())
        .args(args)
        .output()
        .unwrap();
    assert!(!result.status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bootstrap_claim_cli_returns_credentials_once_without_logging_them() {
    use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("p-claim-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir(&data).unwrap();
    fs::create_dir(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    let paths = BootstrapPaths::new(
        &data,
        &secrets,
        positron_kernel::MountQualification::LocalHost,
    )
    .unwrap();
    drop(InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive()).unwrap());
    let config = root.join("positron.toml");
    fs::write(&config, format!("schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n[security]\nlocal_key_file = {:?}\n", data, secrets, secrets.join("local-root-key.v1"))).unwrap();
    let result = Command::new(native_binary::executable())
        .args(["bootstrap", "claim", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("administrator_secret="));
    assert!(output.contains("ingest_secret="));
    assert!(output.contains("query_secret="));
    let retry = Command::new(native_binary::executable())
        .args(["bootstrap", "claim", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!retry.status.success());
    assert!(retry.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&retry.stderr).contains(&output));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn query_cli_validates_canonical_request_before_credentials_or_network() {
    let output = Command::new(native_binary::executable())
        .args([
            "query",
            "--request",
            "/missing/query-request.json",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--allow-plaintext",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("query request unavailable"));
}

#[test]
fn query_cli_preserves_canonical_rejection_classes() {
    use std::io::{Read, Write};
    use std::process::Stdio;
    let root = std::env::temp_dir().join(format!("p-query-rejections-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let request = root.join("request.json");
    fs::write(&request, br#"{"pipeline":"logs | range query_time 0 100 | limit 16","budget":{"scannedBytes":"1048576","decodedRecords":"16","outputRows":"16","outputBytes":"16384","memoryBytes":"1048576","cpuWorkUnits":"15","wallSeconds":"5","maximumTimeRangeNanoseconds":"100"}}"#).unwrap();
    for (status, code, message) in [
        (200, "complete", "\"events\""),
        (400, "invalid_request", "invalid bounded query request"),
        (
            401,
            "authentication_rejected",
            "query authentication rejected",
        ),
        (
            429,
            "capacity_unavailable",
            "query capacity unavailable; retry after backoff",
        ),
        (
            503,
            "query_unavailable",
            "query unavailable; inspect instance readiness",
        ),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut received = Vec::new();
            let mut byte = [0];
            while !received.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                received.extend_from_slice(&byte);
            }
            let header = std::str::from_utf8(&received).unwrap();
            let size: usize = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            stream.read_exact(&mut vec![0; size]).unwrap();
            let body = if status == 200 {
                include_bytes!("../../../fuzz/corpus/log_query_api/complete-response").to_vec()
            } else {
                positron_api::log_query::query_rejection(status, code).unwrap()
            };
            write!(stream, "HTTP/1.1 {status} Rejected\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.write_all(&body).unwrap();
        });
        let mut child = Command::new(native_binary::executable())
            .args([
                "query",
                "--endpoint",
                &endpoint.to_string(),
                "--allow-plaintext",
                "--credential-stdin",
                "--request",
            ])
            .arg(&request)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"test-credential")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        server.join().unwrap();
        if status == 200 {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains(message));
            assert!(output.stderr.is_empty());
        } else {
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(message),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(!String::from_utf8_lossy(&output.stderr).contains("test-credential"));
    }
    fs::remove_dir_all(root).unwrap();
}
