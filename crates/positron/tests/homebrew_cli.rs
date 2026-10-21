use std::{fs, process::Command};
#[path = "../../positron-release/tests/support/mod.rs"]
mod support;

#[test]
fn release_cli_generates_formula_without_configuration_and_refuses_overwrite() {
    let fixture = support::Fixture::new();
    let inventory = fixture.root.join("inventory.json");
    let output = fixture.root.join("positron.rb");
    fs::write(&inventory, fixture.inventory.canonical_bytes().unwrap()).unwrap();
    let args = [
        "release",
        "homebrew",
        "--inventory",
        inventory.to_str().unwrap(),
        "--out",
        output.to_str().unwrap(),
    ];
    let result = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        positron_release::homebrew_formula(&fixture.inventory).unwrap()
    );
    let result = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(args)
        .output()
        .unwrap();
    assert!(!result.status.success());
    fs::write(&inventory, b"{}").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "release",
            "homebrew",
            "--inventory",
            inventory.to_str().unwrap(),
            "--out",
            fixture.root.join("bad.rb").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!fixture.root.join("bad.rb").exists());
}

/// The native macOS matrix supplies the actual twice-built archive. The other
/// platform remains an explicit synthetic fixture; no release is published.
#[test]
fn prepare_native_homebrew_installation_fixture_when_requested() {
    let Some(archive) = std::env::var_os("POSITRON_TEST_HOMEBREW_ARCHIVE") else {
        return;
    };
    let directory = std::path::PathBuf::from(
        std::env::var_os("POSITRON_TEST_HOMEBREW_OUTPUT").expect("fixture output"),
    );
    fs::create_dir(&directory).unwrap();
    let mut fixture = support::Fixture::new();
    let target = format!("macos-{}", std::env::consts::ARCH);
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| {
            artifact.surface == positron_release::Surface::NativeArchive
                && artifact.target == target
        })
        .unwrap();
    let archive = fs::read(archive).unwrap();
    fixture.replace_artifact(index, &archive, &archive);
    fs::write(
        directory.join("positron.rb"),
        positron_release::homebrew_formula(&fixture.inventory).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("archive-name"),
        &fixture.inventory.artifacts[index].file,
    )
    .unwrap();
    fs::write(
        directory.join("inventory.json"),
        fixture.inventory.canonical_bytes().unwrap(),
    )
    .unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn homebrew_service_drains_restarts_and_retains_state_across_uninstall() {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let Some(formula) = std::env::var_os("POSITRON_TEST_HOMEBREW_FORMULA") else {
        return;
    };
    let brew = |args: &[&std::ffi::OsStr]| {
        let output = Command::new("brew")
            .args(args)
            .env("HOMEBREW_NO_AUTO_UPDATE", "1")
            .env("HOMEBREW_NO_INSTALL_CLEANUP", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "brew failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    let prefix = String::from_utf8(brew(&["--prefix".as_ref()]).stdout).unwrap();
    let prefix = std::path::Path::new(prefix.trim());
    let config_dir = prefix.join("etc/positron");
    let data = prefix.join("var/lib/positron");
    let secrets = prefix.join("var/lib/positron-secrets");
    let runtime = prefix.join("var/run/positron");
    // These are isolated qualification hosts, never adopt an existing instance.
    for path in [&config_dir, &data, &secrets, &runtime] {
        assert!(
            !path.exists(),
            "qualification must not adopt {}",
            path.display()
        );
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let binary = prefix.join("opt/positron/bin/positron");
    let config = config_dir.join("positron.toml");
    let probes = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let ports = probes
        .iter()
        .map(|probe| probe.local_addr().unwrap().port())
        .collect::<Vec<_>>();
    let mut settings = format!(
        "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 5\n[listener]\ncontrol_path = \"{}/control.sock\"\n",
        runtime.display()
    );
    for (name, port) in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"]
        .into_iter()
        .zip(&ports)
    {
        settings.push_str(&format!(
            "{name}_bind_address = \"127.0.0.1:{port}\"\n{name}_transport = \"plaintext\"\n"
        ));
    }
    settings.push_str(&format!("[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}/local-root-key.v1\"\n", data.display(), secrets.display(), secrets.display()));
    fs::write(&config, settings).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o400)).unwrap();
    let ready = || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, ports[0])).and_then(
                |mut stream| {
                    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
                    stream.write_all(
                        b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )?;
                    let mut bytes = String::new();
                    stream.read_to_string(&mut bytes)?;
                    Ok(bytes)
                },
            );
            if response.is_ok_and(|response| response.starts_with("HTTP/1.1 200")) {
                break;
            }
            assert!(Instant::now() < deadline, "service readiness deadline");
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    drop(probes);
    let mut child = Command::new(&binary)
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    ready();
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("initial Drain deadline");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let claimed = Command::new(&binary)
        .args(["bootstrap", "claim", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(claimed.status.success());
    let claimed = String::from_utf8(claimed.stdout).unwrap();
    let query_secret = claimed
        .lines()
        .find_map(|line| line.strip_prefix("query_secret="))
        .unwrap();
    let request = config_dir.join("retained-query.json");
    fs::write(&request, br#"{"pipeline":"logs | range query_time 0 100 | limit 16","budget":{"scannedBytes":"1048576","decodedRecords":"16","outputRows":"16","outputBytes":"16384","memoryBytes":"1048576","cpuWorkUnits":"15","wallSeconds":"5","maximumTimeRangeNanoseconds":"100"}}"#).unwrap();
    let record_visible = || {
        use positron_api::log_query::{
            LogQueryResponse, log_query_cell::Value as Cell, log_query_event::Event,
            log_query_value::Value,
        };
        let mut child = Command::new(&binary)
            .args([
                "query",
                "--endpoint",
                &format!("127.0.0.1:{}", ports[1]),
                "--credential-stdin",
                "--allow-plaintext",
                "--request",
            ])
            .arg(&request)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(query_secret.as_bytes())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("public query deadline");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response = LogQueryResponse::decode(&output.stdout).unwrap();
        let complete = response.events.last().and_then(|event| event.event.as_ref()).is_some_and(|event| matches!(event, Event::Terminal(terminal) if terminal.state == "complete" && terminal.stats.as_ref().is_some_and(|stats| stats.records == 1)));
        let mut found = false;
        for event in response.events {
            if let Some(Event::Batch(batch)) = event.event {
                for row in batch.rows {
                    for cell in row.cells {
                        if let Some(Cell::NativeValue(value)) = cell.value
                            && let Some(Value::TextValue(text)) = value.value
                            && text == "homebrew-retained-116"
                        {
                            found = true;
                        }
                    }
                }
            }
        }
        complete && found
    };
    let mut observations = Vec::new();
    let key = fs::read(secrets.join("local-root-key.v1")).unwrap();
    for action in ["start", "restart"] {
        brew(&["services".as_ref(), action.as_ref(), &formula]);
        ready();
        if action == "start" {
            let ingest_secret = claimed
                .lines()
                .find_map(|line| line.strip_prefix("ingest_secret="))
                .unwrap();
            let body = br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"42","body":{"stringValue":"homebrew-retained-116"}}]}]}]}"#;
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let mut stream =
                    TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, ports[3])).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                write!(stream, "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {ingest_secret}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(body).unwrap();
                let mut response = String::new();
                stream.take(65_537).read_to_string(&mut response).unwrap();
                assert!(response.len() <= 65_536);
                if response.starts_with("HTTP/1.1 200 ") {
                    break;
                }
                assert!(
                    response.starts_with("HTTP/1.1 429 ")
                        && response.to_ascii_lowercase().contains("retry-after: 1")
                        && Instant::now() + Duration::from_secs(1) < deadline,
                    "ingest refused: {response}"
                );
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        observations.push(record_visible());
    }
    brew(&["services".as_ref(), "stop".as_ref(), &formula]);
    let deadline = Instant::now() + Duration::from_secs(70);
    while TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, ports[0])).is_ok() {
        assert!(Instant::now() < deadline, "service stop deadline");
        std::thread::sleep(Duration::from_millis(100));
    }
    let paths = positron_runtime::BootstrapPaths::new(
        &data,
        &secrets,
        positron_kernel::MountQualification::LocalHost,
    )
    .unwrap();
    let reopened = positron_runtime::InstanceBootstrap::reopen(&paths).unwrap();
    assert!(
        reopened.graceful_shutdown_record().unwrap().is_some(),
        "LaunchAgent stop must complete native Drain"
    );
    drop(reopened);
    assert_eq!(fs::read(secrets.join("local-root-key.v1")).unwrap(), key);
    brew(&["uninstall".as_ref(), &formula]);
    for path in [&config, &data, &secrets] {
        assert!(path.exists());
    }
    assert!(!binary.exists());
    brew(&["install".as_ref(), "--build-from-source".as_ref(), &formula]);
    assert_eq!(fs::read(secrets.join("local-root-key.v1")).unwrap(), key);
    let retry = Command::new(&binary)
        .args(["bootstrap", "claim", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        !retry.status.success(),
        "reinstall cannot create a new bootstrap credential"
    );
    brew(&["services".as_ref(), "start".as_ref(), &formula]);
    ready();
    observations.push(record_visible());
    brew(&["services".as_ref(), "stop".as_ref(), &formula]);
    let deadline = Instant::now() + Duration::from_secs(70);
    while TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, ports[0])).is_ok() {
        assert!(Instant::now() < deadline, "final service stop deadline");
        std::thread::sleep(Duration::from_millis(100));
    }
    brew(&["uninstall".as_ref(), &formula]);
    for path in [&config_dir, &data, &secrets, &runtime] {
        assert!(path.exists());
        fs::remove_dir_all(path).unwrap();
    }
    assert_eq!(
        observations,
        [true, true, true],
        "acknowledged telemetry must survive service restart and brew uninstall/reinstall"
    );
}
