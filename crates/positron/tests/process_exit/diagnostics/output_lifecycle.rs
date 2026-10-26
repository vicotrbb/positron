//! Real native lifecycle owns and reaps the optional output child.
#![cfg(unix)]
use super::output_helper::full_pipe;
use super::*;
use std::{os::unix::process::ExitStatusExt, process::Child, time::Instant};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct OutputChild(Child);
impl std::ops::Deref for OutputChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for OutputChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for OutputChild {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_none()) && self.0.kill().is_ok() {
            let _reaped = self.0.wait();
        }
    }
}
fn children(parent: u32) -> TestResult<Vec<u32>> {
    let output = Command::new("ps").args(["-axo", "pid=,ppid="]).output()?;
    assert!(output.status.success());
    assert!(output.stdout.len() <= 1024 * 1024);
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            (ppid == parent).then_some(pid)
        })
        .collect())
}
fn await_helper(parent: u32) -> TestResult<u32> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let children = children(parent)?;
        assert!(
            children.len() <= 1,
            "one invocation must own at most one output helper"
        );
        if let Some(pid) = children.first() {
            return Ok(*pid);
        }
        if Instant::now() >= deadline {
            return Err("native output child was not observed".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn await_terminated(pid: u32) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let output = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()?;
        let state = String::from_utf8(output.stdout)?;
        // A dead parent's orphan can briefly await the operating-system reaper.
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("output helper {pid} remains alive: {state}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn terminate(child: &mut Child) -> TestResult {
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(wait_for_child(child)?.code(), Some(0));
    Ok(())
}
fn http(port: u16, path: &str, credential: &str, body: &[u8]) -> TestResult<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert!(
        response.starts_with(b"HTTP/1.1 200 "),
        "public {path} failed with {}",
        String::from_utf8_lossy(&response)
    );
    let boundary = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("HTTP response boundary")?;
    Ok(response
        .get(boundary + 4..)
        .ok_or("HTTP response body")?
        .to_vec())
}

#[test]
fn parent_sigkill_ends_its_output_helper_while_stderr_stays_full() -> TestResult {
    let (_reader, writer) = full_pipe()?;
    let mut parent = OutputChild(
        Command::new(env!("CARGO_BIN_EXE_positron"))
            .args(["serve", "--set", "storage.data_directory=relative"])
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()?,
    );
    let helper = await_helper(parent.id())?;
    std::thread::sleep(Duration::from_millis(50));
    assert!(parent.try_wait()?.is_none());
    parent.kill()?;
    assert_eq!(parent.wait()?.signal(), Some(9));
    await_terminated(helper)?;
    Ok(())
}

#[test]
fn normal_and_saturated_output_reap_before_graceful_marker_and_retain_acknowledged_data()
-> TestResult {
    let _guard = PROCESS_TEST.lock().map_err(|_| "process test lock")?;
    for saturated in [false, true] {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("positron-output-drain-{nonce}"));
        let roots = ChildRoots::new(&root)?;
        let paths =
            BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let ports = available_ports()?;
        let config = root.join("positron.toml");
        fs::write(
            &config,
            format!(
                "schema_version=1\n[runtime]\nshutdown_grace_seconds=2\n[listener]\ncontrol_path=\"{}\"\noperations_bind_address=\"127.0.0.1:{}\"\napi_bind_address=\"127.0.0.1:{}\"\notlp_grpc_bind_address=\"127.0.0.1:{}\"\notlp_http_bind_address=\"127.0.0.1:{}\"\nloki_push_bind_address=\"127.0.0.1:{}\"\noperations_transport=\"plaintext\"\napi_transport=\"plaintext\"\notlp_grpc_transport=\"plaintext\"\notlp_http_transport=\"plaintext\"\nloki_push_transport=\"plaintext\"\n[storage]\ndata_directory=\"{}\"\nsecrets_directory=\"{}\"\n[security]\nlocal_key_file=\"{}\"\n",
                std::env::temp_dir()
                    .join(format!("positron-output-{nonce}.sock"))
                    .display(),
                ports[0],
                ports[1],
                ports[2],
                ports[3],
                ports[4],
                roots.data.display(),
                roots.secrets.display(),
                roots.secrets.join("local-root-key.v1").display()
            ),
        )?;
        let (mut reader, writer) = if saturated {
            full_pipe()?
        } else {
            std::io::pipe()?
        };
        let flags = rustix::fs::fcntl_getfl(&writer)? & rustix::fs::OFlags::NONBLOCK;
        let mut child = OutputChild(
            Command::new(env!("CARGO_BIN_EXE_positron"))
                .args(["serve", "--config"])
                .arg(&config)
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer.try_clone()?))
                .spawn()?,
        );
        wait_for_ready(ports[0])?;
        let helper = children(child.id())?.first().copied();
        http(ports[3], "/v1/logs", claim.ingest_secret().ok_or("ingest credential")?, br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"42","body":{"stringValue":"output-helper-retained"}}]}]}]}"#)?;
        terminate(&mut child)?;
        if let Some(helper) = helper {
            await_terminated(helper)?;
        }
        assert_eq!(
            rustix::fs::fcntl_getfl(&writer)? & rustix::fs::OFlags::NONBLOCK,
            flags
        );
        let reopened = InstanceBootstrap::reopen(&paths)?;
        assert!(reopened.graceful_shutdown_record()?.is_some());
        drop(reopened);
        drop(writer);
        if !saturated {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            assert!(!bytes.is_empty());
            for line in bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let value: serde_json::Value = serde_json::from_slice(line)?;
                assert!(value["event"].is_string());
            }
        }
        let mut restarted = OutputChild(
            Command::new(env!("CARGO_BIN_EXE_positron"))
                .args(["serve", "--config"])
                .arg(&config)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        wait_for_ready(ports[0])?;
        let query = http(ports[1], positron_api::log_query::HTTP_PATH, claim.query_secret().ok_or("query credential")?, br#"{"pipeline":"logs | range query_time 0 100 | limit 16","budget":{"scannedBytes":"1048576","decodedRecords":"16","outputRows":"16","outputBytes":"16384","memoryBytes":"1048576","cpuWorkUnits":"15","wallSeconds":"5","maximumTimeRangeNanoseconds":"100"}}"#)?;
        let response = positron_api::log_query::LogQueryResponse::decode(&query)?;
        use positron_api::log_query::log_query_event::Event;
        assert!(response.events.last().and_then(|event| event.event.as_ref()).is_some_and(|event| matches!(event, Event::Terminal(terminal) if terminal.state == "complete" && terminal.stats.as_ref().is_some_and(|stats| stats.records == 1))));
        assert_eq!(
            String::from_utf8(query)?
                .matches("output-helper-retained")
                .count(),
            1
        );
        terminate(&mut restarted)?;
        fs::remove_dir_all(root)?;
    }
    Ok(())
}
