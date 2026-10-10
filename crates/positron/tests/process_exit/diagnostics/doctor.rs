//! Doctor inspects live owners through public transports without changing their state.
use super::*;

#[cfg(unix)]
#[test]
fn serving_doctor_on_operations_and_control_preserves_persistent_and_runtime_facts()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let (root, roots, config) = initialized_doctor_fixture("live-read-only")?;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let ports = available_ports()?;
    fs::write(
        &config,
        process_configuration(&root, &roots.data, &roots.secrets, ports),
    )?;
    let control = std::path::Path::new("/tmp")
        .join(root.file_name().ok_or("root name")?)
        .with_extension("sock");
    let effective = std::sync::Arc::new(positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&config),
            std::iter::empty::<(String, String)>(),
            std::iter::empty::<(String, String)>(),
        )
        .map_err(|failure| format!("configuration inputs: {failure:?}"))?,
    )?);
    let host = positron_runtime::NativeHost::new(positron_runtime::NativeBindings::from_effective(
        &effective,
    )?);
    // Control the independent background task at the public host seam so
    // strict before/after assertions isolate Doctor's effects. Native listener
    // workers and the compiled Doctor command remain real.
    let tasks = InspectionTasks(&host);
    let process = positron_runtime::ApplicationRuntime::start(
        positron_runtime::ServeConfiguration::new(
            paths,
            positron_runtime::InitializationMode::ExistingOnly,
        )
        .with_effective_configuration(effective),
        positron_runtime::HostInputs::new(&host, &tasks),
    )?;
    let checks = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), Box<dyn std::error::Error>> {
            wait_for_ready(ports[0])?;
            let before_status = status(ports[0], claim.secret())?;
            let before_data = volume_bytes(&roots.data)?;
            let before_secrets = volume_bytes(&roots.secrets)?;
            let data_modified = fs::metadata(&roots.data)?.modified()?;
            let secrets_modified = fs::metadata(&roots.secrets)?.modified()?;
            for control_mode in [false, true] {
                let mut command = Command::new(env!("CARGO_BIN_EXE_positron"));
                command.args(["doctor", "--online", "--credential-stdin"]);
                if control_mode {
                    command.arg("--control-path").arg(&control);
                } else {
                    command.args([
                        "--endpoint",
                        &format!("127.0.0.1:{}", ports[0]),
                        "--allow-plaintext",
                    ]);
                }
                let mut child = command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()?;
                let mut input = child.stdin.take().ok_or("doctor stdin")?;
                input.write_all(claim.secret().as_bytes())?;
                input.write_all(b"\n")?;
                drop(input);
                let output = child.wait_with_output()?;
                assert_eq!(output.status.code(), Some(3));
                let report = String::from_utf8(output.stdout)?;
                assert!(report.contains("status=inspection_incomplete"), "{report}");
                assert!(report.contains("process_phase=serving"), "{report}");
                assert!(report.contains("backup_manifest_verification=not_shipped"));
                assert!(report.contains("storage_ownership=held"), "{report}");
                assert!(report.contains("storage_capabilities=not_probed_read_only"));
                assert!(report.contains("storage_usable_disk_bytes="));
                assert!(report.contains("storage_disk_pressure=healthy"));
                assert!(report.contains("resource_governor_recovery_reserve_memory_bytes="));
                assert!(!report.contains(claim.secret()));
            }
            assert_eq!(
                before_status,
                status(ports[0], claim.secret())?,
                "Doctor must not change authoritative live facts"
            );
            assert_eq!(before_data, volume_bytes(&roots.data)?);
            assert_eq!(before_secrets, volume_bytes(&roots.secrets)?);
            assert_eq!(
                data_modified,
                fs::metadata(&roots.data)?.modified()?,
                "Doctor must not create and remove capability probe artifacts"
            );
            assert_eq!(secrets_modified, fs::metadata(&roots.secrets)?.modified()?);
            Ok(())
        },
    ));
    assert_eq!(
        process.shutdown(positron_runtime::ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    match checks {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn status(port: u16, bearer: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(format!("GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n").as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response.split_once("\r\n\r\n").ok_or("status response")?;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    Ok(serde_json::from_str(body)?)
}

#[cfg(unix)]
struct InspectionTasks<'host>(&'host positron_runtime::NativeHost);
#[cfg(unix)]
impl positron_runtime::TaskRegistrar for InspectionTasks<'_> {
    fn register(
        &self,
        role: positron_runtime::TaskRole,
    ) -> Result<Box<dyn positron_runtime::RegisteredTask>, positron_runtime::TaskFailure> {
        if role == positron_runtime::TaskRole::Maintenance {
            Ok(Box::new(IdleMaintenance))
        } else {
            self.0.register(role)
        }
    }
}
#[cfg(unix)]
struct IdleMaintenance;
#[cfg(unix)]
impl positron_runtime::RegisteredTask for IdleMaintenance {
    fn spawn(
        self: Box<Self>,
        _: positron_runtime::TaskCancellation,
        _: positron_runtime::HealthState,
        _: Option<positron_runtime::ServiceHandle>,
    ) -> Result<Box<dyn positron_runtime::RunningTask>, positron_runtime::TaskFailure> {
        Ok(self)
    }
}
#[cfg(unix)]
impl positron_runtime::RunningTask for IdleMaintenance {
    fn poll_join(
        &mut self,
    ) -> Result<Option<positron_runtime::TaskJoinOutcome>, positron_runtime::TaskFailure> {
        Ok(None)
    }
    fn join_within(
        &mut self,
        _: Duration,
    ) -> Result<positron_runtime::TaskJoinOutcome, positron_runtime::TaskFailure> {
        Ok(positron_runtime::TaskJoinOutcome::Joined)
    }
    fn abort(&mut self) -> Result<(), positron_runtime::TaskFailure> {
        Ok(())
    }
}
