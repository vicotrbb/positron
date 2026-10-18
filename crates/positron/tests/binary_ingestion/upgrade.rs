//! Automatic native handoff and candidate restart through installed commands.
use super::*;
use recovery::{Installed, execute, field, mutate, online, plain};
use std::path::Path;
#[path = "../support/upgrade_candidate.rs"]
mod candidate;
#[path = "../support/upgrade_release.rs"]
mod release;

pub(super) fn run(
    fixture: &mut Fixture,
    installed: Installed<'_>,
    target: &Path,
    expected: &[u8],
) -> TestResult<PathBuf> {
    archive::stop(&mut fixture.child)?;
    let candidate = candidate::prepare()?;
    let archive = positron_release::native_archive(
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH).parse()?,
        &fs::read(&candidate.binary)?,
    )?;
    let installation = target.join("candidate-installation");
    fs::create_dir(&installation)?;
    tar::Archive::new(flate2::read::GzDecoder::new(archive.as_slice())).unpack(&installation)?;
    let executable = installation.join("positron/bin/positron");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555))?;
    let export = target.join("export");
    fs::create_dir_all(&export)?;
    fs::set_permissions(&export, fs::Permissions::from_mode(0o700))?;
    let original = fs::read_to_string(installed.config)?;
    let (_, digest) = release::configuration(
        target,
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
        installed.query,
        installed.binary,
        &executable,
        &candidate.source_commit,
        &candidate.candidate_commit,
    )?;
    let generated = fs::read_to_string(installed.config)?;
    let (_, section) = generated
        .split_once("[release.installation]")
        .ok_or("release fixture section")?;
    fs::write(
        installed.config,
        format!("{original}\n[release.installation]{section}"),
    )?;
    fixture.child = Some(
        Command::new(installed.binary)
            .args(["serve", "--config"])
            .arg(installed.config)
            .spawn()?,
    );
    ready(installed.operations)?;
    assert_eq!(
        archive::query_log(
            installed.binary,
            &fixture.root,
            installed.endpoint,
            installed.query
        )?,
        expected
    );
    let operation = mutate(
        "upgrade",
        serde_json::json!({
            "action": "start", "candidate_manifest": digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "repository_id": "11111111-1111-4111-8111-111111111111", "retention_seconds": 3600,
            "idempotency_key": "66666666-6666-4666-8666-666666666666"
        }),
        installed.endpoint,
        installed.admin,
    )?;
    // The actual Process and automatic Maintenance owner must finish the handoff.
    // Sending a signal here would conceal a broken Upgrade-to-Drain transition.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = fixture.child.as_mut().ok_or("source process")?.try_wait()? {
            assert!(status.success(), "automatic upgrade Drain failed: {status}");
            fixture.child = None;
            break;
        }
        if Instant::now() >= deadline {
            return Err(
                "automatic upgrade handoff did not exit within its configured Drain budget".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let mut arguments = plain(&["upgrade", "offline", "advance", "--config"]);
    arguments.extend([
        installed.config.display().to_string(),
        "--operation-id".into(),
        operation.clone(),
        "--seconds".into(),
        "30".into(),
    ]);
    let watchdog = Instant::now() + Duration::from_secs(300);
    loop {
        let advanced = execute(installed.binary, &arguments, None)?;
        eprintln!(
            "installed offline Upgrade turn: {}",
            String::from_utf8_lossy(&advanced.stdout)
        );
        let stage = field(&advanced, "stage")?;
        if stage == "Some(Publishing)" {
            break;
        }
        assert_eq!(field(&advanced, "status")?, "Running");
        assert_eq!(stage, "Some(Snapshot)");
        if Instant::now() >= watchdog {
            return Err("offline Upgrade snapshot watchdog expired".into());
        }
    }
    arguments = plain(&["upgrade", "offline", "publish", "--config"]);
    arguments.extend([
        installed.config.display().to_string(),
        "--operation-id".into(),
        operation.clone(),
    ]);
    execute(installed.binary, &arguments, None)?;
    // Deployment replaces the staged current authority and executable; the
    // product never downloads or replaces itself.
    fs::copy(
        export.join("candidate.manifest"),
        export.join("current.manifest"),
    )?;
    let candidate_inventory = export.join("inventory.json");
    fs::copy(candidate_inventory, export.join("current.inventory.json"))?;
    fixture.child = Some(
        Command::new(&executable)
            .args(["serve", "--config"])
            .arg(installed.config)
            .spawn()?,
    );
    ready(installed.operations)?;
    assert_eq!(
        archive::query_log(
            &executable,
            &fixture.root,
            installed.endpoint,
            installed.query
        )?,
        expected
    );
    let mut arguments = online("upgrade", "status", installed.endpoint);
    arguments.extend(["--operation-id".into(), operation]);
    let status = execute(&executable, &arguments, Some(installed.admin))?;
    assert_eq!(field(&status, "status")?, "succeeded");
    archive::stop(&mut fixture.child)?;
    Ok(executable)
}
