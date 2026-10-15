use super::*;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn repository_doctor_fifo_failure_releases_runtime_resources()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-runtime-repository-fifo-{}",
        std::process::id()
    ));
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "services::maintenance_api::tests::repository::fifo::doctor_fifo_child_fixture",
            "--ignored",
        ])
        .env("POSITRON_RUNTIME_REPOSITORY_FIFO_PATH", &path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let child_root =
        std::env::temp_dir().join(format!("positron-schema-maintenance-{}-0", child.id()));
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    std::fs::remove_dir_all(path)?;
    if child_root.exists() {
        std::fs::remove_dir_all(child_root)?;
    }
    assert!(
        result.is_some_and(|status| status.success()),
        "Repository Doctor failed or retained its worker/resources"
    );
    Ok(())
}

#[test]
#[ignore = "owned subprocess fixture"]
fn doctor_fifo_child_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let path = std::path::PathBuf::from(
        std::env::var_os("POSITRON_RUNTIME_REPOSITORY_FIFO_PATH").ok_or("fixture path")?,
    );
    let (initialized, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(initialized)?;
    let submit = |action, key| -> Result<_, Box<dyn std::error::Error>> {
        let generation = services
            .open_maintenance_catalog()
            .expect("catalog")
            .pin()?
            .number();
        let accepted = services
            .accept_repository_operation(
                &administrator,
                RepositoryAdmission {
                    action,
                    locator: crate::services::repository_administration::RepositoryLocation::Local(
                        &path,
                    ),
                    repository: [81; 16],
                    expected_generation: generation,
                    idempotency: AdministrativeIdempotencyKey::new([key; 16])?,
                },
            )
            .expect("accepted");
        for _ in 0..32 {
            let operation = services
                .repository_operation_status(&administrator, accepted.operation_id())
                .expect("status");
            if operation.status().is_terminal() {
                return Ok(operation);
            }
            crate::services::maintenance::wake_runtime_maintenance(&services, None)?;
        }
        Err("operation did not terminalize".into())
    };
    assert_eq!(
        submit(RepositoryAction::Initialize, 82)?.status(),
        DurableOperationStatus::Succeeded
    );
    let identity_path = path.join("identity");
    let identity = std::fs::read(&identity_path)?;
    std::fs::remove_file(&identity_path)?;
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&identity_path)
            .status()?
            .success()
    );
    let failed = submit(RepositoryAction::Doctor, 83)?;
    assert_eq!(failed.status(), DurableOperationStatus::Failed);
    assert_eq!(
        services
            .repository_operation_status(&administrator, failed.operation_id())
            .expect("retained failure"),
        failed
    );
    std::fs::remove_file(&identity_path)?;
    std::fs::write(&identity_path, identity)?;
    std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        submit(RepositoryAction::Doctor, 84)?.status(),
        DurableOperationStatus::Succeeded
    );
    Ok(())
}
