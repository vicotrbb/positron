use positron_backup::{
    HeadSlot, ImmutableObject, LocalRepository, RegistryHeadChange, Repository, RepositoryFailure,
    RepositoryIdentity, UploadPlan,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn managed_fifos_are_rejected_without_waiting_for_a_writer()
-> Result<(), Box<dyn std::error::Error>> {
    for case in ["identity", "object", "head", "upload"] {
        let path = std::env::temp_dir().join(format!(
            "positron-repository-fifo-{}-{case}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", "fifo_child_fixture", "--ignored", "--nocapture"])
            .env("POSITRON_REPOSITORY_FIFO_CASE", case)
            .env("POSITRON_REPOSITORY_FIFO_PATH", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
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
        fs::remove_dir_all(path)?;
        assert!(
            result.is_some_and(|status| status.success()),
            "managed {case} FIFO failed or blocked"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "owned subprocess fixture"]
async fn fifo_child_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::PathBuf::from(
        std::env::var_os("POSITRON_REPOSITORY_FIFO_PATH").ok_or("fixture path")?,
    );
    let case = std::env::var("POSITRON_REPOSITORY_FIFO_CASE")?;
    let identity = RepositoryIdentity::local([1; 16], [2; 16], [3; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone()).await?;
    let object = ImmutableObject::new(b"native FIFO regression".to_vec())?;
    let id = object.id();
    let plan = UploadPlan::new(id, object.bytes().len() as u64)?;
    let slot = HeadSlot::registry();
    let prefix = match case.as_str() {
        "identity" => "identity",
        "object" => {
            repository.put_if_absent(object).await?;
            "o-"
        },
        "head" => {
            repository
                .compare_and_swap_head_at(slot, RegistryHeadChange::new(None, b"head".to_vec())?)
                .await?;
            "h-"
        },
        "upload" => {
            repository.begin_upload(plan).await?;
            "u-"
        },
        _ => return Err("fixture case".into()),
    };
    let artifact = fs::read_dir(&path)?
        .find_map(|entry| {
            entry
                .ok()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
        })
        .ok_or("artifact")?
        .path();
    fs::remove_file(&artifact)?;
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&artifact)
            .status()?
            .success()
    );
    let failure = match case.as_str() {
        "identity" => LocalRepository::attach(&path, &identity).await.err(),
        "object" => repository.head(id).await.err(),
        "head" => repository.registry_head_at(slot).await.err(),
        "upload" => repository.inspect_upload(plan.id()).await.err(),
        _ => return Err("fixture case".into()),
    };
    assert_eq!(failure, Some(RepositoryFailure::CorruptState));
    Ok(())
}
