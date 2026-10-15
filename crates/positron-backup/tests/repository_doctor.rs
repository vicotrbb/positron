use positron_backup::{
    DoctorPlan, ImmutableObject, LocalRepository, Repository, RepositoryIdentity, doctor,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
#[tokio::test]
async fn doctor_proves_provider_behaviors_and_cleans_only_its_probes()
-> Result<(), Box<dyn std::error::Error>> {
    let path =
        std::env::temp_dir().join(format!("positron-repository-doctor-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([21; 16], [22; 16], [23; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone()).await?;
    let retained = ImmutableObject::new(b"unrelated encrypted contents".to_vec())?;
    repository.put_if_absent(retained.clone()).await?;
    let plan = DoctorPlan::new(
        [24; 32],
        identity,
        Duration::from_secs(5),
        Arc::new(AtomicBool::new(false)),
    )?;
    let report = doctor(&repository, plan).await?;
    assert!(report.verified());
    assert_eq!(
        report.policy().versioning,
        positron_backup::PolicyObservation::Unobservable
    );
    assert!(report.probes_deleted());
    assert_eq!(
        report.policy().doctor_probe,
        Some(positron_backup::ObjectProtection::unobservable())
    );
    assert_eq!(
        repository.head(retained.id()).await?.checksum(),
        retained.id().checksum()
    );
    let files = fs::read_dir(&path)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(files.len(), 2);
    fs::remove_dir_all(path)?;
    Ok(())
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn interrupted_doctor_resumes_the_same_owned_probe_without_foreign_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{LocalFault, LocalFaultEffect, LocalFaultPoint, RepositoryFailure};
    for (point, preceding, label) in [
        (LocalFaultPoint::AfterUploadPublication, 0, "upload"),
        (LocalFaultPoint::AfterObjectPublication, 1, "object"),
    ] {
        let path = std::env::temp_dir().join(format!(
            "positron-doctor-resume-{}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let identity = RepositoryIdentity::local([31; 16], [32; 16], [33; 32], &path)?;
        let repository = LocalRepository::initialize(&path, identity.clone())
            .await?
            .with_faults(vec![LocalFault::new(
                point,
                LocalFaultEffect::Interrupted,
                preceding,
            )])?;
        let plan = DoctorPlan::new(
            [34; 32],
            identity.clone(),
            Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
        )?;
        assert_eq!(
            doctor(&repository, plan).await,
            Err(RepositoryFailure::Interrupted)
        );
        drop(repository);
        let reopened = LocalRepository::attach(&path, &identity).await?;
        let plan = DoctorPlan::new(
            [34; 32],
            identity,
            Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
        )?;
        assert!(doctor(&reopened, plan).await?.probes_deleted());
        assert_eq!(fs::read_dir(&path)?.count(), 1);
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_or_expired_doctor_does_not_publish_probes_and_can_be_retried()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::RepositoryFailure;
    let path =
        std::env::temp_dir().join(format!("positron-doctor-deadline-{}", std::process::id()));
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    let identity = RepositoryIdentity::local([41; 16], [42; 16], [43; 32], &path)?;
    let repository = LocalRepository::initialize(&path, identity.clone()).await?;
    let cancelled = DoctorPlan::new(
        [44; 32],
        identity.clone(),
        Duration::from_secs(5),
        Arc::new(AtomicBool::new(true)),
    )?;
    assert_eq!(
        doctor(&repository, cancelled).await,
        Err(RepositoryFailure::Interrupted)
    );
    let expired = DoctorPlan::new(
        [44; 32],
        identity.clone(),
        Duration::from_nanos(1),
        Arc::new(AtomicBool::new(false)),
    )?;
    assert_eq!(
        doctor(&repository, expired).await,
        Err(RepositoryFailure::OutcomeUnknown)
    );
    assert_eq!(fs::read_dir(&path)?.count(), 1);
    let retry = DoctorPlan::new(
        [44; 32],
        identity,
        Duration::from_secs(5),
        Arc::new(AtomicBool::new(false)),
    )?;
    assert!(doctor(&repository, retry).await?.probes_deleted());
    assert_eq!(fs::read_dir(&path)?.count(), 1);
    fs::remove_dir_all(path)?;
    Ok(())
}
