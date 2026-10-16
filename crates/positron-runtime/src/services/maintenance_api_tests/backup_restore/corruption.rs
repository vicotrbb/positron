//! Permanent integrity damage terminates the accepted offline operation.
use super::*;
use positron_governance::{DurableOperationPhase, DurableOperationStatus};
use sha2::{Digest, Sha256};

#[test]
fn transfer_retry_records_failed_after_staged_ciphertext_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_corruption(Damage::Target)
}
#[test]
fn remote_verification_records_failed_after_repository_ciphertext_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_corruption(Damage::Source)
}
#[test]
fn remote_verification_preserves_retry_after_temporary_object_unavailability()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_corruption(Damage::Unavailable)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Damage {
    Target,
    Source,
    Unavailable,
}
fn exercise_corruption(damage: Damage) -> Result<(), Box<dyn std::error::Error>> {
    let remote = damage != Damage::Target;
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = RestoreTestFixture::prepare(RestoreCase::Complete)?;
    let begin = || {
        crate::InstanceBootstrap::begin_restore(
            &fixture.paths,
            &fixture.configuration,
            &fixture.restore,
            positron_kernel::RecoveryUnlock::Identity(&fixture.unlock),
        )
    };
    let mut session = begin()?;
    let operation = session.status().operation_id();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let segment = loop {
        let status = session.step()?;
        let candidate = fs::read_dir(fixture.target.join("data/segments/sealed"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "segment")
            });
        if let Some(segment) = candidate {
            if !remote || status.phase() == DurableOperationPhase::BackupVerification {
                break segment;
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err("corruption setup deadline".into());
        }
    };
    let original = fs::read(&segment)?;
    let path = if remote {
        let hash = Sha256::digest(&original)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fixture.repository_path.join(format!("o-{hash}"))
    } else {
        segment
    };
    assert_eq!(fs::read(&path)?, original);
    let mut damaged = original.clone();
    *damaged.first_mut().ok_or("nonempty segment")? ^= 1;
    let unavailable = path.with_extension("unavailable");
    if damage == Damage::Unavailable {
        fs::rename(&path, &unavailable)?;
    } else {
        fs::write(&path, damaged)?;
    }
    if !remote {
        drop(session);
        session = begin()?;
    }
    loop {
        if session.step().is_err() {
            break;
        }
        assert_ne!(session.status().status(), DurableOperationStatus::Succeeded);
        if std::time::Instant::now() >= deadline {
            return Err("corruption verification deadline".into());
        }
    }
    if damage == Damage::Unavailable {
        assert_eq!(session.status().status(), DurableOperationStatus::Running);
        fs::rename(unavailable, &path)?;
        while !session.step()?.status().is_terminal() {
            if std::time::Instant::now() >= deadline {
                return Err("recovery deadline".into());
            }
        }
        assert_eq!(session.status().status(), DurableOperationStatus::Succeeded);
        drop(session);
        assert!(crate::InstanceBootstrap::reopen(&fixture.paths).is_ok());
        return Ok(());
    }
    assert_eq!(
        session.status().status(),
        DurableOperationStatus::Failed,
        "permanent ciphertext corruption must terminate the accepted owner"
    );
    drop(session);
    if remote {
        fs::write(path, original)?;
    }
    assert_corrupt_restore_failed(
        &fixture.paths,
        &fixture.configuration,
        &fixture.restore,
        &fixture.unlock,
        operation,
    )?;
    assert_restore_target_offline(&fixture.paths);
    Ok(())
}
