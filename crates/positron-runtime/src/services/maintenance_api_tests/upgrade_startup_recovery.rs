//! Conservative trusted time is a recoverable startup prerequisite.
use super::*;
use positron_governance::{DurableOperationAdministration as Administration, UpgradeStage};
use std::cell::Cell;
use std::time::Instant;

struct RecoveryBudget {
    deadline: Instant,
    attempts: Cell<u32>,
}
impl crate::RecoveryAttemptHost for RecoveryBudget {
    fn after_failure(&self, attempt: crate::RecoveryAttempt) -> crate::RecoveryDecision {
        assert_eq!(
            attempt.failure(),
            crate::BootstrapFailureCode::ResourceUnavailable
        );
        self.attempts.set(self.attempts.get().saturating_add(1));
        if Instant::now() >= self.deadline {
            crate::RecoveryDecision::Exhausted
        } else {
            std::thread::sleep(Duration::from_millis(100));
            crate::RecoveryDecision::Retry
        }
    }
}
#[test]
fn upgrade_startup_trusted_time_uses_existing_recovery_budget_without_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let prepared = super::upgrade_end_to_end::drain_source(false)?;
    super::upgrade_end_to_end::publish_offline(&prepared)?;
    let instance = crate::InstanceBootstrap::reopen_configured(
        &prepared.fixture.paths()?,
        &prepared.configuration,
    )?;
    let catalog = open_catalog(&instance)?;
    let actor = Administration::resume_upgrade_actor(
        &catalog,
        prepared.id,
        instance.retention_time.security_time_seconds()?,
    )?;
    let ahead = instance
        .retention_time
        .security_time_seconds()?
        .checked_add(2)
        .ok_or("time")?;
    Administration::advance_upgrade(&catalog, actor, prepared.id, UpgradeStage::Verifying, ahead)?;
    let before = catalog.pin()?.identity();
    drop(catalog);
    drop(instance);
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let expired = RecoveryBudget {
        deadline: Instant::now(),
        attempts: Cell::new(0),
    };
    let result = crate::ApplicationRuntime::start(
        configuration(&prepared)?,
        crate::HostInputs::with_recovery(&listeners, &tasks, &expired),
    );
    assert!(
        matches!(
            result,
            Err(crate::ExitOutcome::StartupUnavailable(
                crate::BootstrapFailureCode::ResourceUnavailable
            ))
        ),
        "transient trusted-time lag must exhaust recovery, never become a permanent fence"
    );
    assert_eq!(expired.attempts.get(), 1);
    assert!(listeners.bound.borrow().iter().all(|role| matches!(
        role,
        crate::ListenerRole::Control | crate::ListenerRole::Operations
    )));
    assert!(tasks.events.borrow().iter().all(|event| !matches!(
        event,
        crate::process_lifecycle::TaskEvent::Spawned(
            crate::TaskRole::Maintenance
                | crate::TaskRole::Api
                | crate::TaskRole::OtlpGrpc
                | crate::TaskRole::OtlpHttp
                | crate::TaskRole::LokiPush
        )
    )));

    let instance = crate::InstanceBootstrap::reopen_configured(
        &prepared.fixture.paths()?,
        &prepared.configuration,
    )?;
    let catalog = open_catalog(&instance)?;
    assert_eq!(catalog.pin()?.identity(), before);
    assert_eq!(
        Administration::inspect(&catalog, prepared.id)?
            .ok_or("operation")?
            .upgrade_stage(),
        Some(UpgradeStage::Verifying)
    );
    drop(catalog);
    drop(instance);
    let resumed = RecoveryBudget {
        deadline: Instant::now() + Duration::from_secs(30),
        attempts: Cell::new(0),
    };
    let process = crate::ApplicationRuntime::start(
        configuration(&prepared)?,
        crate::HostInputs::with_recovery(&listeners, &tasks, &resumed),
    )?;
    super::upgrade_end_to_end::verify_readiness(&process, prepared.id, &prepared.query)?;
    assert_eq!(
        process.shutdown(crate::ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}
fn configuration(
    prepared: &super::upgrade_end_to_end::DrainedFixture,
) -> Result<crate::ServeConfiguration, Box<dyn std::error::Error>> {
    let mut verification = crate::UpgradeStartupVerification::new(
        prepared.target.clone(),
        Some(prepared.query.clone()),
    )?;
    verification.fixture_version = Some(prepared.version);
    Ok(crate::ServeConfiguration::new(
        prepared.fixture.paths()?,
        crate::InitializationMode::ExistingOnly,
    )
    .with_effective_configuration(Arc::clone(&prepared.configuration))
    .with_upgrade_verification(verification))
}
