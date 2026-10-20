//! Installed Query authority is an admission prerequisite, with lifecycle eligibility.
use super::*;
use positron_kernel::release_manifest::ProductVersion;
use sha2::{Digest, Sha256};

#[test]
fn installed_upgrade_refuses_missing_query_credential_for_readable_tenant()
-> Result<(), Box<dyn std::error::Error>> {
    check(false, false, false)
}
#[test]
fn installed_upgrade_refuses_ingest_credential_for_read_only_tenant()
-> Result<(), Box<dyn std::error::Error>> {
    check(false, true, false)
}
#[test]
fn installed_upgrade_allows_no_query_credential_when_no_tenant_is_queryable()
-> Result<(), Box<dyn std::error::Error>> {
    check(true, false, false)
}

#[test]
fn installed_upgrade_rejects_stale_generation_without_accepting_intent()
-> Result<(), Box<dyn std::error::Error>> {
    check(true, false, true)
}

#[inline(never)]
fn check(no_queryable: bool, invalid: bool, stale: bool) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (instance, ingest, _, administrator) = fixture.initialized_with_admin()?;
    let export = fixture.recovery_export_directory()?;
    let identity = age::x25519::Identity::generate();
    let recipients =
        positron_kernel::RecoveryRecipients::parse(&[identity.to_public().to_string()])?;
    let bundle = export.join("recovery.age");
    instance.create_recovery_bundle(&bundle, &recipients)?;
    instance.verify_recovery_bundle(
        &bundle,
        positron_kernel::RecoveryUnlock::Identity(&identity),
    )?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    crate::services::upgrade_backup::tests::initialize_registered_repository(
        &instance,
        &services,
        &administrator,
        &export,
    )?;
    if no_queryable || invalid {
        let actor = instance.attribute(
            positron_governance::PresentedCredential::parse(&administrator)?,
            positron_governance::RequestedIntent::SystemAdministration,
            positron_governance::CompatibilityHints::none(),
        )?;
        let state = if no_queryable {
            positron_domain::lifecycle::TenantLifecycleState::Suspended
        } else {
            positron_domain::lifecycle::TenantLifecycleState::ReadOnly
        };
        instance.transition_tenant_lifecycle(
            actor,
            instance.default_tenant_id(),
            state,
            positron_governance::ResourceGeneration::new(1)?,
            positron_governance::AdministrativeIdempotencyKey::new([0xd1; 16])?,
        )?;
    }
    let epoch = instance.catalog_format_epoch()?.ok_or("epoch")?.value();
    drop(services);
    drop(instance);
    let executable = std::env::current_exe()?;
    let bytes = fs::read(&executable)?;
    let hash = Sha256::digest(&bytes).into();
    let source = super::upgrade_end_to_end::fixture_release(
        epoch,
        ProductVersion::parse_exact(env!("CARGO_PKG_VERSION"))?,
        hash,
        bytes.len() as u64,
    )?;
    let target = super::upgrade_end_to_end::fixture_release(
        epoch,
        ProductVersion {
            major: 0,
            minor: 0,
            patch: 1,
        },
        hash,
        bytes.len() as u64,
    )?;
    let configuration = Arc::new(super::upgrade_end_to_end::installed_configuration(
        &fixture,
        &export,
        &source,
        &target,
        &executable,
        if invalid { Some(&ingest) } else { None },
    )?);
    let listeners = crate::process_lifecycle::ObservingListeners::default();
    let tasks = crate::process_lifecycle::ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(fixture.paths()?, InitializationMode::ExistingOnly)
            .with_effective_configuration(configuration),
        HostInputs::new(&listeners, &tasks),
    )?;
    let services = process.services().ok_or("services")?;
    let catalog = open_catalog(&services.instance)?;
    let before = catalog.pin()?;
    drop(catalog);
    let input = positron_api::upgrade::UpgradeRequest {
        action: "start".into(),
        candidate_manifest: Some(super::hex(target.digest())),
        repository_id: Some("2c2c2c2c-2c2c-2c2c-2c2c-2c2c2c2c2c2c".into()),
        retention_seconds: Some(3600),
        expected_catalog_generation: Some(if stale {
            before
                .number()
                .checked_sub(1)
                .ok_or("previous generation")?
        } else {
            before.number()
        }),
        idempotency_key: Some("d2d2d2d2-d2d2-d2d2-d2d2-d2d2d2d2d2d2".into()),
        operation_id: None,
    };
    let result = services.manage_upgrade(&administrator, &input.encode()?);
    if no_queryable && !stale {
        assert!(
            result.is_ok(),
            "no queryable tenant does not require a Query credential: {result:?}"
        );
    } else {
        assert_eq!(
            result,
            Err(if stale {
                MaintenanceServiceFailure::StaleGeneration
            } else {
                MaintenanceServiceFailure::PreconditionFailed
            }),
            "refused preflight must not accept intent"
        );
        assert_eq!(
            open_catalog(&services.instance)?.pin()?.identity(),
            before.identity()
        );
        assert!(process.pending_upgrade_operation()?.is_none());
    }
    assert_eq!(process.health().phase(), crate::ProcessPhase::Serving);
    drop(services);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        crate::ExitOutcome::Graceful
    );
    Ok(())
}
