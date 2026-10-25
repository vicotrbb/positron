//! Cold bounded calls retain only trusted time; unresolved publication fences this owner.
use super::upgrade_offline::{accept, configuration};
use super::*;
use crate::upgrade::{OfflineUpgradeSession, UpgradeFailure};
use positron_governance::{AdministrativeIdempotencyKey, DurableOperationAdministration};

#[test]
fn offline_upgrade_cold_capacity_retains_only_trusted_elapsed_time()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (id, record) = ineligible(&fixture, &configuration)?;
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let catalog = open_catalog(&instance)?;
    let mut before_objects = std::collections::BTreeSet::new();
    let mut before_anchor = None;
    let before_snapshot = catalog.pin()?;
    for id in before_snapshot.object_identities() {
        let bytes = before_snapshot.object(id)?.ok_or("Catalog object")?;
        if positron_kernel::validate_catalog_anchor_record(bytes)? {
            assert!(before_anchor.replace(bytes.to_vec()).is_none());
        } else {
            before_objects.insert(bytes.to_vec());
        }
    }
    drop(catalog);
    drop(instance);
    let mut session = OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    let operation = session.status()?;
    assert!(matches!(
        session.advance(std::time::Instant::now() + std::time::Duration::from_secs(1)),
        Err(UpgradeFailure::CapacityUnavailable)
    ));
    assert_eq!(session.status()?, operation);
    assert!(matches!(
        session.cancel(
            AdministrativeIdempotencyKey::new([83; 16])?,
            operation.revision()
        ),
        Err(UpgradeFailure::SnapshotUnavailable)
    ));
    assert_eq!(session.status()?, operation);
    drop(session);
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let mut after_objects = std::collections::BTreeSet::new();
    let mut after_anchor = None;
    let after_snapshot = open_catalog(&instance)?.pin()?;
    for id in after_snapshot.object_identities() {
        let bytes = after_snapshot.object(id)?.ok_or("Catalog object")?;
        if positron_kernel::validate_catalog_anchor_record(bytes)? {
            assert!(after_anchor.replace(bytes.to_vec()).is_none());
        } else {
            after_objects.insert(bytes.to_vec());
        }
    }
    assert_eq!(
        after_objects, before_objects,
        "clock checkpoint must preserve every non-clock object"
    );
    assert_ne!(
        Some(after_anchor.ok_or("retained clock anchor")?),
        before_anchor,
        "bounded cold calls must retain genuine elapsed progress despite ineligible intent"
    );
    assert_eq!(
        instance
            .graceful_shutdown_record()?
            .ok_or("Drain marker")?
            .marker_identity(),
        record.marker_identity()
    );
    instance
        .verify_graceful_shutdown_frontiers(&record)
        .map_err(|error| format!("frontiers: {error:?}"))?;
    Ok(())
}

fn ineligible(
    fixture: &Fixture,
    configuration: &positron_config::EffectiveConfiguration,
) -> Result<
    (
        positron_governance::OperationId,
        crate::GracefulShutdownRecord,
    ),
    Box<dyn std::error::Error>,
> {
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = accept(&instance, &services, &administrator, configuration)?;
    let actor = services
        .authorize_system_administration(&administrator)
        .map_err(|error| format!("actor: {error:?}"))?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "Drain")?;
    drop(services);
    drop(instance);
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, configuration)?;
    let record = instance
        .graceful_shutdown_record()
        .map_err(|e| format!("record: {e:?}"))?
        .ok_or("record")?;
    let catalog = open_catalog(&instance)?;
    let committed = catalog
        .confirm_committed_transaction(positron_kernel::TransactionId::new(record.transaction())?)?
        .ok_or("committed Drain")?;
    let evidence = positron_governance::UpgradeDrainEvidence::new(
        committed.snapshot().identity().to_bytes(),
        record.catalog_generation(),
        record.marker_identity(),
        record.transaction(),
    )?;
    let future = instance
        .retention_time
        .governance_now_seconds()?
        .checked_add(3600)
        .ok_or("fixture future")?;
    DurableOperationAdministration::record_upgrade_drain(&catalog, actor, id, evidence, future)?;
    Ok((id, record))
}

#[test]
fn unresolved_clock_checkpoint_requires_a_new_offline_owner_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (id, _) = ineligible(&fixture, &configuration)?;
    let mut session = OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    let operation = session.status()?;
    use positron_kernel::CatalogPublicationFault::SynchronizeGenerationDirectory;
    let result = positron_kernel::with_catalog_publication_fault_sequence_after(
        &[
            (SynchronizeGenerationDirectory, 0),
            (SynchronizeGenerationDirectory, 0),
        ],
        || session.advance(std::time::Instant::now() + std::time::Duration::from_secs(1)),
    );
    assert_eq!(result, Err(UpgradeFailure::PersistenceUnavailable));
    assert_eq!(session.status()?, operation);
    assert_eq!(
        session.advance(std::time::Instant::now()),
        Err(UpgradeFailure::PersistenceUnavailable)
    );
    assert_eq!(
        session.cancel(
            AdministrativeIdempotencyKey::new([85; 16])?,
            operation.revision()
        ),
        Err(UpgradeFailure::PersistenceUnavailable)
    );
    assert_eq!(session.fail(), Err(UpgradeFailure::PersistenceUnavailable));
    assert_eq!(
        session.publish_installed(&configuration),
        Err(UpgradeFailure::PersistenceUnavailable)
    );
    assert_eq!(
        session.rollback_installed(
            &configuration,
            AdministrativeIdempotencyKey::new([86; 16])?,
            operation.revision()
        ),
        Err(UpgradeFailure::PersistenceUnavailable)
    );
    drop(session);
    let mut recovered = OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    assert_eq!(recovered.advance(std::time::Instant::now())?, operation);
    Ok(())
}

#[test]
fn cold_offline_cancellation_waits_for_genuine_clock_catchup()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = accept(&instance, &services, &administrator, &configuration)?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "Drain")?;
    drop(services);
    drop(instance);

    let mut instance =
        crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let baseline = instance.retention_time.status().safe_anchor();
    let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(baseline);
    clock.recover_catalog_anchor(&open_catalog(&instance)?.pin()?)?;
    instance.install_retention_time_for_test(clock)?;
    elapsed.advance(2_000_000_000)?;
    let mut session = OfflineUpgradeSession::begin_recovered(instance, &configuration, id)?;
    let recorded = session.status()?;
    assert!(recorded.upgrade_drain_evidence().is_some());
    assert_eq!(session.advance(std::time::Instant::now())?, recorded);
    drop(session);

    let mut instance =
        crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(baseline);
    clock.recover_catalog_anchor(&open_catalog(&instance)?.pin()?)?;
    instance.install_retention_time_for_test(clock)?;
    let recovered_now = instance.retention_time.governance_now_seconds()?;
    assert_eq!(
        instance.retention_time.status().state(),
        positron_kernel::LifecycleClockState::Certain
    );
    assert!(recovered_now < recorded.updated_at_unix_seconds());
    let mut session = OfflineUpgradeSession::begin_recovered(instance, &configuration, id)?;
    let key = AdministrativeIdempotencyKey::new([87; 16])?;
    assert_eq!(
        session.cancel(key, recorded.revision()),
        Err(UpgradeFailure::SnapshotUnavailable)
    );
    assert_eq!(session.status()?, recorded);
    // Only genuine process-monotonic elapsed time closes the conservative gap.
    let delta = recorded
        .updated_at_unix_seconds()
        .checked_sub(recovered_now)
        .ok_or("clock gap")?;
    elapsed.advance(delta.checked_mul(1_000_000_000).ok_or("elapsed overflow")?)?;
    let cancelled = session.cancel(key, recorded.revision())?;
    assert_eq!(
        cancelled.status(),
        positron_governance::DurableOperationStatus::Cancelled
    );
    assert_eq!(cancelled.operation_id(), id);
    Ok(())
}
