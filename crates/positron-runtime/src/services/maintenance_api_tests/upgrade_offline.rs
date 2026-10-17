//! Offline Upgrade must authenticate actual completed Drain before services exist.
use super::*;
use crate::upgrade::{OfflineUpgradeSession, UpgradeFailure};
use positron_governance::{
    AdministrativeIdempotencyKey, BackupSnapshotParameters, DurableOperationAdministration,
    DurableOperationRequest, UpgradeParameters, UpgradeReleaseIdentity, UpgradeStage,
};

#[test]
fn offline_upgrade_refuses_intent_without_a_completed_drain_marker()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = accept(&instance, &services, &administrator, &configuration)?;
    drop(services);
    drop(instance);
    assert!(matches!(
        OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id),
        Err(UpgradeFailure::DrainIncomplete)
    ));
    let cancelled = OfflineUpgradeSession::cancel_intent(
        &fixture.paths()?,
        &configuration,
        id,
        AdministrativeIdempotencyKey::new([81; 16])?,
        3,
    )?;
    assert_eq!(
        cancelled.status(),
        positron_governance::DurableOperationStatus::Cancelled
    );
    let reopened = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    assert!(reopened.graceful_shutdown_record()?.is_none());

    Ok(())
}

#[test]
fn offline_upgrade_authenticates_final_marker_and_recovers_without_serving()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = accept(&instance, &services, &administrator, &configuration)?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "final Drain publication")?;
    drop(services);
    drop(instance);
    let inspected = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let record = inspected.graceful_shutdown_record()?.ok_or("record")?;
    let marker = record.marker_identity();
    let transaction = record.transaction();
    drop(inspected);
    let mut session = OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    let status = session.status()?;
    assert!(session.publish_installed(&configuration).is_err());
    assert_eq!(session.status()?, status);
    assert_eq!(status.upgrade_stage(), Some(UpgradeStage::Snapshot));
    let evidence = status.upgrade_drain_evidence().ok_or("drain evidence")?;
    assert_eq!(evidence.marker_identity(), marker);
    assert_eq!(evidence.transaction(), transaction);
    assert_eq!(session.advance(std::time::Instant::now())?, status);
    assert!(session.rollback_snapshot()?.is_none());
    drop(session);
    let mut session = OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    let status = session.status()?;
    assert_eq!(status.upgrade_stage(), Some(UpgradeStage::Snapshot));
    assert_eq!(status.upgrade_drain_evidence(), Some(evidence));
    let cancelled = session.cancel(
        AdministrativeIdempotencyKey::new([80; 16])?,
        status.revision(),
    )?;
    assert_eq!(
        cancelled.status(),
        positron_governance::DurableOperationStatus::Cancelled
    );
    drop(session);
    drop(crate::InstanceBootstrap::reopen_configured(
        &fixture.paths()?,
        &configuration,
    )?);
    Ok(())
}
#[test]
fn offline_upgrade_refuses_an_older_marker_and_post_drain_data()
-> Result<(), Box<dyn std::error::Error>> {
    for write_after_drain in [false, true] {
        let fixture = Fixture::new()?;
        let configuration = configuration(&fixture)?;
        let (instance, ingest, _, administrator) = fixture.initialized_with_admin()?;
        let services = ServiceHandle::new(Arc::clone(&instance))?;
        let id = if write_after_drain {
            let id = accept(&instance, &services, &administrator, &configuration)?;
            instance
                .publish_graceful_shutdown(&mut || false)
                .map_err(|_| "Drain")?;
            drop(services);
            drop(instance);
            let instance = Arc::new(crate::InstanceBootstrap::reopen_configured(
                &fixture.paths()?,
                &configuration,
            )?);
            let services = ServiceHandle::new(instance)?;
            services.ingest_otlp_logs(&ingest, request("after final marker").encode_to_vec())?;
            drop(services);
            id
        } else {
            instance
                .publish_graceful_shutdown(&mut || false)
                .map_err(|_| "old Drain")?;
            drop(services);
            drop(instance);
            let instance = Arc::new(crate::InstanceBootstrap::reopen_configured(
                &fixture.paths()?,
                &configuration,
            )?);
            let services = ServiceHandle::new(Arc::clone(&instance))?;
            let id = accept(&instance, &services, &administrator, &configuration)?;
            drop(services);
            drop(instance);
            id
        };
        assert!(matches!(
            OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id),
            Err(UpgradeFailure::DrainIncomplete)
        ));
    }
    Ok(())
}

#[test]
fn offline_upgrade_refuses_a_preclaimed_child_key_before_provider_work()
-> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = accept(&instance, &services, &administrator, &configuration)?;
    let foreign = {
        let catalog = open_catalog(&instance)?;
        let parent = DurableOperationAdministration::inspect(&catalog, id)?.ok_or("upgrade")?;
        let expected = parent.upgrade_parameters().ok_or("parameters")?.backup();
        let changed = BackupSnapshotParameters::new(
            expected.repository(),
            7200,
            expected.registration_identity(),
        )?;
        let mut hash = Sha256::new();
        hash.update(b"positron.upgrade.child.v1\0");
        hash.update(id.to_bytes());
        hash.update(b"snapshot");
        let digest = hash.finalize();
        let key =
            AdministrativeIdempotencyKey::new(digest.get(..16).ok_or("child key")?.try_into()?)?;
        let actor = services
            .authorize_system_administration(&administrator)
            .map_err(|error| format!("actor: {error:?}"))?;
        let request = DurableOperationRequest::backup_snapshot(
            actor.principal_id(),
            key,
            instance.instance.to_bytes(),
            catalog.pin()?.number(),
            parent.updated_at_unix_seconds(),
            changed.intent_digest(),
        )?;
        DurableOperationAdministration::accept_backup(
            &catalog,
            actor,
            request,
            changed,
            changed.registration_identity(),
            positron_kernel::CatalogObject::new(b"offline upgrade admission fixture".to_vec())?,
        )?
    };
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "Drain")?;
    drop(services);
    drop(instance);
    let mut session = OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    assert_eq!(
        session.advance(std::time::Instant::now() + Duration::from_secs(5)),
        Err(UpgradeFailure::InvalidRequest)
    );
    drop(session);
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    assert_eq!(
        DurableOperationAdministration::inspect(&open_catalog(&instance)?, foreign.operation_id())?,
        Some(foreign)
    );
    Ok(())
}

#[test]
fn offline_upgrade_retains_exact_drain_when_trusted_time_is_behind()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let accepted_at = instance
        .retention_time
        .governance_now_seconds()?
        .checked_add(3600)
        .ok_or("future fixture time")?;
    let id = accept_at(
        &instance,
        &services,
        &administrator,
        &configuration,
        accepted_at,
    )?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "Drain")?;
    drop(services);
    drop(instance);
    let inspected = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let before = open_catalog(&inspected)?.pin()?.identity();
    drop(inspected);
    assert!(matches!(
        OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id),
        Err(UpgradeFailure::SnapshotUnavailable)
    ));
    let inspected = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
    let catalog = open_catalog(&inspected)?;
    assert_eq!(catalog.pin()?.identity(), before);
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?
            .ok_or("operation")?
            .upgrade_stage(),
        Some(UpgradeStage::Draining)
    );
    Ok(())
}

#[test]
fn offline_upgrade_cold_cancel_reports_retryable_trusted_time_without_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let configuration = configuration(&fixture)?;
    let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let id = accept(&instance, &services, &administrator, &configuration)?;
    let actor = services
        .authorize_system_administration(&administrator)
        .map_err(|error| format!("actor: {error:?}"))?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "Drain")?;
    drop(services);
    drop(instance);
    let instance = crate::InstanceBootstrap::reopen_configured(&fixture.paths()?, &configuration)?;
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
    let before = catalog.pin()?.identity();
    drop(catalog);
    drop(instance);
    let mut session = OfflineUpgradeSession::begin(&fixture.paths()?, &configuration, id)?;
    let operation = session.status()?;
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
    assert_eq!(open_catalog(&instance)?.pin()?.identity(), before);
    Ok(())
}

pub(super) fn configuration(
    fixture: &Fixture,
) -> Result<positron_config::EffectiveConfiguration, Box<dyn std::error::Error>> {
    let path = fixture.migration_configuration()?;
    let root = path.parent().ok_or("configuration root")?;
    fs::write(
        &path,
        format!(
            "schema_version = 1\n[storage]\ndata_directory = {:?}\nsecrets_directory = {:?}\n",
            root.join("data"),
            root.join("secrets")
        ),
    )?;
    Ok(positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&path),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|failure| format!("configuration: {failure:?}"))?,
    )?)
}
pub(super) fn accept(
    instance: &crate::InitializedInstance,
    services: &ServiceHandle,
    administrator: &str,
    configuration: &positron_config::EffectiveConfiguration,
) -> Result<positron_governance::OperationId, Box<dyn std::error::Error>> {
    // Model an intent which has already waited before Drain. Cold recovery is
    // conservatively behind the current clock; a fresh intent is tested below.
    accept_at(
        instance,
        services,
        administrator,
        configuration,
        instance
            .retention_time
            .governance_now_seconds()?
            .checked_sub(16)
            .ok_or("fixture accepted time")?,
    )
}
fn accept_at(
    instance: &crate::InitializedInstance,
    services: &ServiceHandle,
    administrator: &str,
    configuration: &positron_config::EffectiveConfiguration,
    now: u64,
) -> Result<positron_governance::OperationId, Box<dyn std::error::Error>> {
    let actor = services
        .authorize_system_administration(administrator)
        .map_err(|error| format!("actor: {error:?}"))?;
    let catalog = open_catalog(instance)?;
    let basis = catalog.pin()?;
    let registration =
        positron_kernel::CatalogObject::new(b"offline upgrade admission fixture".to_vec())?;
    let registration_address = registration.identity();
    let registration_id = registration_address.to_bytes();
    let mut objects = Vec::new();
    for id in basis.object_identities() {
        objects.push(positron_kernel::CatalogObject::new(
            basis.object(id)?.ok_or("object")?.to_vec(),
        )?);
    }
    objects.push(registration);
    catalog.commit(
        basis.identity(),
        positron_kernel::CatalogProposal::new(
            positron_kernel::TransactionId::new([71; 16])?,
            basis.format_epoch().ok_or("epoch")?,
            objects,
        )?,
        None,
    )?;
    let repository = positron_governance::RepositoryOperationParameters::local(
        positron_governance::RepositoryAction::Verify,
        "/backup",
        [72; 16],
        [73; 32],
        [74; 32],
    )?;
    let parameters = UpgradeParameters::new(
        UpgradeReleaseIdentity::new([75; 32], [76; 32], [0, 0, 0])?,
        UpgradeReleaseIdentity::new([77; 32], [78; 32], [0, 0, 1])?,
        catalog.pin()?.format_epoch().ok_or("epoch")?.value(),
        configuration.audit_binding_digest(),
        BackupSnapshotParameters::new(repository, 3600, registration_id)?,
    )?;
    let request = DurableOperationRequest::upgrade(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([79; 16])?,
        instance.instance.to_bytes(),
        catalog.pin()?.number(),
        now,
        parameters.intent_digest(),
    )?;
    let operation = DurableOperationAdministration::accept_upgrade(
        &catalog,
        actor,
        request,
        parameters,
        registration_address,
    )?;
    let id = operation.operation_id();
    DurableOperationAdministration::begin(&catalog, actor, id, now)?;
    DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Draining,
        now,
    )?;
    Ok(id)
}
