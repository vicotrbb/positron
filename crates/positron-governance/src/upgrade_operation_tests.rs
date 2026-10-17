use super::*;
use crate::*;
#[path = "upgrade_fixture.rs"]
mod fixture_support;
use fixture_support::*;
#[path = "upgrade_snapshot_fixture.rs"]
mod snapshot_support;
use snapshot_support::{verification_report, verified_snapshot};
#[path = "upgrade_failure_tests.rs"]
mod failure_tests;

#[test]
fn upgrade_intent_reopens_exactly_and_cannot_skip_drain_evidence() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let Fixture {
        authority,
        keys,
        instance,
        actor,
        parameters,
        ..
    } = &fixture;
    let catalog = Catalog::open(authority, *instance, keys.catalog_secret(*instance)?)?;
    let (instance, actor, parameters) = (*instance, *actor, *parameters);
    let request = DurableOperationRequest::upgrade(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([11; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        18,
        parameters.intent_digest(),
    )?;
    let wrong_epoch = UpgradeParameters::new(
        parameters.source(),
        parameters.target(),
        2,
        parameters.configuration_digest(),
        parameters.backup(),
    )?;
    let wrong_request = DurableOperationRequest::upgrade(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([90; 16])?,
        instance.to_bytes(),
        catalog.pin()?.number(),
        18,
        wrong_epoch.intent_digest(),
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_upgrade(
            &catalog,
            actor,
            wrong_request,
            wrong_epoch,
            fixture.registration_row
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    let wrong_instance = DurableOperationRequest::upgrade(
        actor.principal_id(),
        AdministrativeIdempotencyKey::new([92; 16])?,
        [93; 16],
        catalog.pin()?.number(),
        18,
        parameters.intent_digest(),
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_upgrade(
            &catalog,
            actor,
            wrong_instance,
            parameters,
            fixture.registration_row
        ),
        Err(DurableOperationFailure::InvalidInput)
    );
    let accepted = DurableOperationAdministration::accept_upgrade(
        &catalog,
        actor,
        request,
        parameters,
        fixture.registration_row,
    )?;
    assert_eq!(accepted.upgrade_parameters(), Some(parameters));
    assert_eq!(
        DurableOperationAdministration::accept_upgrade(
            &catalog,
            actor,
            request,
            parameters,
            fixture.registration_row
        )?,
        accepted
    );
    let changed = UpgradeParameters::new(
        parameters.source(),
        parameters.target(),
        parameters.format_epoch(),
        [91; 32],
        parameters.backup(),
    )?;
    let changed_request = DurableOperationRequest::upgrade(
        actor.principal_id(),
        request.idempotency_key(),
        instance.to_bytes(),
        request.accepted_generation(),
        19,
        changed.intent_digest(),
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_upgrade(
            &catalog,
            actor,
            changed_request,
            changed,
            fixture.registration_row
        ),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    assert_eq!(
        DurableOperationAdministration::next_upgrade_operation(&catalog, None)?,
        Some(accepted)
    );
    assert_eq!(
        DurableOperationAdministration::resume_upgrade_actor(
            &catalog,
            accepted.operation_id(),
            19
        )?
        .principal_id(),
        actor.principal_id()
    );
    let id = accepted.operation_id();
    let running = DurableOperationAdministration::begin(&catalog, actor, id, 19)?;
    assert_eq!(running.upgrade_stage(), Some(UpgradeStage::Preflight));
    assert_eq!(
        DurableOperationAdministration::advance_upgrade(
            &catalog,
            actor,
            id,
            UpgradeStage::Publishing,
            20
        ),
        Err(DurableOperationFailure::InvalidState)
    );
    let draining = DurableOperationAdministration::advance_upgrade(
        &catalog,
        actor,
        id,
        UpgradeStage::Draining,
        20,
    )?;
    drop(catalog);
    let catalog = Catalog::open(authority, instance, keys.catalog_secret(instance)?)?;
    assert_eq!(
        DurableOperationAdministration::inspect(&catalog, id)?,
        Some(draining)
    );
    assert_eq!(
        DurableOperationAdministration::advance_upgrade(
            &catalog,
            actor,
            id,
            UpgradeStage::Snapshot,
            21
        ),
        Err(DurableOperationFailure::InvalidState)
    );
    let cancelled = DurableOperationAdministration::cancel_upgrade(
        &catalog,
        actor,
        id,
        AdministrativeIdempotencyKey::new([12; 16])?,
        draining.revision(),
        21,
    )?;
    assert_eq!(cancelled.status(), DurableOperationStatus::Cancelled);
    Ok(())
}

#[path = "upgrade_registration_tests.rs"]
mod registration_tests;

#[path = "upgrade_publication_tests.rs"]
mod publication_tests;
