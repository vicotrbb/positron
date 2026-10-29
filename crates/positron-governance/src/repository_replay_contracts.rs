//! Repository-specific replay contracts using the existing real Catalog fixture.
use super::*;
use crate::DurableOperation;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn active_bindings(
    catalog: &Catalog<'_>,
    actor: crate::AuthorizedContext,
    request: DurableOperationRequest,
    parameters: crate::RepositoryOperationParameters,
    accepted: DurableOperation,
) -> TestResult {
    let generation = catalog.pin()?.number();
    assert_eq!(
        DurableOperationAdministration::accept_repository(catalog, actor, request, parameters)?,
        accepted
    );
    assert_eq!(
        catalog.pin()?.number(),
        generation,
        "exact replay cannot publish another operation"
    );
    let changed_generation = DurableOperationRequest::repository(
        actor.principal_id(),
        request.idempotency_key(),
        request.target_identity().ok_or("target")?,
        request
            .accepted_generation()
            .checked_add(1)
            .ok_or("generation")?,
        19,
        parameters.intent_digest(),
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_repository(
            catalog,
            actor,
            changed_generation,
            parameters
        ),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    let changed_principal = DurableOperationRequest::repository(
        PrincipalId::from_bytes([0x91; 16])?,
        request.idempotency_key(),
        request.target_identity().ok_or("target")?,
        request.accepted_generation(),
        19,
        parameters.intent_digest(),
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_repository(
            catalog,
            actor,
            changed_principal,
            parameters
        ),
        Err(DurableOperationFailure::Unauthorized)
    );
    assert_eq!(
        catalog.pin()?.number(),
        generation,
        "refusals cannot publish another operation"
    );
    assert_eq!(
        DurableOperationAdministration::inspect_by_idempotency(catalog, request.idempotency_key())?,
        Some(accepted)
    );
    Ok(())
}

pub(super) fn wrong_kind(
    catalog: &Catalog<'_>,
    actor: crate::AuthorizedContext,
    parameters: crate::RepositoryOperationParameters,
    instance: [u8; 16],
) -> TestResult {
    let key = AdministrativeIdempotencyKey::new([0x92; 16])?;
    let basis = catalog.pin()?.number();
    let format_request = DurableOperationRequest::catalog_format_migration(
        actor.principal_id(),
        key,
        instance,
        basis,
        24,
    )?;
    let format = DurableOperationAdministration::accept_catalog_format_migration(
        catalog,
        actor,
        format_request,
    )?;
    let generation = catalog.pin()?.number();
    let repository = DurableOperationRequest::repository(
        actor.principal_id(),
        key,
        instance,
        basis,
        24,
        parameters.intent_digest(),
    )?;
    assert_eq!(
        DurableOperationAdministration::accept_repository(catalog, actor, repository, parameters),
        Err(DurableOperationFailure::IdempotencyConflict)
    );
    assert_eq!(catalog.pin()?.number(), generation);
    assert_eq!(
        DurableOperationAdministration::inspect_by_idempotency(catalog, key)?,
        Some(format)
    );
    Ok(())
}

pub(super) fn prepared_and_expired(
    authority: &positron_kernel::StorageKernelResourceAuthority,
    keys: &BootstrapKeyCustody,
    instance: positron_kernel::InstanceId,
    actor: crate::AuthorizedContext,
    parameters: crate::RepositoryOperationParameters,
    completed_request: DurableOperationRequest,
    completed: DurableOperation,
) -> TestResult {
    let catalog = Catalog::open(authority, instance, keys.catalog_secret(instance)?)?;
    let before = catalog.pin()?.number();
    let key = AdministrativeIdempotencyKey::new([0x93; 16])?;
    let request = DurableOperationRequest::repository(
        actor.principal_id(),
        key,
        instance.to_bytes(),
        before,
        25,
        parameters.intent_digest(),
    )?;
    let failed = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        0,
        || DurableOperationAdministration::accept_repository(&catalog, actor, request, parameters),
    );
    assert_eq!(failed, Err(DurableOperationFailure::PersistenceUnavailable));
    assert_eq!(catalog.pin()?.number(), before);
    drop(catalog);
    let catalog = Catalog::open(authority, instance, keys.catalog_secret(instance)?)?;
    let resumed =
        DurableOperationAdministration::accept_repository(&catalog, actor, request, parameters)?;
    assert_eq!(resumed.operation_id(), request.operation_id());
    assert_eq!(
        catalog.pin()?.number(),
        before + 1,
        "prepared recovery publishes exactly one successor"
    );
    assert_eq!(
        DurableOperationAdministration::accept_repository(&catalog, actor, request, parameters)?,
        resumed
    );
    assert_eq!(catalog.pin()?.number(), before + 1);

    let expiry = completed
        .earliest_lookup_expiry_unix_seconds()
        .ok_or("completed expiry")?;
    let next_key = AdministrativeIdempotencyKey::new([0x94; 16])?;
    let next = DurableOperationRequest::repository(
        actor.principal_id(),
        next_key,
        instance.to_bytes(),
        catalog.pin()?.number(),
        expiry,
        parameters.intent_digest(),
    )?;
    DurableOperationAdministration::accept_repository(&catalog, actor, next, parameters)?;
    assert!(
        DurableOperationAdministration::inspect_by_idempotency(
            &catalog,
            completed_request.idempotency_key()
        )?
        .is_none()
    );
    let generation = catalog.pin()?.number();
    assert_eq!(
        DurableOperationAdministration::accept_repository(
            &catalog,
            actor,
            completed_request,
            parameters
        ),
        Err(DurableOperationFailure::CompletedLookupExpired)
    );
    assert_eq!(
        catalog.pin()?.number(),
        generation,
        "expired binding cannot admit replacement intent"
    );
    Ok(())
}
