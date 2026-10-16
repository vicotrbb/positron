//! Fresh restoration adopts its recovered route in a real target transaction.
use super::*;
use positron_kernel::{BootstrapKeyCustody, InstanceId, StorageKernelResourceAuthority};

pub(crate) fn adopt_restored_route(
    authority: &StorageKernelResourceAuthority,
    catalog: &Catalog<'_>,
    custody: &BootstrapKeyCustody,
    instance: InstanceId,
    operation: positron_governance::DurableOperation,
) -> Result<(), LocalKeyRotationFailure> {
    let parameters = operation
        .backup_restore_parameters()
        .ok_or(LocalKeyRotationFailure::Authentication)?;
    if catalog
        .restore_origin_intent()
        .map_err(|_| LocalKeyRotationFailure::Storage)?
        != Some(parameters.intent_digest())
    {
        return Err(LocalKeyRotationFailure::Authentication);
    }
    let snapshot = catalog
        .pin()
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
    let previous = State::find(&snapshot)?;
    let provider = custody
        .active_provider_identity()
        .map_err(|_| LocalKeyRotationFailure::Custody)?;
    let native = provider.family() != positron_kernel::key_provider::ProviderFamily::LocalFile;
    if previous.is_none()
        && !native
        && custody
            .active_root_epoch()
            .map_err(|_| LocalKeyRotationFailure::Custody)?
            == 1
    {
        return Ok(());
    }
    let mut hash = Sha256::new();
    hash.update(b"positron.fresh-restore.root-adoption.v1\0");
    hash.update(parameters.intent_digest());
    let transaction = TransactionId::new(
        hash.finalize()
            .get(..16)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(LocalKeyRotationFailure::Storage)?,
    )
    .map_err(|_| LocalKeyRotationFailure::Storage)?;
    let session = RootRewrapSession::admit_provider(authority)
        .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
    let epoch = custody
        .active_root_epoch()
        .map_err(|_| LocalKeyRotationFailure::Custody)?;
    let envelope = if native {
        session.active_system_envelope(custody, instance)
    } else {
        session.wrap_system(custody, custody, instance, epoch)
    }
    .map_err(|_| LocalKeyRotationFailure::Authentication)?;
    let state = State {
        instance,
        transaction,
        anchor: custody.bootstrap_identity(),
        active: Route {
            epoch,
            identity: custody
                .active_root_identity()
                .map_err(|_| LocalKeyRotationFailure::Custody)?,
            envelope,
        },
        successor: None,
        predecessor: None,
        retiring: false,
        cancelled: false,
        provider_format: native,
        migration_source: if native { Some(provider) } else { None },
    };
    if previous.as_ref() == Some(&state) {
        return cutover::confirm_state(catalog, &state);
    }
    if operation.status().is_terminal() {
        return Err(LocalKeyRotationFailure::Authentication);
    }
    let _copy = catalog
        .reserve_catalog_proposal_copy(&snapshot)
        .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(snapshot.object_count().saturating_add(1))
        .map_err(|_| LocalKeyRotationFailure::LimitExceeded)?;
    for id in snapshot.object_identities() {
        let bytes = snapshot
            .object(id)
            .map_err(|_| LocalKeyRotationFailure::Storage)?
            .ok_or(LocalKeyRotationFailure::Authentication)?;
        if !state::is_state(bytes) {
            objects.push(
                CatalogObject::new(bytes.to_vec()).map_err(|_| LocalKeyRotationFailure::Storage)?,
            );
        }
    }
    objects
        .push(CatalogObject::new(state.encode()?).map_err(|_| LocalKeyRotationFailure::Storage)?);
    let intent = positron_governance::catalog_root_migration_audit_intent(
        CatalogRootRotationStage::Restored,
        state.active.identity.key_id(),
        epoch,
        operation.request().principal(),
        operation.operation_id(),
    )
    .map_err(|_| LocalKeyRotationFailure::Authentication)?;
    let proposal = CatalogProposal::new(
        transaction,
        snapshot
            .format_epoch()
            .ok_or(LocalKeyRotationFailure::Authentication)?,
        objects,
    )
    .map_err(|_| LocalKeyRotationFailure::Storage)?;
    catalog
        .commit(snapshot.identity(), proposal, Some(intent))
        .map_err(|_| LocalKeyRotationFailure::Storage)?;
    cutover::confirm_state(catalog, &state)
}
