//! Provider-aware startup transfers the admitted system bootstrap authority.
use super::*;
use positron_kernel::key_provider::NativeRootConfiguration;

pub(in crate::instance_bootstrap) fn reopen(
    paths: &BootstrapPaths,
    configuration: NativeRootConfiguration,
    max_registered_tenants: u16,
) -> Result<InitializedInstance, BootstrapFailure> {
    let (volume, access) = acquire(paths)?;
    let layout = access.layout().map_err(storage::storage_failure)?;
    use positron_kernel::BootstrapEntry;
    if layout.unknown_or_unsafe()
        || ![
            BootstrapEntry::Initialized,
            BootstrapEntry::Catalog,
            BootstrapEntry::Segments,
            BootstrapEntry::SystemKeyEnvelope,
        ]
        .into_iter()
        .all(|entry| layout.contains(entry))
        || [
            BootstrapEntry::Pending,
            BootstrapEntry::PendingReplacement,
            BootstrapEntry::InitializedStaging,
        ]
        .into_iter()
        .any(|entry| layout.contains(entry))
    {
        return Err(inconsistent());
    }
    let mut authority = resources::establish_system_diagnostics(volume, max_registered_tenants)?;
    let session =
        positron_kernel::RootRewrapSession::admit_provider(&authority).map_err(key_failure)?;
    let key = session
        .open_provider_recovery(&access, configuration, paths.key_cache_lease)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyEnvelopeMismatch))?;
    let encoded = storage::read(&access, BootstrapArtifact::Initialized)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)?;
    require_key_identity(&record, key.bootstrap_identity())?;
    drop(session);
    resources::activate_authenticated_bootstrap(
        &mut authority,
        record.tenant,
        max_registered_tenants,
    )?;
    super::reopen_authenticated(
        paths.storage.clone(),
        paths.key_cache_lease,
        max_registered_tenants,
        access,
        key,
        record,
        authority,
        false,
    )
}
