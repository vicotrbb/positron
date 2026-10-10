use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_governance::{GovernanceAuditEntry, Identity};
use positron_kernel::{
    ActiveSegmentLedger, BootstrapArtifact, BootstrapArtifactAccess, BootstrapKeyCustody,
    BootstrapObjectPurpose, Catalog, LedgerFailureCode, RetentionTimeAuthority, SegmentScope,
    StorageKernelResourceAuthority,
};
use std::sync::Arc;

use super::super::codec::{BootstrapRecord, encode_claim, encode_legacy_claim};
use super::super::storage;
use super::super::{BootstrapFailure, BootstrapFailureCode, InitializedInstance};
use super::support::{catalog_failure, key_failure};

pub(super) fn open_initial_ledgers(
    authority: &StorageKernelResourceAuthority,
    retention_time: &RetentionTimeAuthority,
    catalog: &Catalog<'_>,
    key: &BootstrapKeyCustody,
    record: &BootstrapRecord,
) -> Result<(), BootstrapFailure> {
    recover_ledgers(
        authority,
        retention_time,
        catalog,
        key,
        record.instance,
        record.tenant,
    )
}

pub(crate) fn recover_initial_ledgers(
    instance: &InitializedInstance,
) -> Result<(), BootstrapFailure> {
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(key_failure)?,
    )
    .map_err(catalog_failure)?;
    // A prepared administrative transaction keeps the prior Catalog generation
    // authoritative until its owner resolves it. Reopening active ledgers can
    // publish a successor, so preserve the established startup behavior here.
    if catalog
        .has_prepared_transaction()
        .map_err(catalog_failure)?
    {
        return Ok(());
    }
    recover_ledgers(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        &instance.key,
        instance.instance,
        instance.tenant,
    )?;
    let generation = catalog.pin().map_err(catalog_failure)?.number();
    instance.record_catalog_generation(generation);
    Ok(())
}

fn recover_ledgers(
    authority: &StorageKernelResourceAuthority,
    retention_time: &RetentionTimeAuthority,
    catalog: &Catalog<'_>,
    key: &BootstrapKeyCustody,
    instance: positron_kernel::InstanceId,
    tenant: TenantId,
) -> Result<(), BootstrapFailure> {
    let shard = VirtualShardId::new(1)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let snapshot = catalog.pin().map_err(catalog_failure)?;
    let identity = Identity::open(&snapshot)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let envelope = identity
        .tenant_key_envelope(tenant)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let session = positron_kernel::RootRewrapSession::admit(authority).map_err(key_failure)?;
    let rotation_pending = key
        .pending_tenant_key_epoch(instance, tenant, envelope)
        .map_err(key_failure)?
        .is_some();
    for signal in [SignalKind::Logs, SignalKind::Traces] {
        let scope = SegmentScope::new(tenant, signal, shard);
        // Sealed metadata is the durable rotation checkpoint. Reopening must
        // not recreate a predecessor active segment after a completed roll.
        if rotation_pending
            && !snapshot
                .has_active_ledger_scope(scope)
                .map_err(|failure| ledger_open_failure(failure.code()))?
        {
            continue;
        }
        let protection = session
            .tenant_segment_key(key, instance, scope, envelope)
            .map_err(|failure| match failure {
                positron_kernel::BootstrapKeyFailure::Authentication => {
                    BootstrapFailure::new(BootstrapFailureCode::KeyEnvelopeMismatch)
                },
                failure => key_failure(failure),
            })?;
        let ledger = if rotation_pending {
            ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                authority,
                retention_time,
                catalog,
                scope,
                protection,
            )
        } else {
            ActiveSegmentLedger::open_with_retention_time(
                authority,
                retention_time,
                catalog,
                scope,
                protection,
            )
        }
        .map_err(|failure| ledger_open_failure(failure.code()))?;
        drop(ledger);
    }
    Ok(())
}

const fn ledger_open_failure(code: LedgerFailureCode) -> BootstrapFailure {
    let bootstrap = match code {
        LedgerFailureCode::DurabilityFrontierAmbiguity => {
            BootstrapFailureCode::DurabilityFrontierAmbiguity
        },
        LedgerFailureCode::IntegrityCorruption
        | LedgerFailureCode::Quarantined
        | LedgerFailureCode::AuthenticationFailed
        | LedgerFailureCode::UnsupportedFormat
        | LedgerFailureCode::InvalidInput
        | LedgerFailureCode::PhysicalScopeMismatch
        | LedgerFailureCode::RecoveryRequired
        | LedgerFailureCode::StaleResumeMarker => BootstrapFailureCode::CorruptState,
        LedgerFailureCode::StorageUnavailable => BootstrapFailureCode::LedgerUnavailable,
        LedgerFailureCode::ResourceAdmissionRefused
        | LedgerFailureCode::LimitExceeded
        | LedgerFailureCode::StorageExhausted
        | LedgerFailureCode::Cancelled => BootstrapFailureCode::ResourceUnavailable,
        LedgerFailureCode::StaleGeneration
        | LedgerFailureCode::ConcurrentWriter
        | LedgerFailureCode::IdempotencyConflict
        | LedgerFailureCode::SnapshotExpired
        | LedgerFailureCode::ClockUncertain => BootstrapFailureCode::CatalogUnavailable,
    };
    BootstrapFailure::new(bootstrap)
}

pub(super) fn ensure_claim(
    access: &BootstrapArtifactAccess,
    key: &BootstrapKeyCustody,
    record: &BootstrapRecord,
    secret: &[u8; 32],
) -> Result<(), BootstrapFailure> {
    let plaintext = match &record.ingest {
        Some(ingest) => encode_claim(
            record.instance,
            record.administrator,
            secret,
            ingest.principal,
            ingest
                .api_key_secret
                .as_ref()
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
            record
                .query
                .as_ref()
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?
                .principal,
            record
                .query
                .as_ref()
                .and_then(|query| query.api_key_secret.as_ref())
                .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
        ),
        None => encode_legacy_claim(record.instance, record.administrator, secret),
    };
    let encrypted = key
        .protect(record.instance, BootstrapObjectPurpose::Claim, &plaintext)
        .map_err(key_failure)?;
    if storage::exists(access, BootstrapArtifact::Claim)? {
        let existing = storage::read(access, BootstrapArtifact::Claim)?;
        let opened = key
            .open_object(record.instance, BootstrapObjectPurpose::Claim, &existing)
            .map_err(key_failure)?;
        if opened != plaintext {
            return Err(BootstrapFailure::new(
                BootstrapFailureCode::IdentityMismatch,
            ));
        }
        Ok(())
    } else {
        storage::write_new(access, BootstrapArtifact::Claim, &encrypted)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "bootstrap handoff transfers each established authority exactly once"
)]
pub(super) fn outcome(
    bootstrap_storage: positron_kernel::InstanceBootstrapStorage,
    record: &BootstrapRecord,
    key: BootstrapKeyCustody,
    key_cache_lease: positron_kernel::key_provider::KeyCacheLease,
    identity: Identity,
    audit: Vec<GovernanceAuditEntry>,
    authority: StorageKernelResourceAuthority,
    maintenance: positron_kernel::MaintenanceCoordinator,
    retention_time: RetentionTimeAuthority,
    generation: u64,
    audit_frontier: u64,
    claim_available: bool,
    registered_tenants: Vec<TenantId>,
    max_registered_tenants: u16,
) -> Result<InitializedInstance, BootstrapFailure> {
    let key = super::super::local_rotation::reopen_active_route(
        &authority,
        &bootstrap_storage,
        record.instance,
        key,
    )
    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::KeyEnvelopeMismatch))?;
    let key_session = positron_kernel::RootRewrapSession::admit(&authority).map_err(key_failure)?;
    let key = key_session
        .lease_system(key, record.instance, key_cache_lease)
        .map_err(key_failure)?;
    drop(key_session);
    let logs_shard = VirtualShardId::new(1)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let admission_group_planner =
        Arc::new(positron_ingest::FixedAdmissionGroupPlanner::new(logs_shard));
    #[cfg(not(any(test, fuzzing)))]
    let _ = (identity, audit);
    Ok(InitializedInstance {
        bootstrap_storage,
        key,
        #[cfg(any(test, fuzzing))]
        identity,
        #[cfg(any(test, fuzzing))]
        audit,
        _authority: authority,
        maintenance,
        governance_audit_checkpoint_gate: std::sync::Mutex::new(()),
        retention_time,
        instance: record.instance,
        tenant: record.tenant,
        logs_shard,
        value_limit_profile: positron_domain::value::ValueLimitProfile::release_1_system_maximum(),
        admission_group_planner,
        tenant_drains: super::super::types::TenantDrainRegistry::establish(
            &registered_tenants,
            max_registered_tenants,
        )?,
        #[cfg(test)]
        lifecycle_preflight_hook: std::sync::Mutex::new(None),
        #[cfg(test)]
        catalog_migration_preflight_hook: std::sync::Mutex::new(None),
        tenant_slug: BootstrapRecord::tenant_slug()?,
        administrator: record.administrator,
        integrity_key_fingerprint: record.integrity_fingerprint,
        catalog_generation: std::sync::atomic::AtomicU64::new(generation),
        governance_audit_frontier: audit_frontier,
        claim_available,
    })
}

pub(in crate::instance_bootstrap) fn governance_audit_records(
    catalog: &Catalog<'_>,
) -> Result<Vec<GovernanceAuditEntry>, BootstrapFailure> {
    catalog
        .governance_audit_records()
        .map_err(catalog_failure)?
        .iter()
        .map(|record| {
            GovernanceAuditEntry::decode(record)
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))
        })
        .collect()
}
