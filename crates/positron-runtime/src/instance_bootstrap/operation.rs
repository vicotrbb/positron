use positron_domain::identity::{PrincipalId, TenantId};
use positron_governance::Identity;
use positron_governance::{
    InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent, TenantAdministration,
};
use positron_kernel::{
    AuditIntent, BootstrapArtifact, BootstrapArtifactAccess, BootstrapKeyCustody,
    BootstrapObjectPurpose, Catalog, CatalogObject, CatalogProposal, FormatEpoch, InstanceId,
    MaintenanceCoordinator, OwnedPrimaryDataVolume, ResourceAmounts, RetentionTimeAuthority,
    StorageKernelResourceAuthority, TransactionId, WorkClaim,
};
use zeroize::Zeroizing;

use super::codec::{
    BootstrapIngestIdentity, BootstrapQueryIdentity, BootstrapRecord, decode_claim,
};
use super::storage::{self, INTENT};
use super::{
    BootstrapClaim, BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BootstrapState,
    InitializationPlan, InitializedInstance, resources,
};

mod classification;
mod compatibility;
mod completion;
pub(super) mod support;
pub(super) use classification::classify;
pub(super) use completion::governance_audit_records;
pub(crate) use completion::recover_initial_ledgers;
use completion::{ensure_claim, open_initial_ledgers, outcome};
pub(super) use support::decode_record;
use support::{
    acquire, catalog_failure, entropy_failure, format_secret, inconsistent, key_failure,
    recover_pending_replacement, require_key_identity,
};

pub(super) fn initialize(
    paths: &BootstrapPaths,
    plan: InitializationPlan,
    max_registered_tenants: u16,
) -> Result<InitializedInstance, BootstrapFailure> {
    match storage::classify(paths)? {
        BootstrapState::Empty => {
            let (volume, access) = acquire(paths)?;
            storage::write_new(&access, BootstrapArtifact::Pending, INTENT)?;
            return resume(paths, plan, volume, access, max_registered_tenants);
        },
        BootstrapState::Incomplete => {},
        BootstrapState::Initialized => return reopen(paths, max_registered_tenants),
        BootstrapState::Inconsistent => return Err(inconsistent()),
    }
    let (volume, access) = acquire(paths)?;
    resume(paths, plan, volume, access, max_registered_tenants)
}

fn resume(
    paths: &BootstrapPaths,
    plan: InitializationPlan,
    volume: OwnedPrimaryDataVolume,
    access: BootstrapArtifactAccess,
    max_registered_tenants: u16,
) -> Result<InitializedInstance, BootstrapFailure> {
    if storage::exists(&access, BootstrapArtifact::InitializedStaging)?
        && !storage::exists(&access, BootstrapArtifact::Pending)?
    {
        storage::publish_initialized(&access)?;
        drop(volume);
        return reopen(paths, max_registered_tenants);
    }
    let key = if access
        .layout()
        .map_err(storage::storage_failure)?
        .contains(positron_kernel::BootstrapEntry::LocalKey)
    {
        access.open_key().map_err(key_failure)?
    } else {
        access.initialize_key().map_err(key_failure)?
    };
    recover_pending_replacement(&access, &key)?;
    let pending_bytes = storage::read(&access, BootstrapArtifact::Pending)?;
    let mut record = if pending_bytes == INTENT {
        let generated = generate_record(&key)?;
        let protected = key
            .protect(
                generated.instance,
                BootstrapObjectPurpose::Pending,
                &generated.encode(),
            )
            .map_err(key_failure)?;
        storage::replace_pending(&access, &protected)?;
        generated
    } else {
        decode_record(&key, BootstrapObjectPurpose::Pending, &pending_bytes)?
    };
    require_key_identity(&record, key.identity())?;
    let authority = resources::establish(volume, record.tenant, max_registered_tenants)?;
    let catalog = Catalog::open(
        &authority,
        record.instance,
        key.catalog_secret(record.instance).map_err(key_failure)?,
    )
    .map_err(catalog_failure)?;
    let retention_time = RetentionTimeAuthority::establish()
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    compatibility::migrate_pending_v1(&access, &key, &catalog, &mut record)?;
    let api_secret = record
        .api_key_secret
        .as_ref()
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let integrity_secret = record
        .integrity_key_secret
        .as_ref()
        .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let integrity_identity = key
        .integrity_identity(integrity_secret)
        .map_err(key_failure)?;
    let external_alias = plan.external_alias()?;
    if integrity_identity.fingerprint() != record.integrity_fingerprint {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    let protected_integrity = key
        .protect_instance_integrity_key(record.instance, integrity_secret)
        .map_err(key_failure)?;
    let tenant_key_envelope = key
        .provision_tenant_key_envelope(
            record.instance,
            record.tenant,
            key.random_identifier().map_err(key_failure)?,
            1,
        )
        .map_err(key_failure)?;
    let before = catalog.pin().map_err(catalog_failure)?;
    let initial = if before.number() == 0 {
        let ingest = compatibility::require_new_ingest(&record)?;
        let query = compatibility::require_new_query(&record)?;
        let tenant_intent = InitialTenantIntent::new_with_external_tenant_alias(
            record.instance.to_bytes(),
            record.tenant,
            BootstrapRecord::tenant_slug()?,
            external_alias,
            "Default tenant",
            record.administrator,
            record.api_key_salt,
            record.api_key_hash,
            ingest.principal,
            ingest.api_key_salt,
            ingest.api_key_hash,
            query.principal,
            query.api_key_salt,
            query.api_key_hash,
            integrity_identity.public_key(),
            record.integrity_fingerprint,
            protected_integrity,
            tenant_key_envelope,
            2_592_000,
            1,
            1,
            resources::initial_tenant_quota(),
            InitialAuditContext::new(
                key.identity().created_at_unix_seconds(),
                record.transaction.to_bytes(),
                plan.creates_claim(),
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let governance = InitialGovernanceIntent::create_tenant(tenant_intent)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        let (governance_object, audit_intent) = governance.into_parts();
        let default_policy = positron_ingest::IngestPolicy::preserving(1)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?
            .activated_object(record.tenant)
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
        Some(
            catalog
                .commit(
                    before.identity(),
                    CatalogProposal::new(
                        record.transaction,
                        FormatEpoch::CATALOG_V2,
                        vec![
                            CatalogObject::new(governance_object).map_err(catalog_failure)?,
                            TenantAdministration::initial_registry(record.instance, record.tenant)
                                .map_err(|_| {
                                    BootstrapFailure::new(BootstrapFailureCode::CorruptState)
                                })?,
                            CatalogObject::new(default_policy.into_bytes())
                                .map_err(catalog_failure)?,
                        ],
                    )
                    .map_err(catalog_failure)?,
                    Some(AuditIntent::new(audit_intent).map_err(catalog_failure)?),
                )
                .map_err(catalog_failure)?,
        )
    } else {
        None
    };
    open_initial_ledgers(&authority, &retention_time, &catalog, &key, &record)?;
    let current = catalog.pin().map_err(catalog_failure)?;
    apply_catalog_quota(&authority, &current)?;
    let registered_tenants = TenantAdministration::registered_tenant_ids(&current)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    if plan.creates_claim() {
        ensure_claim(&access, &key, &record, api_secret)?;
    }
    let initialized_record = record.initialized();
    let initialized = key
        .protect(
            record.instance,
            BootstrapObjectPurpose::Initialized,
            &initialized_record.encode(),
        )
        .map_err(key_failure)?;
    if !storage::exists(&access, BootstrapArtifact::InitializedStaging)? {
        storage::write_new(&access, BootstrapArtifact::InitializedStaging, &initialized)?;
    }
    storage::remove(&access, BootstrapArtifact::Pending)?;
    storage::publish_initialized(&access)?;
    let generation = current.number();
    let audit = initial
        .as_ref()
        .and_then(|commit| commit.governance_audit_record())
        .map_or(current.governance_audit_frontier(), |audit| {
            audit.position()
        });
    let claim_available = storage::exists(&access, BootstrapArtifact::Claim)?;
    let identity = Identity::open(&current)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let audit_records = governance_audit_records(&catalog)?;
    let maintenance = MaintenanceCoordinator::restore_from_catalog(&catalog)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
    drop(catalog);
    outcome(
        &record,
        key,
        identity,
        audit_records,
        authority,
        maintenance,
        retention_time,
        generation,
        audit,
        claim_available,
        registered_tenants,
        max_registered_tenants,
    )
}

pub(super) fn reopen(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
) -> Result<InitializedInstance, BootstrapFailure> {
    let (volume, access) = acquire(paths)?;
    if storage::classify_with(&access)? != BootstrapState::Initialized {
        return Err(inconsistent());
    }
    let key = access.open_key().map_err(key_failure)?;
    let encoded = storage::read(&access, BootstrapArtifact::Initialized)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)?;
    require_key_identity(&record, key.identity())?;
    let authority = resources::establish(volume, record.tenant, max_registered_tenants)?;
    let catalog = Catalog::open(
        &authority,
        record.instance,
        key.catalog_secret(record.instance).map_err(key_failure)?,
    )
    .map_err(catalog_failure)?;
    let retention_time = RetentionTimeAuthority::establish()
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    if catalog.pin().map_err(catalog_failure)?.number() == 0 {
        return Err(BootstrapFailure::new(BootstrapFailureCode::CorruptState));
    }
    let current = catalog.pin().map_err(catalog_failure)?;
    apply_catalog_quota(&authority, &current)?;
    let registered_tenants = TenantAdministration::registered_tenant_ids(&current)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let generation = current.number();
    let audit = current.governance_audit_frontier();
    let claim_available = storage::exists(&access, BootstrapArtifact::Claim)?;
    let identity = Identity::open(&current)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    let audit_records = governance_audit_records(&catalog)?;
    let maintenance = MaintenanceCoordinator::restore_from_catalog(&catalog)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable))?;
    drop(catalog);
    outcome(
        &record,
        key,
        identity,
        audit_records,
        authority,
        maintenance,
        retention_time,
        generation,
        audit,
        claim_available,
        registered_tenants,
        max_registered_tenants,
    )
}

pub(super) fn claim(paths: &BootstrapPaths) -> Result<BootstrapClaim, BootstrapFailure> {
    let (_volume, access) = acquire(paths)?;
    if storage::classify_with(&access)? != BootstrapState::Initialized
        || !storage::exists(&access, BootstrapArtifact::Claim)?
    {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::ClaimUnavailable,
        ));
    }
    let key = access.open_key().map_err(key_failure)?;
    let initialized = storage::read(&access, BootstrapArtifact::Initialized)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &initialized)?;
    let encrypted_claim = storage::read(&access, BootstrapArtifact::Claim)?;
    let plaintext = key
        .open_object(
            record.instance,
            BootstrapObjectPurpose::Claim,
            &encrypted_claim,
        )
        .map_err(key_failure)?;
    let decoded = decode_claim(record.instance, &plaintext)?;
    let expected_ingest = record.ingest.as_ref().map(|ingest| ingest.principal);
    let expected_query = record.query.as_ref().map(|query| query.principal);
    if decoded.principal != record.administrator
        || decoded.ingest.as_ref().map(|(principal, _)| *principal) != expected_ingest
        || decoded.query.as_ref().map(|(principal, _)| *principal) != expected_query
    {
        return Err(BootstrapFailure::new(
            BootstrapFailureCode::IdentityMismatch,
        ));
    }
    let secret = Zeroizing::new(format_secret(&decoded.secret));
    let principal = decoded.principal;
    let ingest = decoded
        .ingest
        .map(|(principal, secret)| (principal, Zeroizing::new(format_secret(&secret))));
    let query = decoded
        .query
        .map(|(principal, secret)| (principal, Zeroizing::new(format_secret(&secret))));
    storage::remove(&access, BootstrapArtifact::Claim)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ClaimDestructionFailed))?;
    Ok(BootstrapClaim {
        principal,
        secret,
        ingest,
        query,
    })
}

fn apply_catalog_quota(
    authority: &StorageKernelResourceAuthority,
    snapshot: &positron_kernel::CatalogSnapshot,
) -> Result<(), BootstrapFailure> {
    let (_, governance) = snapshot.governance_object().map_err(catalog_failure)?;
    authority
        .update_tenant_quota(
            governance.tenant(),
            u16::try_from(governance.quota_weight())
                .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
            ResourceAmounts::new(governance.quota_resources()),
        )
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    for (tenant, weight, resources) in TenantAdministration::registered_tenant_quotas(snapshot)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?
    {
        authority
            .register_tenant_quota(
                tenant,
                u16::try_from(weight)
                    .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?,
                ResourceAmounts::new(resources),
            )
            .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::CorruptState))?;
    }
    Ok(())
}

fn generate_record(key: &BootstrapKeyCustody) -> Result<BootstrapRecord, BootstrapFailure> {
    let instance = InstanceId::new(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let tenant = TenantId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let administrator = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let transaction = TransactionId::new(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let api_key_salt = key.random_secret().map_err(key_failure)?;
    let api_key_secret = key.random_secret().map_err(key_failure)?;
    let api_key_hash = key
        .salted_secret_hash(api_key_salt.as_ref(), api_key_secret.as_ref())
        .map_err(key_failure)?;
    let ingest_principal = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let ingest_api_key_salt = key.random_secret().map_err(key_failure)?;
    let ingest_api_key_secret = key.random_secret().map_err(key_failure)?;
    let ingest_api_key_hash = key
        .salted_secret_hash(ingest_api_key_salt.as_ref(), ingest_api_key_secret.as_ref())
        .map_err(key_failure)?;
    let query_principal = PrincipalId::from_bytes(key.random_identifier().map_err(key_failure)?)
        .map_err(|_| entropy_failure())?;
    let query_api_key_salt = key.random_secret().map_err(key_failure)?;
    let query_api_key_secret = key.random_secret().map_err(key_failure)?;
    let query_api_key_hash = key
        .salted_secret_hash(query_api_key_salt.as_ref(), query_api_key_secret.as_ref())
        .map_err(key_failure)?;
    let integrity_secret = key.random_secret().map_err(key_failure)?;
    let integrity_fingerprint = key
        .integrity_identity(integrity_secret.as_ref())
        .map_err(key_failure)?
        .fingerprint();
    Ok(BootstrapRecord {
        instance,
        key: key.identity(),
        tenant,
        administrator,
        transaction,
        api_key_salt: *api_key_salt,
        api_key_hash,
        ingest: Some(BootstrapIngestIdentity {
            principal: ingest_principal,
            api_key_salt: *ingest_api_key_salt,
            api_key_hash: ingest_api_key_hash,
            api_key_secret: Some(Zeroizing::new(*ingest_api_key_secret)),
        }),
        query: Some(BootstrapQueryIdentity {
            principal: query_principal,
            api_key_salt: *query_api_key_salt,
            api_key_hash: query_api_key_hash,
            api_key_secret: Some(Zeroizing::new(*query_api_key_secret)),
        }),
        integrity_fingerprint,
        api_key_secret: Some(Zeroizing::new(*api_key_secret)),
        integrity_key_secret: Some(Zeroizing::new(*integrity_secret)),
    })
}

/// Opens only read-only bootstrap and Catalog inspection state for offline
/// verification. It deliberately does not call reopen: reopen may restore
/// active ledgers, whereas verification must neither create nor repair data.
pub(super) fn verify_offline_integrity(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    selected_scope: Option<positron_kernel::SegmentScope>,
    resume: Option<crate::OfflineIntegrityContinuation>,
    claim: positron_kernel::WorkClaim,
    cancellation: &positron_kernel::IntegrityCancellation,
) -> Result<crate::OfflineIntegrityVerification, crate::OfflineIntegrityFailure> {
    use positron_domain::routing::SignalKind;
    use positron_kernel::{
        ActiveSegmentLedger, IntegrityScrubBudget, IntegrityVerificationMode, TransactionId,
    };

    let (volume, access) = paths.storage.acquire().map_err(|failure| match failure {
        positron_kernel::BootstrapStorageFailure::OwnershipLocked => {
            crate::OfflineIntegrityFailure::OwnershipLocked
        },
        _ => crate::OfflineIntegrityFailure::BootstrapUnavailable,
    })?;
    let state = storage::classify_with(&access)
        .map_err(|_| crate::OfflineIntegrityFailure::BootstrapUnavailable)?;
    if state != BootstrapState::Initialized {
        if state == BootstrapState::Inconsistent && access.open_key().is_err() {
            return Err(crate::OfflineIntegrityFailure::KeyUnavailable);
        }
        if state == BootstrapState::Inconsistent {
            return Err(crate::OfflineIntegrityFailure::CorruptState);
        }
        return Err(crate::OfflineIntegrityFailure::BootstrapUnavailable);
    }
    let key = access
        .open_key()
        .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
    let encoded = storage::read(&access, BootstrapArtifact::Initialized)
        .map_err(|_| crate::OfflineIntegrityFailure::BootstrapUnavailable)?;
    let record = decode_record(&key, BootstrapObjectPurpose::Initialized, &encoded)
        .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    require_key_identity(&record, key.identity())
        .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let authority = resources::establish_system_diagnostics(volume, max_registered_tenants)
        .map_err(|_| crate::OfflineIntegrityFailure::StorageUnavailable)?;
    let inspection =
        Catalog::reserve_offline_integrity_inspection(&authority, claim).map_err(|failure| {
            match failure.code() {
                positron_kernel::CatalogFailureCode::ResourceAdmissionRefused
                | positron_kernel::CatalogFailureCode::LimitExceeded => {
                    crate::OfflineIntegrityFailure::CapacityUnavailable
                },
                _ => crate::OfflineIntegrityFailure::StorageUnavailable,
            }
        })?;
    let resource_snapshot = inspection
        .authority()
        .governor()
        .inspect()
        .map_err(|_| crate::OfflineIntegrityFailure::StorageUnavailable)?;
    let snapshot = inspection
        .read_current_snapshot(
            record.instance,
            key.catalog_secret(record.instance)
                .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?,
        )
        .map_err(|failure| match failure.code() {
            positron_kernel::CatalogFailureCode::StorageUnavailable => {
                crate::OfflineIntegrityFailure::StorageUnavailable
            },
            positron_kernel::CatalogFailureCode::ConcurrentWriter => {
                crate::OfflineIntegrityFailure::CatalogUnavailable
            },
            positron_kernel::CatalogFailureCode::LimitExceeded
            | positron_kernel::CatalogFailureCode::ResourceAdmissionRefused => {
                crate::OfflineIntegrityFailure::CapacityUnavailable
            },
            _ => crate::OfflineIntegrityFailure::CorruptState,
        })?;
    if snapshot.number() == 0 {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    let findings = positron_kernel::integrity_quarantine_findings(&snapshot).map_err(
        |failure| match failure.code() {
            positron_kernel::IntegrityFailureCode::FindingCapacity => {
                crate::OfflineIntegrityFailure::CapacityUnavailable
            },
            _ => crate::OfflineIntegrityFailure::CorruptState,
        },
    )?;
    let backup_repository =
        crate::BackupRepositoryInspection::from_authenticated_catalog(&snapshot)
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let identity =
        Identity::open(&snapshot).map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let tenants = TenantAdministration::registered_tenant_ids(&snapshot)
        .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
    let mut verified_envelope_count = 0_usize;
    for tenant in &tenants {
        let envelope = identity
            .tenant_key_envelope(*tenant)
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        // This custody check derives an opaque key from each persisted tenant
        // envelope. Every ledger-specific binding is verified below.
        let shard = positron_domain::routing::VirtualShardId::new(1)
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
        let scope = positron_kernel::SegmentScope::new(*tenant, SignalKind::Logs, shard);
        let _ = key
            .segment_key_from_tenant_envelope(record.instance, scope, envelope)
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        verified_envelope_count = verified_envelope_count
            .checked_add(1)
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    }
    let mut scopes = Vec::new();
    for tenant in &tenants {
        for signal in [SignalKind::Logs, SignalKind::Traces] {
            let found = snapshot
                .reachable_ledger_scopes(*tenant, signal)
                .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
            scopes
                .try_reserve(found.len())
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
            scopes.extend(found);
        }
    }
    let resuming = resume.is_some();
    if selected_scope.is_some() && resuming {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    let reachable_scope_count = scopes.len();
    let OfflineIntegrityContinuationState {
        mode,
        mut scope_index,
        covered: mut covered_scope_count,
        verified: mut verified_scope_count,
        fenced: mut fenced_scope_count,
        mut all_verified,
        mut examined_segments,
        mut examined_bytes,
        mut omitted_segments,
        mut aggregate_evidence,
        cursor: mut resume_cursor,
    } = if let Some(token) = resume {
        let decoded = key
            .open_object(
                record.instance,
                BootstrapObjectPurpose::Initialized,
                token.encoded(),
            )
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?;
        decode_offline_integrity_continuation(&decoded, snapshot.number())?
    } else {
        OfflineIntegrityContinuationState {
            mode: selected_scope.map_or(OfflineIntegrityContinuationMode::Aggregate, |scope| {
                OfflineIntegrityContinuationMode::Scope(scope)
            }),
            scope_index: 0,
            covered: 0,
            verified: 0,
            fenced: 0,
            all_verified: true,
            examined_segments: 0,
            examined_bytes: 0,
            omitted_segments: 0,
            aggregate_evidence: Vec::new(),
            cursor: None,
        }
    };
    let aggregate = matches!(mode, OfflineIntegrityContinuationMode::Aggregate);
    if aggregate && (scope_index > scopes.len() || covered_scope_count > scopes.len()) {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    if let OfflineIntegrityContinuationMode::Scope(scope) = mode {
        if !scopes.contains(&scope) {
            return Err(crate::OfflineIntegrityFailure::CorruptState);
        }
        let target_index = scopes
            .iter()
            .position(|candidate| *candidate == scope)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        if resuming {
            if scope_index != target_index || covered_scope_count > 1 || verified_scope_count > 1 {
                return Err(crate::OfflineIntegrityFailure::CorruptState);
            }
        } else {
            scope_index = target_index;
            covered_scope_count = 0;
            verified_scope_count = 0;
            all_verified = true;
            resume_cursor = None;
        }
    }
    let mut reports = Vec::new();
    let mut remaining_segments = IntegrityScrubBudget::MAX_SEGMENTS;
    let mut remaining_bytes = IntegrityScrubBudget::MAX_BYTES;
    let mut incomplete_scope_count = 0_usize;
    while let Some(scope) = scopes.get(scope_index).copied() {
        if remaining_segments == 0 || remaining_bytes == 0 {
            break;
        }
        let envelope = identity
            .tenant_key_envelope(scope.tenant_id())
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        let protection = key
            .segment_key_from_tenant_envelope(record.instance, scope, envelope)
            .map_err(|_| crate::OfflineIntegrityFailure::KeyUnavailable)?;
        let report = ActiveSegmentLedger::verify_snapshot_integrity(
            &authority,
            &snapshot,
            record.instance,
            scope,
            protection,
            IntegrityVerificationMode::Offline,
            IntegrityScrubBudget::with_bytes(remaining_segments, remaining_bytes)
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
            cancellation,
            TransactionId::new([0xf1; 16])
                .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?,
            resume_cursor,
        )
        .map_err(|failure| match failure.code() {
            positron_kernel::IntegrityFailureCode::StorageUnavailable => {
                crate::OfflineIntegrityFailure::StorageUnavailable
            },
            positron_kernel::IntegrityFailureCode::Cancelled
            | positron_kernel::IntegrityFailureCode::InvalidInput
            | positron_kernel::IntegrityFailureCode::AmbiguousIntegrity
            | positron_kernel::IntegrityFailureCode::FindingCapacity => {
                crate::OfflineIntegrityFailure::CorruptState
            },
        })?;
        remaining_segments = remaining_segments.saturating_sub(report.examined_segments());
        remaining_bytes = remaining_bytes.saturating_sub(report.examined_bytes());
        let outcome = report.outcome();
        examined_segments = examined_segments
            .checked_add(
                u64::try_from(report.examined_segments())
                    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
            )
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        examined_bytes = examined_bytes
            .checked_add(report.examined_bytes())
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        omitted_segments = omitted_segments
            .checked_add(
                u64::try_from(report.omitted_segments())
                    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?,
            )
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        reports
            .try_reserve(1)
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        reports.push(report);
        if outcome == positron_kernel::IntegrityVerificationOutcome::Incomplete {
            incomplete_scope_count = 1;
            resume_cursor = reports.last().and_then(|report| report.continuation());
            break;
        }
        if aggregate_evidence.len() == MAX_OFFLINE_AGGREGATE_EVIDENCE {
            return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
        }
        aggregate_evidence
            .try_reserve(1)
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        aggregate_evidence.push(crate::OfflineIntegrityEvidence::from_report(report));
        covered_scope_count = covered_scope_count
            .checked_add(1)
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        if outcome == positron_kernel::IntegrityVerificationOutcome::Verified {
            verified_scope_count = verified_scope_count
                .checked_add(1)
                .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        } else {
            all_verified = false;
            if outcome == positron_kernel::IntegrityVerificationOutcome::Fenced {
                fenced_scope_count = fenced_scope_count
                    .checked_add(1)
                    .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
            }
        }
        scope_index = scope_index
            .checked_add(1)
            .ok_or(crate::OfflineIntegrityFailure::CapacityUnavailable)?;
        resume_cursor = None;
        if !aggregate {
            break;
        }
    }
    let disk_pressure = match resource_snapshot.disk_pressure() {
        positron_kernel::DiskPressureState::Healthy => crate::OfflineDiskPressure::Healthy,
        positron_kernel::DiskPressureState::SoftPressure => crate::OfflineDiskPressure::Soft,
        positron_kernel::DiskPressureState::HardPressure => crate::OfflineDiskPressure::Hard,
    };
    let facts = crate::OfflineInspectionFacts::new(
        snapshot.number(),
        tenants.len(),
        reachable_scope_count,
        verified_envelope_count,
        findings.len(),
        verified_scope_count,
        fenced_scope_count,
        incomplete_scope_count,
        resource_snapshot.usable_disk_bytes(),
        disk_pressure,
        backup_repository,
    );
    let needs_continuation = if aggregate {
        covered_scope_count < reachable_scope_count
    } else {
        resume_cursor.is_some()
    };
    let continuation = if needs_continuation {
        let encoded = encode_offline_integrity_continuation(
            snapshot.number(),
            OfflineIntegrityContinuationState {
                mode,
                scope_index,
                covered: covered_scope_count,
                verified: verified_scope_count,
                fenced: fenced_scope_count,
                all_verified,
                examined_segments,
                examined_bytes,
                omitted_segments,
                aggregate_evidence: aggregate_evidence.clone(),
                cursor: resume_cursor,
            },
        )?;
        Some(crate::OfflineIntegrityContinuation(
            key.protect(
                record.instance,
                BootstrapObjectPurpose::Initialized,
                &encoded,
            )
            .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?,
        ))
    } else {
        None
    };
    Ok(crate::OfflineIntegrityVerification::new(
        reports,
        findings,
        facts,
        continuation,
        covered_scope_count,
        all_verified,
        examined_segments,
        examined_bytes,
        omitted_segments,
        aggregate_evidence,
    ))
}

// The canonical scope manifest admits at most 1,024 scopes. Its complete
// terminal account is encoded in the protected continuation (62 bytes each),
// remaining below the 64 KiB continuation limit without silently reducing a
// valid manifest to a partial success claim.
const MAX_OFFLINE_AGGREGATE_EVIDENCE: usize = 1_024;

fn encode_offline_integrity_continuation(
    generation: u64,
    state: OfflineIntegrityContinuationState,
) -> Result<Vec<u8>, crate::OfflineIntegrityFailure> {
    if state.aggregate_evidence.len() > MAX_OFFLINE_AGGREGATE_EVIDENCE {
        return Err(crate::OfflineIntegrityFailure::CapacityUnavailable);
    }
    let mut encoded = Vec::with_capacity(16_384);
    encoded.push(4);
    encoded.extend_from_slice(&generation.to_be_bytes());
    match state.mode {
        OfflineIntegrityContinuationMode::Aggregate => encoded.push(0),
        OfflineIntegrityContinuationMode::Scope(scope) => {
            encoded.push(1);
            encoded.extend_from_slice(&scope.tenant_id().to_bytes());
            encoded.push(match scope.signal_kind() {
                positron_domain::routing::SignalKind::Logs => 1,
                positron_domain::routing::SignalKind::Traces => 2,
            });
            encoded.extend_from_slice(&scope.shard_id().value().to_be_bytes());
        },
    }
    for value in [
        state.scope_index,
        state.covered,
        state.verified,
        state.fenced,
    ] {
        encoded.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?
                .to_be_bytes(),
        );
    }
    encoded.push(u8::from(state.all_verified));
    for value in [
        state.examined_segments,
        state.examined_bytes,
        state.omitted_segments,
    ] {
        encoded.extend_from_slice(&value.to_be_bytes());
    }
    encoded.extend_from_slice(
        &u16::try_from(state.aggregate_evidence.len())
            .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?
            .to_be_bytes(),
    );
    for evidence in &state.aggregate_evidence {
        let scope = evidence.scope();
        encoded.extend_from_slice(&scope.tenant_id().to_bytes());
        encoded.push(match scope.signal_kind() {
            positron_domain::routing::SignalKind::Logs => 1,
            positron_domain::routing::SignalKind::Traces => 2,
        });
        encoded.extend_from_slice(&scope.shard_id().value().to_be_bytes());
        encoded.extend_from_slice(&evidence.catalog_generation().to_be_bytes());
        encoded.push(match evidence.outcome() {
            positron_kernel::IntegrityVerificationOutcome::Verified => 1,
            positron_kernel::IntegrityVerificationOutcome::Stale => 2,
            positron_kernel::IntegrityVerificationOutcome::Quarantined => 3,
            positron_kernel::IntegrityVerificationOutcome::Fenced => 4,
            positron_kernel::IntegrityVerificationOutcome::Incomplete => {
                return Err(crate::OfflineIntegrityFailure::CorruptState);
            },
        });
        encoded.extend_from_slice(&evidence.checksum());
    }
    if let Some(cursor) = state.cursor {
        encoded.push(1);
        encoded.extend_from_slice(&cursor.encode());
    } else {
        encoded.push(0);
    }
    Ok(encoded)
}

#[derive(Clone, Copy)]
enum OfflineIntegrityContinuationMode {
    Aggregate,
    Scope(positron_kernel::SegmentScope),
}

#[derive(Clone)]
struct OfflineIntegrityContinuationState {
    mode: OfflineIntegrityContinuationMode,
    scope_index: usize,
    covered: usize,
    verified: usize,
    fenced: usize,
    all_verified: bool,
    examined_segments: u64,
    examined_bytes: u64,
    omitted_segments: u64,
    aggregate_evidence: Vec<crate::OfflineIntegrityEvidence>,
    cursor: Option<positron_kernel::IntegrityScrubContinuation>,
}

fn decode_offline_integrity_continuation(
    encoded: &[u8],
    generation: u64,
) -> Result<OfflineIntegrityContinuationState, crate::OfflineIntegrityFailure> {
    if encoded.first() != Some(&4) || encoded.get(1..9) != Some(generation.to_be_bytes().as_slice())
    {
        return Err(crate::OfflineIntegrityFailure::CorruptState);
    }
    let (mode, offset) = match encoded.get(9) {
        Some(0) => (OfflineIntegrityContinuationMode::Aggregate, 10),
        Some(1) => {
            let tenant = encoded
                .get(10..26)
                .and_then(|bytes| bytes.try_into().ok())
                .and_then(|bytes| positron_domain::identity::TenantId::from_bytes(bytes).ok())
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
            let signal = match encoded.get(26) {
                Some(1) => positron_domain::routing::SignalKind::Logs,
                Some(2) => positron_domain::routing::SignalKind::Traces,
                _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
            };
            let shard = encoded
                .get(27..31)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes)
                .and_then(|value| positron_domain::routing::VirtualShardId::new(value).ok())
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
            (
                OfflineIntegrityContinuationMode::Scope(positron_kernel::SegmentScope::new(
                    tenant, signal, shard,
                )),
                31,
            )
        },
        _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
    };
    let number = |offset| {
        encoded
            .get(offset..offset + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)
    };
    let scope_index = number(offset)?;
    let covered = number(offset + 2)?;
    let verified = number(offset + 4)?;
    let fenced = number(offset + 6)?;
    let all_verified = match encoded.get(offset + 8) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
    };
    let aggregates_offset = offset + 9;
    let aggregate = |offset| {
        encoded
            .get(offset..offset + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)
    };
    let examined_segments = aggregate(aggregates_offset)?;
    let examined_bytes = aggregate(aggregates_offset + 8)?;
    let omitted_segments = aggregate(aggregates_offset + 16)?;
    let evidence_count_offset = aggregates_offset + 24;
    let evidence_count = encoded
        .get(evidence_count_offset..evidence_count_offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .filter(|count| *count <= MAX_OFFLINE_AGGREGATE_EVIDENCE)
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let evidence_offset = evidence_count_offset + 2;
    const EVIDENCE_BYTES: usize = 62;
    let evidence_end = evidence_offset
        .checked_add(
            evidence_count
                .checked_mul(EVIDENCE_BYTES)
                .ok_or(crate::OfflineIntegrityFailure::CorruptState)?,
        )
        .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
    let mut aggregate_evidence = Vec::new();
    aggregate_evidence
        .try_reserve(evidence_count)
        .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    for index in 0..evidence_count {
        let start = evidence_offset + index * EVIDENCE_BYTES;
        let tenant = encoded
            .get(start..start + 16)
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes| positron_domain::identity::TenantId::from_bytes(bytes).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let signal = match encoded.get(start + 16) {
            Some(1) => positron_domain::routing::SignalKind::Logs,
            Some(2) => positron_domain::routing::SignalKind::Traces,
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        };
        let shard = encoded
            .get(start + 17..start + 21)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .and_then(|value| positron_domain::routing::VirtualShardId::new(value).ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let evidence_generation = encoded
            .get(start + 21..start + 29)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_be_bytes)
            .filter(|value| *value == generation)
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        let outcome = match encoded.get(start + 29) {
            Some(1) => positron_kernel::IntegrityVerificationOutcome::Verified,
            Some(2) => positron_kernel::IntegrityVerificationOutcome::Stale,
            Some(3) => positron_kernel::IntegrityVerificationOutcome::Quarantined,
            Some(4) => positron_kernel::IntegrityVerificationOutcome::Fenced,
            _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
        };
        let checksum = encoded
            .get(start + 30..start + EVIDENCE_BYTES)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(crate::OfflineIntegrityFailure::CorruptState)?;
        aggregate_evidence.push(crate::OfflineIntegrityEvidence::from_parts(
            positron_kernel::SegmentScope::new(tenant, signal, shard),
            evidence_generation,
            outcome,
            checksum,
        ));
    }
    let cursor_offset = evidence_end;
    let cursor = match encoded.get(cursor_offset) {
        Some(0) if encoded.len() == cursor_offset + 1 => None,
        Some(1) if encoded.len() == cursor_offset + 57 => Some(
            positron_kernel::IntegrityScrubContinuation::decode(&encoded[cursor_offset + 1..])
                .map_err(|_| crate::OfflineIntegrityFailure::CorruptState)?,
        ),
        _ => return Err(crate::OfflineIntegrityFailure::CorruptState),
    };
    Ok(OfflineIntegrityContinuationState {
        mode,
        scope_index,
        covered,
        verified,
        fenced,
        all_verified,
        examined_segments,
        examined_bytes,
        omitted_segments,
        aggregate_evidence,
        cursor,
    })
}

pub(super) fn offline_integrity_claim()
-> Result<positron_kernel::WorkClaim, crate::OfflineIntegrityFailure> {
    positron_kernel::WorkClaim::system_diagnostics(positron_kernel::integrity_scrub_resource_claim())
    .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)
}

/// Holds exclusive offline ownership and a system diagnostics reservation for
/// the complete caller operation when bootstrap key custody is unavailable.
/// The closure cannot acquire a second Positron ownership lock while this
/// capability is live, which keeps admission ahead of every collection step.
pub(super) fn with_offline_key_unavailable_diagnostics<T>(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    claim: WorkClaim,
    operation: impl FnOnce(positron_kernel::CrashRecordStore) -> T,
) -> Result<T, crate::OfflineIntegrityFailure> {
    let (volume, access) = paths.storage.acquire().map_err(|failure| match failure {
        positron_kernel::BootstrapStorageFailure::OwnershipLocked => {
            crate::OfflineIntegrityFailure::OwnershipLocked
        },
        _ => crate::OfflineIntegrityFailure::BootstrapUnavailable,
    })?;
    let state = storage::classify_with(&access)
        .map_err(|_| crate::OfflineIntegrityFailure::BootstrapUnavailable)?;
    if state != BootstrapState::Inconsistent || access.open_key().is_ok() {
        return Err(crate::OfflineIntegrityFailure::BootstrapUnavailable);
    }
    let authority = resources::establish_system_diagnostics(volume, max_registered_tenants)
        .map_err(|_| crate::OfflineIntegrityFailure::StorageUnavailable)?;
    let _reservation = authority
        .governor()
        .reserve(claim)
        .map_err(|_| crate::OfflineIntegrityFailure::CapacityUnavailable)?;
    let crash_records = positron_kernel::CrashRecordStore::from_authority(&authority)
        .map_err(|_| crate::OfflineIntegrityFailure::StorageUnavailable)?;
    Ok(operation(crash_records))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use positron_kernel::{
        AdmissionFailureCode, DiskObservation, DiskPressureThresholds, GovernorPolicy,
        InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment,
        OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume, RecoveryPoolCapacities,
        RecoveryReserve, ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration,
        ResourceInventory, StorageKernelResourceAuthority,
    };

    use super::offline_integrity_claim;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn offline_integrity_claim_refuses_the_complete_catalog_peak_before_catalog_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "positron-offline-integrity-admission-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let authority = bounded_system_diagnostics_authority(&root)?;

        // This is the historical single-scrub claim. It fits the configured
        // ordinary capacity and releases normally, demonstrating that the
        // pressure fixture does not reject all diagnostics work.
        let historical_scrub =
            positron_kernel::WorkClaim::system_diagnostics(ResourceAmounts::new([
                16_777_216, 0, 1, 4_000_000, 128, 0, 0, 1, 1, 1, 0,
            ]))?;
        let reservation = authority.governor().reserve(historical_scrub)?;
        assert_eq!(authority.governor().inspect()?.outstanding_total(), 1);
        drop(reservation);
        assert!(authority.governor().inspect()?.complete());

        let refusal =
            authority
                .governor()
                .reserve(offline_integrity_claim().map_err(|failure| {
                    std::io::Error::other(format!("claim failed: {failure:?}"))
                })?)
                .expect_err("the complete Catalog peak must be refused before Catalog inspection");
        assert_eq!(refusal.code(), AdmissionFailureCode::CapacityExhausted);
        assert!(authority.governor().inspect()?.complete());
        drop(authority);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn bounded_system_diagnostics_authority(
        root: &std::path::Path,
    ) -> Result<StorageKernelResourceAuthority, Box<dyn std::error::Error>> {
        let volume = PrimaryDataVolume::acquire(root, MountQualification::LocalHost)?;
        let cardinality = InventoryCardinalityLimits::new(1, 16)?;
        let ordinary = ResourceAmounts::new([
            16_777_316, 32, 32, 4_000_100, 70_000, 32, 32, 32, 4_000_100, 32, 40_000_000,
        ]);
        let recovery_reserve = ResourceAmounts::new([7; 11]);
        let raw = add(
            add(ordinary, recovery_reserve)?,
            cardinality.governor_bootstrap_overhead(1)?,
        )?;
        let observed = ObservedResourceEnvironment::for_test(
            &volume,
            raw,
            DiskObservation::new(raw.get(ResourceDimension::DiskHeadroomBytes)),
        )?;
        let inventory = ResourceInventory::new_observed(
            observed,
            OperatorLimits::new(raw)?,
            RecoveryReserve::new(recovery_reserve)?,
            cardinality,
            DiskPressureThresholds::new(7, 8, 9, raw.get(ResourceDimension::DiskHeadroomBytes))?,
        )?;
        let policy = GovernorPolicy::system_only(OrdinaryPoolPolicy::new(
            ResourceAmounts::new([4; 11]),
            ResourceAmounts::new([3; 11]),
            ResourceAmounts::new([2; 11]),
            ResourceAmounts::new([1; 11]),
        )?);
        let one = ResourceAmounts::new([1; 11]);
        let recovery = RecoveryPoolCapacities::new(one, one, one, one, one, one, one)?;
        let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;
        Ok(StorageKernelResourceAuthority::establish(
            volume,
            configuration,
        )?)
    }

    fn add(
        left: ResourceAmounts,
        right: ResourceAmounts,
    ) -> Result<ResourceAmounts, Box<dyn std::error::Error>> {
        let amount = |dimension| {
            left.get(dimension)
                .checked_add(right.get(dimension))
                .ok_or("resource amount overflow")
        };
        Ok(ResourceAmounts::new([
            amount(ResourceDimension::MemoryBytes)?,
            amount(ResourceDimension::QueueSlots)?,
            amount(ResourceDimension::TaskSlots)?,
            amount(ResourceDimension::BufferCacheBytes)?,
            amount(ResourceDimension::BatchItems)?,
            amount(ResourceDimension::LeaseSlots)?,
            amount(ResourceDimension::RetrySlots)?,
            amount(ResourceDimension::IoPermits)?,
            amount(ResourceDimension::CpuWorkUnits)?,
            amount(ResourceDimension::FileDescriptors)?,
            amount(ResourceDimension::DiskHeadroomBytes)?,
        ]))
    }
}
