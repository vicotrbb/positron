//! Independent reads retain one durable Maintenance owner and publish one report.
use super::execution::{BackupWork, owner::BackupOwner, provider_failure};
use super::*;
use positron_backup::BackupSnapshotVerification;
use positron_kernel::{BackupCaptureFileKind, BackupCaptureVerification, MaintenanceExecution};

pub(in crate::services) struct VerificationWork {
    pub(super) owner: BackupOwner,
    remote: Option<BackupSnapshotVerification>,
    metadata: Option<BackupCaptureVerification>,
    catalog: Option<positron_kernel::CatalogSnapshot>,
    next_file: usize,
    metadata_required: u64,
    governance_required: u64,
    recovered_keys: usize,
    next_schema: usize,
    schema_tenants: Vec<positron_domain::identity::TenantId>,
    policy_tenants: Vec<positron_domain::identity::TenantId>,
}

fn parameters(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    operation: DurableOperation,
) -> Result<(BackupVerificationParameters, RepositoryOperationBinding), ServiceFailure> {
    require_operation(operation, services.instance.instance.to_bytes())?;
    let parameters = operation
        .backup_verification_parameters()
        .ok_or(ServiceFailure::CorruptState)?;
    let binding = RepositoryOperationBinding::from_execution(execution)
        .map_err(super::super::maintenance::map_failure)?;
    if parameters.intent_digest() != binding.intent_digest() {
        return Err(ServiceFailure::CorruptState);
    }
    Ok((parameters, binding))
}

pub(super) fn prepare(
    services: &ServiceHandle,
    execution: &MaintenanceExecution<'_>,
    operation: DurableOperation,
    catalog: &positron_kernel::Catalog<'_>,
) -> Result<positron_governance::AuthorizedContext, ServiceFailure> {
    parameters(services, execution, operation)?;
    let now = services
        .maintenance_status_now()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let actor =
        DurableOperationAdministration::resume_backup_actor(catalog, operation.operation_id(), now)
            .map_err(|_| ServiceFailure::Unauthorized)?;
    if operation.status() == positron_governance::DurableOperationStatus::Pending {
        DurableOperationAdministration::begin(catalog, actor, operation.operation_id(), now)
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    }
    if matches!(
        operation.phase(),
        positron_governance::DurableOperationPhase::Accepted
            | positron_governance::DurableOperationPhase::Preflight
    ) {
        DurableOperationAdministration::advance_backup_verification(
            catalog,
            actor,
            operation.operation_id(),
            false,
            now,
        )
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    }
    Ok(actor)
}

pub(super) fn complete(
    services: &ServiceHandle,
    execution: &mut MaintenanceExecution<'_>,
    work: &mut Option<BackupWork>,
    operation: DurableOperation,
    cancellation: Option<&crate::TaskCancellation>,
    actor: Option<positron_governance::AuthorizedContext>,
) -> Result<bool, ServiceFailure> {
    let (parameters, binding) = parameters(services, execution, operation)?;
    if operation.status().is_terminal() {
        *work = None;
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let coordinator = services.instance.maintenance_coordinator();
        if operation.status() == positron_governance::DurableOperationStatus::Cancelled {
            coordinator
                .cancel_and_persist(&catalog, execution.task().identity())
                .map_err(super::super::maintenance::map_failure)?;
        }
        execution
            .complete_and_persist(
                coordinator,
                &catalog,
                operation.status() == positron_governance::DurableOperationStatus::Succeeded,
            )
            .map_err(super::super::maintenance::map_failure)?;
        return Ok(true);
    }
    let actor = actor.ok_or(ServiceFailure::CorruptState)?;
    if !matches!(work, Some(BackupWork::Verification(_))) {
        *work = Some(BackupWork::Verification(Box::new(VerificationWork {
            owner: BackupOwner::open(services, execution, operation)?,
            remote: None,
            metadata: None,
            catalog: None,
            next_file: 0,
            metadata_required: 0,
            governance_required: 0,
            recovered_keys: 0,
            next_schema: 0,
            schema_tenants: Vec::new(),
            policy_tenants: Vec::new(),
        })));
    }
    let Some(BackupWork::Verification(work)) = work.as_mut() else {
        return Err(ServiceFailure::CorruptState);
    };
    let external = work
        .remote
        .as_ref()
        .map(BackupSnapshotVerification::retained_memory_bytes)
        .transpose()
        .map_err(provider_failure)?
        .unwrap_or(0)
        .checked_add(work.metadata_required)
        .and_then(|bytes| bytes.checked_add(work.governance_required))
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    if !work.owner.registry_ready(services, execution, external)? {
        return Ok(false);
    }
    let publisher = work.owner.publisher(external).map_err(provider_failure)?;
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    if work.remote.is_none() {
        #[cfg(feature = "test-support")]
        let initialization_started = std::time::Instant::now();
        let (_, checkpoint) = execution::checkpoint::current(services, execution, binding)?;
        let (_, progress) = execution::checkpoint::unpack(&checkpoint)?;
        let remote = work
            .owner
            .runtime
            .block_on(async {
                if progress.is_empty() {
                    publisher
                        .begin_snapshot_verification(
                            parameters.snapshot_id(),
                            binding.operation_id(),
                            binding.intent_digest(),
                        )
                        .await
                } else {
                    publisher
                        .resume_snapshot_verification(
                            progress,
                            binding.operation_id(),
                            binding.intent_digest(),
                        )
                        .await
                }
            })
            .map_err(provider_failure)?;
        if remote.manifest_checksum() != parameters.manifest_checksum() {
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
        work.remote = Some(remote);
        #[cfg(feature = "test-support")]
        report_state(
            "remote_initialized",
            Some(work),
            None,
            Some(initialization_started.elapsed().as_millis()),
            None,
        );
        return Ok(false);
    }
    let remote = work.remote.as_mut().ok_or(ServiceFailure::Internal)?;
    if !remote.complete() {
        work.owner
            .runtime
            .block_on(publisher.snapshot_verification_step(remote))
            .map_err(provider_failure)?;
        let progress = publisher
            .snapshot_verification_checkpoint(remote)
            .map_err(provider_failure)?;
        execution::checkpoint::persist(services, execution, binding, None, Some(&progress))?;
        return Ok(false);
    }
    if work.metadata.is_none() && work.catalog.is_none() {
        let manifest = remote.manifest();
        let (original, request) = manifest
            .capture_binding()
            .ok_or(ServiceFailure::BackupRepositoryRejected)?;
        let bytes = work
            .owner
            .runtime
            .block_on(publisher.read_snapshot_file(
                manifest,
                manifest.capture_index(),
                8 * 1024 * 1024,
            ))
            .map_err(provider_failure)?;
        let _gate = services.catalog_operation()?;
        let catalog = services
            .open_maintenance_catalog()
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        let metadata = catalog
            .begin_backup_capture_verification(original, request, &bytes)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        // The signed descriptor inventory determines the future native metadata
        // peak. Admit that peak before reading or decoding any metadata file.
        work.metadata_required = metadata
            .prospective_memory_bytes()
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        let prospective = external
            .checked_add(work.metadata_required)
            .and_then(|bytes| bytes.checked_add(work.governance_required))
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        let publisher = work
            .owner
            .publisher(prospective)
            .map_err(provider_failure)?;
        publisher
            .validate_snapshot_inventory(remote, metadata.files())
            .map_err(provider_failure)?;
        work.metadata = Some(metadata);
        return Ok(false);
    }
    if let Some(metadata) = work.metadata.as_mut() {
        while let Some(file) = metadata.files().get(work.next_file).copied() {
            if matches!(
                file.kind(),
                BackupCaptureFileKind::CatalogObject
                    | BackupCaptureFileKind::GovernanceAudit
                    | BackupCaptureFileKind::AuditCheckpoint
            ) {
                let bytes = work
                    .owner
                    .runtime
                    .block_on(publisher.read_snapshot_file(
                        remote.manifest(),
                        file.identity(),
                        8 * 1024 * 1024,
                    ))
                    .map_err(provider_failure)?;
                let secret = services
                    .instance
                    .key
                    .catalog_secret(services.instance.instance)
                    .map_err(|_| ServiceFailure::KeyUnavailable)?;
                metadata
                    .verify_protected_file(&secret, file.identity(), &bytes)
                    .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
                work.next_file += 1;
                return Ok(false);
            }
            // Ciphertext and segment/frontier identity were checked remotely and
            // by the detached index. No native metadata read is required here.
            work.next_file += 1;
        }
        let metadata = work.metadata.take().ok_or(ServiceFailure::Internal)?;
        let snapshot = metadata
            .finish()
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        if snapshot.number() != remote.manifest().catalog_generation()
            || snapshot.identity().to_bytes() != remote.manifest().catalog_identity()
            || snapshot.governance_audit_frontier() != remote.manifest().audit_frontier()
        {
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
        let governance_required = semantic_memory_requirement(&snapshot)?;
        work.governance_required = governance_required;
        let prospective = external
            .checked_add(governance_required)
            .ok_or(ServiceFailure::CapacityUnavailable)?;
        let _admitted = work
            .owner
            .publisher(prospective)
            .map_err(provider_failure)?;
        let tenants = positron_governance::TenantAdministration::restore_key_tenant_ids(&snapshot)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        if tenants.len() != publisher.verification_key_count(remote) {
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
        work.catalog = Some(snapshot);
        #[cfg(test)]
        execution::test_stops::hit(
            execution::test_stops::StopPoint::VerificationMetadataVerified,
            cancellation,
        )?;
        return Ok(false);
    }
    let snapshot = work.catalog.as_ref().ok_or(ServiceFailure::Internal)?;
    for identity in snapshot.object_identities().skip(work.next_schema) {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?
            .ok_or(ServiceFailure::BackupRepositoryRejected)?;
        work.next_schema += 1;
        if !bytes.starts_with(b"PSCHEMA1") && !bytes.starts_with(b"PIPACT01") {
            continue;
        }
        if bytes.starts_with(b"PSCHEMA1") {
            let memory = semantic_memory_bound(bytes)?;
            // The authenticated snapshot's maximum transient is already priced.
            let _admitted = work.owner.publisher(external).map_err(provider_failure)?;
            let tenants =
                positron_governance::TenantAdministration::restore_key_tenant_ids(snapshot)
                    .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
            verify_schema_object(bytes, &tenants, &mut work.schema_tenants, memory)?;
        }
        if bytes.starts_with(b"PIPACT01") {
            semantic_memory_bound(bytes)?;
            let _admitted = work.owner.publisher(external).map_err(provider_failure)?;
            let tenants =
                positron_governance::TenantAdministration::restore_key_tenant_ids(snapshot)
                    .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
            verify_policy_object(bytes, &tenants, &mut work.policy_tenants)?;
        }
        return Ok(false);
    }
    #[cfg(test)]
    execution::test_stops::hit(
        execution::test_stops::StopPoint::VerificationSemanticVerified,
        cancellation,
    )?;
    if work.recovered_keys < publisher.verification_key_count(remote) {
        let envelope = work
            .owner
            .runtime
            .block_on(publisher.read_verification_key(remote, work.recovered_keys))
            .map_err(provider_failure)?;
        let tenant = positron_domain::identity::TenantId::from_bytes(envelope.tenant())
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        let (epoch, fingerprint) = services
            .instance
            .key
            .backup_tenant_key_identity(services.instance.instance, tenant, envelope.protected())
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        if epoch != envelope.epoch() || fingerprint != envelope.fingerprint() {
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
        let identity = positron_governance::Identity::open(snapshot)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        let mut expected = b"POSBKR01".to_vec();
        expected.extend_from_slice(&envelope.tenant());
        expected.extend_from_slice(&epoch.to_be_bytes());
        expected.extend_from_slice(&fingerprint);
        if identity
            .tenant_key_envelope(tenant)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?
            != expected
        {
            return Err(ServiceFailure::BackupRepositoryRejected);
        }
        work.recovered_keys += 1;
        #[cfg(test)]
        execution::test_stops::hit(
            execution::test_stops::StopPoint::VerificationKeyRecovered,
            cancellation,
        )?;
        return Ok(false);
    }
    if readiness(services)? != crate::RecoveryReadiness::Verified {
        return Err(ServiceFailure::BackupRepositoryRejected);
    }
    let report = work
        .owner
        .runtime
        .block_on(publisher.snapshot_verification_report(remote, snapshot, work.recovered_keys))
        .map_err(provider_failure)?;
    let report = positron_kernel::CatalogObject::new(report.bytes().to_vec())
        .map_err(|_| ServiceFailure::CorruptState)?;
    let _gate = services.catalog_operation()?;
    let catalog = services
        .open_maintenance_catalog()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let now = services
        .maintenance_status_now()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    DurableOperationAdministration::advance_backup_verification(
        &catalog,
        actor,
        operation.operation_id(),
        true,
        now,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    DurableOperationAdministration::succeed_backup_verification(
        &catalog,
        actor,
        operation.operation_id(),
        report,
        now,
    )
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    #[cfg(test)]
    execution::test_stops::hit(
        execution::test_stops::StopPoint::VerificationReportPublished,
        cancellation,
    )?;
    Ok(false)
}

fn verify_policy_object(
    bytes: &[u8],
    tenants: &[positron_domain::identity::TenantId],
    seen: &mut Vec<positron_domain::identity::TenantId>,
) -> Result<(), ServiceFailure> {
    if !bytes.starts_with(b"PIPACT01") {
        return Ok(());
    }
    let tenant = bytes
        .get(8..24)
        .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
        .and_then(|bytes| positron_domain::identity::TenantId::from_bytes(bytes).ok())
        .ok_or(ServiceFailure::BackupRepositoryRejected)?;
    if !tenants.contains(&tenant) || seen.contains(&tenant) {
        return Err(ServiceFailure::BackupRepositoryRejected);
    }
    positron_policy::IngestPolicy::decode_activated_object(tenant, bytes)
        .map_err(|_| ServiceFailure::BackupRepositoryRejected)?
        .ok_or(ServiceFailure::BackupRepositoryRejected)?;
    seen.try_reserve_exact(1)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    seen.push(tenant);
    Ok(())
}

fn semantic_memory_requirement(
    snapshot: &positron_kernel::CatalogSnapshot,
) -> Result<u64, ServiceFailure> {
    let object_count = snapshot.object_identities().count();
    let mut governance_required = 0_u64;
    let mut semantic_transient = 0_usize;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)?
            .ok_or(ServiceFailure::BackupRepositoryRejected)?;
        let memory =
            positron_governance::Identity::catalog_object_memory_bound(bytes, object_count)
                .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
        semantic_transient = semantic_transient.max(semantic_memory_bound(bytes)?);
        governance_required = governance_required
            .checked_add(u64::try_from(memory).map_err(|_| ServiceFailure::CapacityUnavailable)?)
            .ok_or(ServiceFailure::CapacityUnavailable)?;
    }
    // Semantic readers run sequentially. Retain the Governance reconstruction
    // charge plus the largest schema/policy decode peak, not their sum.
    let governance_required = governance_required
        .checked_add(
            u64::try_from(semantic_transient).map_err(|_| ServiceFailure::CapacityUnavailable)?,
        )
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    Ok(governance_required)
}

fn semantic_memory_bound(bytes: &[u8]) -> Result<usize, ServiceFailure> {
    if bytes.starts_with(b"PSCHEMA1") {
        positron_signals::SchemaCatalog::catalog_memory_bound(bytes)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)
    } else if bytes.starts_with(b"PIPACT01") {
        positron_policy::IngestPolicy::activated_object_memory_bound(bytes)
            .map_err(|_| ServiceFailure::BackupRepositoryRejected)
    } else {
        Ok(0)
    }
}

fn verify_schema_object(
    bytes: &[u8],
    tenants: &[positron_domain::identity::TenantId],
    seen: &mut Vec<positron_domain::identity::TenantId>,
    admitted_memory: usize,
) -> Result<(), ServiceFailure> {
    if !bytes.starts_with(b"PSCHEMA1") {
        return Ok(());
    }
    let required = positron_signals::SchemaCatalog::catalog_memory_bound(bytes)
        .map_err(|_| ServiceFailure::BackupRepositoryRejected)?;
    if required > admitted_memory {
        return Err(ServiceFailure::CapacityUnavailable);
    }
    let schema = positron_signals::SchemaCatalog::decode_catalog_object_if_recognized(bytes)
        .map_err(|_| ServiceFailure::BackupRepositoryRejected)?
        .ok_or(ServiceFailure::BackupRepositoryRejected)?;
    if !tenants.contains(&schema.tenant()) || seen.contains(&schema.tenant()) {
        return Err(ServiceFailure::BackupRepositoryRejected);
    }
    seen.try_reserve_exact(1)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    seen.push(schema.tenant());
    Ok(())
}

#[cfg(feature = "test-support")]
pub(in crate::services) fn report_turn(stage: &'static str, work: Option<&BackupWork>) {
    report_state(
        stage,
        match work {
            Some(BackupWork::Verification(work)) => Some(work),
            _ => None,
        },
        None,
        None,
        None,
    );
}

#[cfg(feature = "test-support")]
pub(in crate::services) fn report_timed_turn(
    work: Option<&BackupWork>,
    elapsed: std::time::Duration,
    remaining: std::time::Duration,
) {
    let Some(BackupWork::Verification(work)) = work else {
        return;
    };
    report_state(
        "slow_step",
        Some(work),
        None,
        Some(elapsed.as_millis()),
        Some(remaining.as_millis()),
    );
}

#[cfg(feature = "test-support")]
fn take_diagnostic_permit() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static REMAINING: AtomicU8 = AtomicU8::new(64);
    REMAINING
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
}

#[cfg(feature = "test-support")]
pub(super) fn report_snapshot_stage(
    stage: &'static str,
    elapsed: std::time::Duration,
    progress: Option<&positron_backup::BackupPublicationCheck>,
) {
    if elapsed >= std::time::Duration::from_millis(250) && take_diagnostic_permit() {
        eprintln!(
            "backup_snapshot_stage stage={stage} elapsed_ms={} publication_progress={progress:?}",
            elapsed.as_millis()
        );
    }
}

#[cfg(feature = "test-support")]
fn report_state(
    stage: &'static str,
    work: Option<&VerificationWork>,
    readmission: Option<(ServiceFailure, u64, u64)>,
    elapsed_ms: Option<u128>,
    remaining_ms: Option<u128>,
) {
    if !take_diagnostic_permit() {
        return;
    }
    if let Some(work) = work {
        eprintln!(
            "upgrade_verification_turn stage={stage} readmission_failure_requested_granted={readmission:?} remote_complete={:?} remote_progress={:?} elapsed_ms={elapsed_ms:?} remaining_ms={remaining_ms:?} native_file_index={} native_file_total={:?} catalog_ready={} schema_index={} schema_total={:?} key_index={}",
            work.remote
                .as_ref()
                .map(BackupSnapshotVerification::complete),
            work.remote.as_ref(),
            work.next_file,
            work.metadata
                .as_ref()
                .map(|metadata| metadata.files().len()),
            work.catalog.is_some(),
            work.next_schema,
            work.catalog
                .as_ref()
                .map(|catalog| catalog.object_identities().count()),
            work.recovered_keys
        );
    } else {
        eprintln!("upgrade_verification_turn stage={stage} verification_work=false");
    }
}

#[cfg(feature = "test-support")]
pub(in crate::services) fn report_readmission(
    work: Option<&BackupWork>,
    failure: ServiceFailure,
    requested_memory: u64,
    granted_memory: u64,
) {
    let Some(BackupWork::Verification(work)) = work else {
        return;
    };
    report_state(
        "readmission_discard",
        Some(work),
        Some((failure, requested_memory, granted_memory)),
        None,
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semantic_peak_prices_the_largest_sequential_owner_across_registered_tenants()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::identity::{TenantId, TenantSlug};
        use positron_governance::{
            AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
        };
        use positron_kernel::{CatalogObject, CatalogProposal, FormatEpoch, TransactionId};
        let fixture = crate::services::tests::schema_maintenance::Fixture::new()?;
        let (instance, _, _, administrator) = fixture.initialized_with_admin()?;
        let actor = instance.attribute(
            PresentedCredential::parse(&administrator)?,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )?;
        let secondary = TenantId::from_bytes([0xe4; 16])?;
        instance.create_tenant(
            actor,
            secondary,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("semantic-peak")?,
                "Semantic peak",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0xe5; 16])?,
        )?;
        let schema = |tenant| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            Ok(positron_signals::SchemaCatalog::new(
                tenant,
                positron_signals::SchemaBudget::new(16, 16_384, 16_384, 4096)?,
            )?
            .encode_catalog_object()?)
        };
        let default_schema = schema(instance.default_tenant_id())?;
        let secondary_schema = schema(secondary)?;
        let policy = positron_policy::IngestPolicy::reject_exact_text_body(
            1,
            "large-policy",
            &"x".repeat(8192),
        )?
        .activated_object(secondary)?
        .into_bytes();
        let policy_peak = positron_policy::IngestPolicy::activated_object_memory_bound(&policy)?;
        assert!(
            policy_peak > positron_signals::SchemaCatalog::catalog_memory_bound(&default_schema)?
        );
        assert!(
            policy_peak > positron_signals::SchemaCatalog::catalog_memory_bound(&secondary_schema)?
        );
        let catalog = crate::services::tests::schema_maintenance::open_catalog(&instance)?;
        let append =
            |extra: Vec<Vec<u8>>,
             transaction|
             -> Result<positron_kernel::CatalogSnapshot, Box<dyn std::error::Error>> {
                let basis = catalog.pin()?;
                let mut objects = Vec::new();
                for identity in basis.object_identities() {
                    objects.push(CatalogObject::new(
                        basis
                            .object(identity)?
                            .ok_or("semantic fixture object")?
                            .to_vec(),
                    )?);
                }
                for bytes in extra {
                    objects.push(CatalogObject::new(bytes)?);
                }
                catalog.commit(
                    basis.identity(),
                    CatalogProposal::new(
                        TransactionId::new([transaction; 16])?,
                        FormatEpoch::CATALOG_V1,
                        objects,
                    )?,
                    None,
                )?;
                Ok(catalog.pin()?)
            };
        let first = append(vec![default_schema, policy], 0xe6)?;
        let mut governance = 0_u64;
        for identity in first.object_identities() {
            let bytes = first.object(identity)?.ok_or("semantic object")?;
            governance +=
                u64::try_from(positron_governance::Identity::catalog_object_memory_bound(
                    bytes,
                    first.object_identities().count(),
                )?)?;
        }
        let first_peak = semantic_memory_requirement(&first)?;
        assert_eq!(first_peak, governance + u64::try_from(policy_peak)?);
        drop(first);
        let second = append(vec![secondary_schema], 0xe7)?;
        assert_eq!(
            semantic_memory_requirement(&second)?,
            first_peak,
            "a second valid tenant schema adds no simultaneous transient decode"
        );
        drop(second);
        let malformed = append(vec![b"PSCHEMA1truncated".to_vec()], 0xe8)?;
        assert_eq!(
            semantic_memory_requirement(&malformed),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        assert_eq!(
            semantic_memory_bound(b"PIPACT01truncated"),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        assert_eq!(semantic_memory_bound(b"another owner"), Ok(0));
        Ok(())
    }

    #[test]
    fn independent_verification_binds_schema_metadata_to_one_registered_tenant()
    -> Result<(), Box<dyn std::error::Error>> {
        use positron_domain::identity::TenantId;
        use positron_signals::{SchemaBudget, SchemaCatalog};
        let tenant = TenantId::from_bytes([0x61; 16])?;
        let foreign = TenantId::from_bytes([0x62; 16])?;
        let schema = SchemaCatalog::new(tenant, SchemaBudget::new(16, 16_384, 16_384, 4_096)?)?;
        let bytes = schema.encode_catalog_object()?;
        let memory = SchemaCatalog::catalog_memory_bound(&bytes)?;
        let mut seen = Vec::new();
        assert_eq!(
            verify_schema_object(&bytes, &[foreign], &mut seen, memory),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        assert!(seen.is_empty());
        assert_eq!(
            verify_schema_object(&bytes, &[tenant], &mut seen, memory - 1),
            Err(ServiceFailure::CapacityUnavailable)
        );
        assert_eq!(
            verify_schema_object(&bytes, &[tenant], &mut seen, memory),
            Ok(())
        );
        assert_eq!(
            verify_schema_object(&bytes, &[tenant], &mut seen, memory),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        Ok(())
    }
    #[test]
    fn independent_verification_binds_active_policy_to_one_registered_tenant()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = positron_domain::identity::TenantId::from_bytes([0x71; 16])?;
        let foreign = positron_domain::identity::TenantId::from_bytes([0x72; 16])?;
        let bytes = positron_policy::IngestPolicy::reject_exact_text_body(1, "reject", "secret")?
            .activated_object(tenant)?
            .into_bytes();
        let mut seen = Vec::new();
        assert_eq!(
            verify_policy_object(&bytes, &[foreign], &mut seen),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        assert!(seen.is_empty());
        assert_eq!(verify_policy_object(&bytes, &[tenant], &mut seen), Ok(()));
        assert_eq!(
            verify_policy_object(&bytes, &[tenant], &mut seen),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        Ok(())
    }
    #[test]
    fn independent_verification_rejects_authenticated_malformed_policy_metadata() {
        let mut seen = Vec::new();
        assert_eq!(
            verify_policy_object(b"PIPACT01truncated", &[], &mut seen),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        assert_eq!(
            verify_policy_object(b"another owner", &[], &mut seen),
            Ok(())
        );
    }
    #[test]
    fn independent_verification_rejects_authenticated_malformed_schema_metadata() {
        let mut seen = Vec::new();
        assert_eq!(
            verify_schema_object(b"PSCHEMA1truncated", &[], &mut seen, 0),
            Err(ServiceFailure::BackupRepositoryRejected)
        );
        assert_eq!(
            verify_schema_object(b"another owner", &[], &mut seen, 0),
            Ok(())
        );
    }
}
