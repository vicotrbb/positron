use super::*;
#[path = "backup_restore/corruption.rs"]
mod corruption;
#[path = "backup_restore/driver.rs"]
mod driver;
#[path = "backup_restore/fixture.rs"]
mod fixture;
use driver::drive_restore;
use fixture::{RestoreProviderFixture, RestoreTestFixture};

#[test]
fn fresh_restore_recovers_initial_origin_staging_interruption()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::OriginInterruption)
}

#[test]
fn fresh_restore_publishes_durable_operation_and_original_query_results()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::Complete)
}
#[test]
fn fresh_restore_binds_target_configuration_without_relaxing_initialized_immutability()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::Configured)
}

#[test]
fn fresh_restore_reconciles_only_its_authenticated_self_capture()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::HistoricalSnapshot)
}

#[test]
fn fresh_restore_replays_historical_completion_after_interrupted_acceptance()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::HistoricalInterruption)
}
#[test]
fn fresh_restore_retains_historical_evidence_across_an_authenticated_registry_append()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::HistoricalAppend)
}

#[test]
fn fresh_restore_preserves_unrelated_active_administrative_work()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::HistoricalUnrelated)
}

#[test]
fn cancelled_fresh_restore_remains_offline_on_exact_cold_retry()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::Cancel)
}
#[test]
fn publishing_restore_rechecks_native_ciphertext_after_cold_restart()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::Tamper)
}
#[test]
fn fresh_restore_preserves_nonempty_recognized_target_without_creating_artifacts()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::Nonempty)
}
#[test]
fn fresh_restore_applies_current_signed_purge_before_default_tenant_exposure()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::PurgedDefault)
}
#[test]
fn fresh_restore_accepts_missing_key_only_for_current_authenticated_purge_exclusion()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::MissingExcluded)
}
#[test]
fn fresh_restore_refuses_missing_live_key_without_mutating_target()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::MissingLive)
}
#[test]
fn fresh_restore_accepts_removed_excluded_registry_reference_with_original_key_context()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::RemovedReference)
}
#[test]
fn fresh_restore_refuses_stale_exclusions_after_current_head_changes_and_cold_retry()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::HeadRace)
}
#[test]
fn fresh_restore_recovers_native_provider_overlay_without_local_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::Provider)
}
#[test]
fn fresh_restore_recovers_publication_after_durable_receipt_before_boot_gate()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::PublicationGap)
}
#[test]
fn fresh_restore_recovers_snapshot_after_worker_retires_original_root_and_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::RetiredLocal)
}
#[test]
fn fresh_restore_status_never_accepts_or_stages_an_unknown_operation()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::InspectFresh)
}
#[test]
fn fresh_restore_status_authenticates_existing_receipt_without_changing_target_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    exercise_restore(RestoreCase::InspectAccepted)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RestoreCase {
    OriginInterruption,
    Complete,
    Configured,
    HistoricalSnapshot,
    HistoricalInterruption,
    HistoricalAppend,
    HistoricalUnrelated,
    Cancel,
    Tamper,
    Nonempty,
    PurgedDefault,
    MissingExcluded,
    MissingLive,
    RemovedReference,
    HeadRace,
    Provider,
    PublicationGap,
    RetiredLocal,
    InspectFresh,
    InspectAccepted,
}
impl RestoreCase {
    fn purged(self) -> bool {
        matches!(
            self,
            Self::PurgedDefault | Self::MissingExcluded | Self::RemovedReference
        )
    }
}
fn exercise_restore(case: RestoreCase) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = RestoreTestFixture::prepare(case)?;
    drive_restore(RestoreTestContext {
        case,
        initialized: &fixture.initialized,
        source_configuration: fixture.source_configuration.as_ref(),
        services: &fixture.services,
        repository_path: &fixture.repository_path,
        runtime: &fixture.runtime,
        target: &fixture.target,
        paths: &fixture.paths,
        configuration: &fixture.configuration,
        restore: &fixture.restore,
        unlock: &fixture.unlock,
        query: &fixture.query,
        administrator: &fixture.administrator,
        pin: fixture.pin,
        provider: fixture.provider.as_ref(),
    })
}
struct RestoreTestContext<'a> {
    case: RestoreCase,
    initialized: &'a Arc<crate::InitializedInstance>,
    source_configuration: Option<&'a (positron_config::EffectiveConfiguration, u64)>,
    services: &'a ServiceHandle,
    repository_path: &'a std::path::Path,
    runtime: &'a tokio::runtime::Runtime,
    target: &'a std::path::Path,
    paths: &'a crate::BootstrapPaths,
    configuration: &'a positron_config::EffectiveConfiguration,
    restore: &'a crate::BackupRestoreRequest,
    unlock: &'a age::x25519::Identity,
    query: &'a str,
    administrator: &'a str,
    pin: positron_kernel::RecoveryIdentity,
    provider: Option<&'a RestoreProviderFixture>,
}
async fn remove_registry_key_references(
    repository: &LocalRepository,
    signer: &positron_kernel::BackupControlSigner,
) -> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{
        CasOutcome, HeadSlot, ImmutableObject, ObjectId, ObjectRange, RegistryHeadChange,
        Repository,
    };
    use sha2::{Digest, Sha256};
    let head = repository
        .registry_head_at(HeadSlot::registry())
        .await?
        .ok_or("registry head")?;
    let generation =
        ObjectId::from_checksum(head.bytes().get(8..40).ok_or("head identity")?.try_into()?);
    let size = repository.object_size_hint(generation).await?;
    let frame = repository
        .read_range(ObjectRange::new(generation, 0, size)?.with_expected_size(size)?)
        .await?;
    let mut payload = frame
        .bytes()
        .get(..frame.bytes().len().checked_sub(64).ok_or("signature")?)
        .ok_or("generation payload")?
        .to_vec();
    let count = |bytes: &[u8], offset: usize| -> Result<usize, Box<dyn std::error::Error>> {
        Ok(u32::from_be_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or("registry count")?
                .try_into()?,
        ) as usize)
    };
    let reservations = 160 + count(&payload, 156)? * 64;
    let keys = reservations + 4 + count(&payload, reservations)? * 64;
    let key_count = count(&payload, keys)?;
    assert!(key_count > 0);
    payload.drain(keys + 4..keys + 4 + key_count * 120);
    payload
        .get_mut(keys..keys + 4)
        .ok_or("key count")?
        .copy_from_slice(&0u32.to_be_bytes());
    let number = u64::from_be_bytes(payload.get(8..16).ok_or("generation number")?.try_into()?)
        .checked_add(1)
        .ok_or("successor")?;
    payload
        .get_mut(8..16)
        .ok_or("generation number")?
        .copy_from_slice(&number.to_be_bytes());
    payload
        .get_mut(16..48)
        .ok_or("previous")?
        .copy_from_slice(&generation.checksum());
    payload.extend_from_slice(&signer.sign(&Sha256::digest(&payload))?.bytes());
    let successor = ImmutableObject::new(payload)?;
    let id = successor.id();
    repository.put_if_absent(successor).await?;
    let mut bytes = b"POSBKH01".to_vec();
    bytes.extend_from_slice(&id.checksum());
    bytes.extend_from_slice(&signer.sign(&Sha256::digest(&bytes))?.bytes());
    assert!(matches!(
        repository
            .compare_and_swap_head_at(
                HeadSlot::registry(),
                RegistryHeadChange::new(Some(head.version()), bytes)?
            )
            .await?,
        CasOutcome::Published(_)
    ));
    Ok(())
}

fn assert_failed_restore_replay(
    paths: &crate::BootstrapPaths,
    configuration: &positron_config::EffectiveConfiguration,
    restore: &crate::BackupRestoreRequest,
    unlock: &age::x25519::Identity,
    operation: positron_governance::OperationId,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..2 {
        let mut retry = crate::InstanceBootstrap::begin_restore(
            paths,
            configuration,
            restore,
            positron_kernel::RecoveryUnlock::Identity(unlock),
        )
        .map_err(|failure| format!("failed operation must remain inspectable: {failure:?}"))?;
        assert_eq!(retry.status().operation_id(), operation);
        assert_eq!(
            retry.status().status(),
            positron_governance::DurableOperationStatus::Failed
        );
        assert_eq!(
            retry.step()?.status(),
            positron_governance::DurableOperationStatus::Failed
        );
    }
    Ok(())
}

fn assert_restore_target_offline(paths: &crate::BootstrapPaths) {
    assert!(
        crate::InstanceBootstrap::reopen(paths).is_err(),
        "receipt cannot expose a partially published instance"
    );
}

type RestoreTargetBytes = Vec<(std::path::PathBuf, Vec<u8>)>;

fn restore_target_bytes(
    root: &std::path::Path,
) -> Result<RestoreTargetBytes, Box<dyn std::error::Error>> {
    let mut pending = vec![root.to_owned()];
    let mut entries = Vec::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_owned();
        if metadata.is_dir() {
            entries.push((relative, Vec::new()));
            for child in fs::read_dir(path)? {
                pending.push(child?.path());
            }
        } else if metadata.is_file() {
            entries.push((relative, fs::read(path)?));
        } else {
            return Err("unexpected target fixture object".into());
        }
    }
    entries.sort();
    Ok(entries)
}

fn assert_corrupt_restore_failed(
    paths: &crate::BootstrapPaths,
    configuration: &positron_config::EffectiveConfiguration,
    restore: &crate::BackupRestoreRequest,
    unlock: &age::x25519::Identity,
    operation: positron_governance::OperationId,
) -> Result<(), Box<dyn std::error::Error>> {
    let failed = crate::InstanceBootstrap::inspect_restore(
        paths,
        configuration,
        restore,
        positron_kernel::RecoveryUnlock::Identity(unlock),
    )?;
    assert_eq!(failed.operation_id(), operation);
    assert_eq!(
        failed.status(),
        positron_governance::DurableOperationStatus::Failed,
        "authenticated permanent target corruption must terminate its durable owner"
    );
    assert_eq!(
        failed.retry_guidance(),
        positron_governance::DurableOperationRetry::Never
    );
    assert!(failed.backup_restore_report().is_none());
    Ok(())
}

#[test]
fn interrupted_restore_historical_completion_refuses_another_administrative_key()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = RestoreTestFixture::prepare(RestoreCase::Complete)?;
    let begin = |request: &crate::BackupRestoreRequest| {
        crate::InstanceBootstrap::begin_restore(
            &fixture.paths,
            &fixture.configuration,
            request,
            positron_kernel::RecoveryUnlock::Identity(&fixture.unlock),
        )
    };
    let interrupted = positron_kernel::with_catalog_publication_fault_after(
        positron_kernel::CatalogPublicationFault::SynchronizeCommit,
        1,
        || begin(&fixture.restore),
    );
    assert!(interrupted.is_err());
    let changed = crate::BackupRestoreRequest::new(
        fixture.source,
        fixture.pin,
        fixture.bundle.clone(),
        positron_governance::AdministrativeIdempotencyKey::new([0x79; 16])?,
    )?;
    let before = restore_target_bytes(&fixture.target)?;
    assert!(
        begin(&changed).is_err(),
        "a different key cannot adopt a committed historical restore"
    );
    assert_eq!(restore_target_bytes(&fixture.target)?, before);
    let original = begin(&fixture.restore)?;
    assert_eq!(
        original.status().kind(),
        positron_governance::DurableOperationKind::BackupRestore
    );
    Ok(())
}

#[test]
fn restored_historical_receipt_rejects_a_signed_registry_rollback_that_still_contains_the_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_backup::{CasOutcome, HeadSlot, RegistryHeadChange, Repository};
    let _serial = crate::services::tests::schema_maintenance::live_native_maintenance_test_guard();
    let fixture = RestoreTestFixture::prepare(RestoreCase::Complete)?;
    let identity = RepositoryIdentity::local(
        [91; 16],
        fixture.initialized.instance.to_bytes(),
        fixture.initialized.integrity_key_fingerprint(),
        &fixture.repository_path,
    )?;
    let repository = fixture
        .runtime
        .block_on(LocalRepository::attach(&fixture.repository_path, &identity))?;
    let slot = HeadSlot::registry();
    let older = fixture
        .runtime
        .block_on(repository.registry_head_at(slot))?
        .ok_or("original published head")?;
    fixture::append_snapshot(
        &fixture.services,
        &fixture.administrator,
        &fixture.repository_path,
    )?;
    let newer = fixture
        .runtime
        .block_on(repository.registry_head_at(slot))?
        .ok_or("appended head")?;
    assert_ne!(older.version(), newer.version());
    let begin = || {
        crate::InstanceBootstrap::begin_restore(
            &fixture.paths,
            &fixture.configuration,
            &fixture.restore,
            positron_kernel::RecoveryUnlock::Identity(&fixture.unlock),
        )
    };
    drop(begin()?);
    let before = restore_target_bytes(&fixture.target)?;
    assert!(matches!(
        fixture
            .runtime
            .block_on(repository.compare_and_swap_head_at(
                slot,
                RegistryHeadChange::new(Some(newer.version()), older.bytes().to_vec())?
            ))?,
        CasOutcome::Published(_)
    ));
    assert!(
        begin().is_err(),
        "membership alone cannot undo the committed observed-head floor"
    );
    assert_eq!(restore_target_bytes(&fixture.target)?, before);
    assert!(matches!(
        fixture
            .runtime
            .block_on(repository.compare_and_swap_head_at(
                slot,
                RegistryHeadChange::new(Some(older.version()), newer.bytes().to_vec())?
            ))?,
        CasOutcome::Published(_)
    ));
    assert!(begin().is_ok());
    Ok(())
}
