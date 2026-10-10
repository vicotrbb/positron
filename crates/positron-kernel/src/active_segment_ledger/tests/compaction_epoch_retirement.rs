//! A real prepared Compaction binding remains a reference after envelope migration.
use super::support::{
    TemporaryRoot, establish_authority, predecessor_protection as old,
    successor_protection as successor,
};
use crate::*;
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
    time::UnixNanoseconds,
};
use std::error::Error;

#[test]
fn specialized_compaction_binding_blocks_retirement_after_current_segments_migrate()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xc1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    super::retention_frontier::install_governance_policy(&catalog, instance, tenant, 60, 0xc4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let (clock, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let ledger =
        ActiveSegmentLedger::open_with_retention_time(&authority, &clock, &catalog, scope, old())?;
    let preparation = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    ledger.append(
        ledger
            .begin_store_block(preparation, StoreBlockIdentity::new([0xc5; 16])?)?
            .finish(b"retained-compaction-reference".to_vec())?,
    )?;
    let snapshot = ledger.snapshot()?;
    let block = snapshot.blocks().first().ok_or("source block")?;
    let bucket = RetentionBucket::for_ingest_time(
        tenant,
        SignalKind::Logs,
        block.authenticate_ingest_time(UnixNanoseconds::new(10_000_000_000))?,
        catalog
            .pin()?
            .retention_policy(SignalKind::Logs)?
            .retention_seconds(),
    )?;
    drop(snapshot);
    ledger.seal()?;
    let ledger = ActiveSegmentLedger::open_for_query_with_retention_time(
        &authority,
        &clock,
        &catalog,
        scope,
        old(),
    )?;
    let prepared = ledger.prepare_compaction_task(
        bucket,
        MaintenanceTaskId::new([0xc6; 16]).map_err(|_| "task identity")?,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    prepared.submit_and_persist(&coordinator, &catalog, 1)?;
    drop(ledger);
    assert!(ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
        TransactionId::new([0xc7; 16])?,
        None
    )?);
    let basis = catalog.pin()?.identity();
    let failure = ActiveSegmentLedger::guard_tenant_epoch_retirement(
        &authority,
        &catalog,
        tenant,
        &successor()?,
    )
    .err()
    .ok_or("retained Compaction binding allowed retirement")?;
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    assert_eq!(catalog.pin()?.identity(), basis);
    coordinator
        .cancel_and_persist(
            &catalog,
            MaintenanceTaskId::new([0xc6; 16]).map_err(|_| "task identity")?,
        )
        .map_err(|_| "durable cancellation")?;
    assert!(
        ActiveSegmentLedger::guard_tenant_epoch_retirement(
            &authority,
            &catalog,
            tenant,
            &successor()?
        )
        .is_err()
    );
    Ok(())
}
