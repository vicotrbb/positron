use std::error::Error;
use std::fs;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::support::{TemporaryRoot, establish_authority};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, LedgerFailureCode, MountQualification,
    OrdinaryPool, PreparedStoreBlock, PrimaryDataVolume, ResourceAmounts, ResourceDimension,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};

#[test]
fn observed_reader_does_not_recreate_an_absent_segments_directory() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x84; 32])),
    )?;
    let segments = root.path().join("segments");
    assert!(segments.is_dir());
    fs::remove_dir_all(&segments)?;

    let failure = ledger
        .reader()
        .expect_err("observed reader must not create missing storage");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert!(
        !segments.exists(),
        "reader opening mutated the storage root"
    );
    Ok(())
}

#[test]
fn observed_reader_admits_reconstruction_before_reading_segment_bytes() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x85; 16])?,
        CatalogSecret::from_owned(Box::new([0x86; 32]), Box::new([0x87; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x88; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x89; 16])?,
        b"reader-admission".to_vec(),
    )?)?;
    for entry in fs::read_dir(root.path().join("segments/active"))? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "segment")
        {
            fs::remove_file(path)?;
        }
    }

    let before = authority.governor().inspect()?;
    let dimension = ResourceDimension::MemoryBytes;
    let shared = before
        .pool_capacity(OrdinaryPool::Shared, dimension)
        .checked_sub(before.pool_usage(OrdinaryPool::Shared, dimension))
        .ok_or("shared memory usage exceeds capacity")?;
    let query = before
        .pool_capacity(OrdinaryPool::InteractiveQueryTail, dimension)
        .checked_sub(before.pool_usage(OrdinaryPool::InteractiveQueryTail, dimension))
        .ok_or("query memory usage exceeds capacity")?;
    let blocker_amount = shared
        .checked_add(query)
        .and_then(|available| available.checked_sub(1))
        .ok_or("admission blocker cannot leave one byte of headroom")?;
    let blocker = authority.governor().reserve(WorkClaim::tenant(
        scope.tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(dimension, blocker_amount)?,
    )?)?;

    let reader = ledger.reader()?;
    let failure = match reader.snapshot() {
        Ok(_) => return Err("reader reconstructed despite saturated capacity".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    drop(blocker);
    Ok(())
}

#[test]
fn successor_segment_epoch_reads_retained_frames_and_rolls_before_new_writes()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let predecessor = || SegmentProtectionKey::from_owned(Box::new([0xb4; 32]));
    let old = ActiveSegmentLedger::open(&authority, &catalog, scope, predecessor())?;
    old.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xb5; 16])?,
        b"previous-epoch".to_vec(),
    )?)?;
    let old_segments =
        fs::read_dir(root.path().join("segments/active"))?.collect::<Result<Vec<_>, _>>()?;
    let original = old_segments
        .iter()
        .find(|entry| entry.path().extension().is_some_and(|e| e == "segment"))
        .ok_or("missing original durable segment")?;
    let original_name = original.file_name();
    let original_bytes = fs::read(original.path())?;
    drop(old);
    let successor =
        SegmentProtectionKey::from_owned_with_route(Box::new([0xb6; 32]), [0xb7; 16], 2)?
            .retain_predecessor(predecessor())?;
    let new = ActiveSegmentLedger::open(&authority, &catalog, scope, successor)?;
    new.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xb8; 16])?,
        b"successor-epoch".to_vec(),
    )?)?;
    let snapshot = new.snapshot()?;
    assert_eq!(
        snapshot
            .blocks()
            .iter()
            .map(|block| block.payload())
            .collect::<Vec<_>>(),
        [b"previous-epoch".as_slice(), b"successor-epoch".as_slice()]
    );
    drop(snapshot);
    let sealed =
        fs::read_dir(root.path().join("segments/sealed"))?.collect::<Result<Vec<_>, _>>()?;
    assert!(
        sealed
            .iter()
            .any(|entry| entry.path().extension().is_some_and(|e| e == "segment"))
    );
    assert_eq!(
        fs::read(root.path().join("segments/sealed").join(original_name))?,
        original_bytes
    );
    drop(new);
    let reopened = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned_with_route(Box::new([0xb6; 32]), [0xb7; 16], 2)?
            .retain_predecessor(predecessor())?,
    )?;
    assert_eq!(reopened.snapshot()?.blocks().len(), 2);
    Ok(())
}

#[test]
fn retained_epoch_wrong_key_cannot_roll_or_mutate_existing_segment() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xc1; 16])?,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let old = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xc4; 32])),
    )?;
    old.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xc5; 16])?,
        b"retained-key-authentication".to_vec(),
    )?)?;
    drop(old);
    let generation = catalog.pin()?.number();
    let entries =
        fs::read_dir(root.path().join("segments/active"))?.collect::<Result<Vec<_>, _>>()?;
    let before = entries
        .iter()
        .map(|entry| Ok((entry.path(), fs::read(entry.path())?)))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let failure = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned_with_route(Box::new([0xc6; 32]), [0xc7; 16], 2)?
            .retain_predecessor(SegmentProtectionKey::from_owned(Box::new([0xc8; 32])))?,
    )
    .expect_err("wrong retained key must fail before rolling the active segment");
    assert_eq!(failure.code(), LedgerFailureCode::AuthenticationFailed);
    assert_eq!(catalog.pin()?.number(), generation);
    for (path, bytes) in before {
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[test]
fn query_open_observes_sealed_scope_without_publishing_or_acquiring_write_key()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let protection = || SegmentProtectionKey::from_owned(Box::new([0xd4; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, protection())?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xd5; 16])?,
        b"sealed-read".to_vec(),
    )?)?;
    ledger.seal()?;
    let generation = catalog.pin()?.identity();
    let active_before = fs::read_dir(root.path().join("segments/active"))?.count();
    let retention = crate::RetentionTimeAuthority::establish()?;
    let observation = ActiveSegmentLedger::open_for_query_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        protection(),
    )?;
    assert_eq!(catalog.pin()?.identity(), generation);
    assert_eq!(
        fs::read_dir(root.path().join("segments/active"))?.count(),
        active_before
    );
    let snapshot = observation.snapshot()?;
    assert_eq!(snapshot.blocks().len(), 1);
    assert_eq!(
        snapshot
            .blocks()
            .first()
            .ok_or("missing sealed block")?
            .payload(),
        b"sealed-read"
    );
    drop(snapshot);
    let failure = observation
        .append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([0xd6; 16])?,
            b"refused-write".to_vec(),
        )?)
        .expect_err("query observation has no write capability");
    assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
    let failure = observation
        .seal()
        .expect_err("query observation cannot seal");
    assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
    assert_eq!(
        fs::read_dir(root.path().join("segments/active"))?.count(),
        active_before
    );
    Ok(())
}

#[test]
fn migrated_successor_envelope_reads_original_immutable_segment_without_predecessor_key()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let predecessor = || SegmentProtectionKey::from_owned(Box::new([0xe4; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, predecessor())?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xe5; 16])?,
        b"immutable-migrated".to_vec(),
    )?)?;
    ledger.seal()?;
    let path = fs::read_dir(root.path().join("segments/sealed"))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "segment")
        })
        .ok_or("missing immutable segment")?
        .path();
    let original = fs::read(&path)?;
    let successor =
        || SegmentProtectionKey::from_owned_with_route(Box::new([0xe6; 32]), [0xe7; 16], 2);
    assert!(
        ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            successor()?.retain_predecessor(predecessor())?,
            crate::TransactionId::new([0xe8; 16])?,
            None
        )
        .expect("successor envelope publication/verification")
    );
    assert!(
        !ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            successor()?,
            crate::TransactionId::new([0xe9; 16])?,
            None
        )
        .expect("successor envelope publication/verification")
    );
    assert_eq!(fs::read(&path)?, original);
    let reader = crate::CommittedLedgerReader::open(&authority, &catalog, scope, successor()?)?;
    let snapshot = reader
        .snapshot()
        .expect("target-only migrated segment decryption");
    assert_eq!(
        snapshot
            .blocks()
            .first()
            .ok_or("missing migrated block")?
            .payload(),
        b"immutable-migrated"
    );
    Ok(())
}
