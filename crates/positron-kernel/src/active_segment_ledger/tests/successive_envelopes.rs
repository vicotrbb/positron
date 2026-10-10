//! Later migrations must use a verified retained Catalog route, without epoch 1.
use super::support::{
    TemporaryRoot, establish_authority, predecessor_protection as old,
    successor_protection as second,
};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret,
    CommittedLedgerReader, InstanceId, LedgerFailureCode, MountQualification, PreparedStoreBlock,
    PrimaryDataVolume, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, TransactionId,
};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
use std::error::Error;

fn third(wrong: bool) -> Result<SegmentProtectionKey, Box<dyn Error>> {
    let predecessor = if wrong {
        SegmentProtectionKey::from_owned_with_route(Box::new([0xff; 32]), [0xe7; 16], 2)?
    } else {
        second()?
    };
    Ok(
        SegmentProtectionKey::from_owned_with_route(Box::new([0xf6; 32]), [0xf7; 16], 3)?
            .retain_predecessor(predecessor)?,
    )
}

#[test]
fn successive_migration_authenticates_applicable_epoch_two_before_publication()
-> Result<(), Box<dyn Error>> {
    for mutation in [
        None,
        Some(8),
        Some(24),
        Some(40),
        Some(41),
        Some(45),
        Some(61),
        Some(95),
        Some(111),
        Some(121),
        Some(1_000),
        Some(1_001),
        Some(1_002),
        Some(1_003),
    ] {
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
        let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, old())?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([0xe5; 16])?,
            b"successive-route-data".to_vec(),
        )?)?;
        ledger.seal()?;
        let path = std::fs::read_dir(root.path().join("segments/sealed"))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "segment")
            })
            .ok_or("immutable segment")?
            .path();
        let original = std::fs::read(&path)?;
        assert!(ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            second()?.retain_predecessor(old())?,
            TransactionId::new([0xe8; 16])?,
            None
        )?);
        if let Some(offset) = mutation
            && offset != 1_003
        {
            let basis = catalog.pin()?;
            let _copy = catalog.reserve_catalog_proposal_copy(&basis)?;
            let mut objects = Vec::new();
            for id in basis.object_identities() {
                let mut bytes = basis.object(id)?.ok_or("source object")?.to_vec();
                if bytes.starts_with(b"POSDENV1") {
                    match offset {
                        1_000 => {
                            bytes.pop().ok_or("truncated ciphertext")?;
                        },
                        1_001 => bytes.push(0),
                        1_002 => {
                            let mut duplicate = bytes.clone();
                            *duplicate.get_mut(121).ok_or("duplicate ciphertext")? ^= 1;
                            objects.push(CatalogObject::new(duplicate)?);
                        },
                        _ => {
                            *bytes.get_mut(offset).ok_or("canonical context")? ^=
                                if offset == 40 { 3 } else { 1 };
                        },
                    }
                }
                objects.push(CatalogObject::new(bytes)?);
            }
            catalog.commit(
                basis.identity(),
                CatalogProposal::new(
                    TransactionId::new([0xe9; 16])?,
                    basis.format_epoch().ok_or("format")?,
                    objects,
                )?,
                None,
            )?;
        }
        let before = catalog.pin()?.identity();
        let result = ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            third(mutation == Some(1_003))?,
            TransactionId::new([0xfa; 16])?,
            None,
        );
        if mutation.is_some() {
            assert_eq!(
                result
                    .expect_err("applicable epoch 2 corruption refused")
                    .code(),
                LedgerFailureCode::AuthenticationFailed
            );
            assert_eq!(catalog.pin()?.identity(), before);
        } else {
            assert!(result?);
            let key =
                SegmentProtectionKey::from_owned_with_route(Box::new([0xf6; 32]), [0xf7; 16], 3)?;
            let reader = CommittedLedgerReader::open(&authority, &catalog, scope, key)?;
            assert_eq!(
                reader
                    .snapshot()?
                    .blocks()
                    .first()
                    .ok_or("target-only data")?
                    .payload(),
                b"successive-route-data"
            );
        }
        assert_eq!(std::fs::read(&path)?, original);
    }
    Ok(())
}
