//! Public persisted-envelope corruption fixtures use its canonical byte format.
use super::support::{TemporaryRoot, establish_authority};
use super::support::{predecessor_protection as old, successor_protection as successor};
use crate::SegmentProtectionKey;
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret,
    CommittedLedgerReader, InstanceId, LedgerFailureCode, MountQualification, PreparedStoreBlock,
    PrimaryDataVolume, SegmentScope, StoreBlockIdentity, TransactionId,
};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
use std::error::Error;
#[test]
fn migration_rejects_wrong_original_key_without_publishing_or_changing_segment_bytes()
-> Result<(), Box<dyn Error>> {
    for signal in [SignalKind::Logs, SignalKind::Traces] {
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
            signal,
            VirtualShardId::new(1)?,
        );
        let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, old())?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([0xe5; 16])?,
            b"original-authentication".to_vec(),
        )?)?;
        ledger.seal()?;
        let path = std::fs::read_dir(root.path().join("segments/sealed"))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|entry| entry.path().extension().is_some_and(|e| e == "segment"))
            .ok_or("immutable segment")?
            .path();
        let original_bytes = std::fs::read(&path)?;
        let before = catalog.pin()?.identity();
        let wrong = SegmentProtectionKey::from_owned(Box::new([0xff; 32]));
        let failure = ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            successor()?.retain_predecessor(wrong)?,
            TransactionId::new([0xe8; 16])?,
            None,
        )
        .expect_err("unverified original DEK must not be migrated");
        assert_eq!(failure.code(), LedgerFailureCode::AuthenticationFailed);
        assert_eq!(catalog.pin()?.identity(), before);
        assert_eq!(std::fs::read(&path)?, original_bytes);
        assert!(ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            successor()?.retain_predecessor(old())?,
            TransactionId::new([0xe8; 16])?,
            None,
        )?);
        assert_eq!(std::fs::read(&path)?, original_bytes);
        let reader = CommittedLedgerReader::open(&authority, &catalog, scope, successor()?)?;
        assert_eq!(
            reader
                .snapshot()?
                .blocks()
                .first()
                .ok_or("migrated block")?
                .payload(),
            b"original-authentication"
        );
    }
    Ok(())
}

#[test]
fn substituted_successor_context_cannot_silently_fall_back_to_retained_predecessor()
-> Result<(), Box<dyn Error>> {
    for offset in [8, 24, 40, 41, 95, 61, 121, 1_000, 1_001, 1_002] {
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
            b"substitution-canary".to_vec(),
        )?)?;
        ledger.seal()?;
        assert!(ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            successor()?.retain_predecessor(old())?,
            TransactionId::new([0xe8; 16])?,
            None
        )?);
        let basis = catalog.pin()?;
        let _copy = catalog.reserve_catalog_proposal_copy(&basis)?;
        let mut objects = Vec::new();
        for identity in basis.object_identities() {
            let mut bytes = basis.object(identity)?.ok_or("missing object")?.to_vec();
            if bytes.starts_with(b"POSDENV1") {
                match offset {
                    1_000 => {
                        bytes.pop().ok_or("wrapped ciphertext")?;
                    },
                    1_001 => bytes.push(0),
                    1_002 => {
                        let mut duplicate = bytes.clone();
                        *duplicate.get_mut(121).ok_or("ciphertext")? ^= 1;
                        objects.push(CatalogObject::new(duplicate)?);
                    },
                    _ => {
                        let byte = bytes.get_mut(offset).ok_or("canonical field")?;
                        *byte ^= if offset == 40 { 3 } else { 1 };
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
        let current = catalog.pin()?.identity();
        // Keeping the old capability must not hide a substituted target route.
        let reader = CommittedLedgerReader::open(
            &authority,
            &catalog,
            scope,
            successor()?.retain_predecessor(old())?,
        )?;
        let failure = reader.snapshot().err().ok_or("substitution was accepted")?;
        assert_eq!(failure.code(), LedgerFailureCode::AuthenticationFailed);
        assert_eq!(catalog.pin()?.identity(), current);
    }
    Ok(())
}

#[test]
fn replaying_another_segments_successor_ciphertext_cannot_decrypt_or_publish()
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
    for block in [0xf1, 0xf2] {
        let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, old())?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([block; 16])?,
            b"replay-canary".to_vec(),
        )?)?;
        ledger.seal()?;
    }
    for transaction in [0xf3, 0xf4] {
        assert!(ActiveSegmentLedger::migrate_next_envelope(
            &authority,
            &catalog,
            scope,
            successor()?.retain_predecessor(old())?,
            TransactionId::new([transaction; 16])?,
            None
        )?);
    }
    let basis = catalog.pin()?;
    let _copy = catalog.reserve_catalog_proposal_copy(&basis)?;
    let mut first = None;
    for id in basis.object_identities() {
        let bytes = basis.object(id)?.ok_or("object")?;
        if bytes.starts_with(b"POSDENV1") {
            first = Some(bytes);
            break;
        }
    }
    let first = first.ok_or("first envelope")?;
    let mut objects = Vec::new();
    let mut replaced = false;
    for id in basis.object_identities() {
        let mut bytes = basis.object(id)?.ok_or("object")?.to_vec();
        if bytes.starts_with(b"POSDENV1") && bytes.as_slice() != first {
            bytes
                .get_mut(121..)
                .ok_or("target ciphertext")?
                .copy_from_slice(first.get(121..).ok_or("source ciphertext")?);
            replaced = true;
        }
        objects.push(CatalogObject::new(bytes)?);
    }
    assert!(replaced);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf5; 16])?,
            basis.format_epoch().ok_or("format")?,
            objects,
        )?,
        None,
    )?;
    let current = catalog.pin()?.identity();
    let reader = CommittedLedgerReader::open(
        &authority,
        &catalog,
        scope,
        successor()?.retain_predecessor(old())?,
    )?;
    assert_eq!(
        reader.snapshot().err().ok_or("replay accepted")?.code(),
        LedgerFailureCode::AuthenticationFailed
    );
    assert_eq!(catalog.pin()?.identity(), current);
    Ok(())
}
