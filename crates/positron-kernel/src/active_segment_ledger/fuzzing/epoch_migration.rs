//! Actual additive envelope migration, target-only reads and corruption refusal.
use super::*;
use crate::{CommittedLedgerReader, RootRewrapSession};

fn second() -> Result<SegmentProtectionKey, Box<dyn std::error::Error>> {
    Ok(SegmentProtectionKey::from_owned_with_route(
        Box::new([0xe6; 32]),
        [0xe7; 16],
        2,
    )?)
}

pub(super) fn exercise(commands: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let Some(root) = FuzzRoot::new() else {
        return Ok(());
    };
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let Some(authority) = fuzz_authority(volume) else {
        return Ok(());
    };
    let _work = RootRewrapSession::admit(&authority)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let catalog = Catalog::open(&authority, instance, catalog_secret())?;
    let scope = scope();
    let old = || SegmentProtectionKey::from_owned(Box::new([0xe4; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, old())?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xe5; 16])?,
        b"successive-envelope-fuzz-data".to_vec(),
    )?)?;
    ledger.seal()?;
    let path = fs::read_dir(root.0.join("segments/sealed"))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "segment")
        })
        .ok_or("sealed envelope fixture")?
        .path();
    let immutable = fs::read(&path)?;
    assert!(ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        second()?.retain_predecessor(old())?,
        TransactionId::new([0xe8; 16])?,
        None
    )?);
    let basis = catalog.pin()?;
    let _copy = catalog.reserve_catalog_proposal_copy(&basis)?;
    let mut objects = Vec::new();
    let mut changed = false;
    for id in basis.object_identities() {
        let mut bytes = basis.object(id)?.ok_or("managed source")?.to_vec();
        if bytes.starts_with(b"POSDENV1") {
            let original = bytes.clone();
            let (kind, mutations) = commands
                .split_first()
                .map_or((0, &[][..]), |(&kind, tail)| (kind % 4, tail));
            match kind {
                0 => {},
                1 => {
                    for command in mutations.chunks_exact(3) {
                        let offset = usize::from(u16::from_be_bytes([command[0], command[1]]));
                        if let Some(byte) = bytes.get_mut(offset) {
                            *byte ^= command[2];
                        }
                    }
                    changed = bytes != original;
                },
                2 => {
                    bytes.truncate(mutations.first().map_or(0, |value| usize::from(*value)));
                    changed = bytes != original;
                },
                3 => {
                    let mut duplicate = bytes.clone();
                    *duplicate.get_mut(121).ok_or("wrapped key fixture")? ^= 1;
                    objects.push(CatalogObject::new(duplicate)?);
                    changed = true;
                },
                _ => unreachable!("bounded selector"),
            }
        }
        // A completely removed overlay is also an adversarial missing route.
        if !bytes.is_empty() {
            objects.push(CatalogObject::new(bytes)?);
        }
    }
    if changed {
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([0xe9; 16])?,
                basis.format_epoch().ok_or("source format")?,
                objects,
            )?,
            None,
        )?;
    }
    let before = catalog.pin()?.identity();
    let successor =
        SegmentProtectionKey::from_owned_with_route(Box::new([0xf6; 32]), [0xf7; 16], 3)?
            .retain_predecessor(second()?)?;
    let result = ActiveSegmentLedger::migrate_next_envelope(
        &authority,
        &catalog,
        scope,
        successor,
        TransactionId::new([0xfa; 16])?,
        None,
    );
    if changed {
        assert_eq!(
            result
                .expect_err("corrupt applicable route must refuse")
                .code(),
            LedgerFailureCode::AuthenticationFailed
        );
        assert_eq!(catalog.pin()?.identity(), before);
    } else {
        assert!(result?);
        let key = SegmentProtectionKey::from_owned_with_route(Box::new([0xf6; 32]), [0xf7; 16], 3)?;
        let reader = CommittedLedgerReader::open(&authority, &catalog, scope, key)?;
        assert_eq!(
            reader
                .snapshot()?
                .blocks()
                .first()
                .ok_or("target-only block")?
                .payload(),
            b"successive-envelope-fuzz-data"
        );
    }
    assert_eq!(fs::read(path)?, immutable);
    Ok(())
}
