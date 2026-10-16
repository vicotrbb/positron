use crate::*;
use positron_domain::identity::TenantId;

#[test]
fn live_key_reclamation_requires_published_authority_and_survives_cold_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-live-purge-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&path)?;
    let authority = super::support::establish_catalog_authority_with_purge_pool(
        PrimaryDataVolume::acquire(&path, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
        true,
    )?;
    let instance = InstanceId::new([1; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    let target = TenantId::from_bytes([0x43; 16])?;
    let proof = [5; 32];
    let key = CatalogObject::new(b"target recoverable envelope".to_vec())?;
    let key_id = key.identity();
    let other = CatalogObject::new(b"unrelated recoverable envelope".to_vec())?;
    let other_id = other.identity();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([6; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![
                key,
                CatalogObject::new(b"unrelated recoverable envelope".to_vec())?,
            ],
        )?,
        Some(AuditIntent::new(b"create".to_vec())?),
    )?;
    let historical = catalog.pin()?;
    let key_name = format!(
        "0000000002-{}.frame",
        key_id
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let staged = path.join("catalog/staging/abababababababababababababababab");
    std::fs::create_dir(&staged)?;
    std::fs::copy(
        path.join("catalog/objects").join(&key_name),
        staged.join(&key_name),
    )?;
    let rewrap_copy = path
        .join("catalog/staging")
        .join(format!("rewrap-1-{key_name}"));
    std::fs::copy(path.join("catalog/objects").join(&key_name), &rewrap_copy)?;
    assert!(catalog.reclaim_tenant_key_objects(target, proof).is_err());
    let mut abandoned = catalog.begin_tenant_key_inventory(target, proof)?;
    assert!(matches!(
        abandoned.step(&catalog, |bytes| Ok::<_, ()>(
            bytes == b"target recoverable envelope"
        ))?,
        TenantKeyInventoryStep::Pending { .. }
    ));
    assert!(path.join("catalog/objects").join(&key_name).exists());
    drop(abandoned);
    // Losing an unpublished session never grants deletion and starts a bounded
    // rescan; no native directory offset becomes durable authority.
    let mut inventory = catalog.begin_tenant_key_inventory(target, proof)?;
    let mut pending = 0;
    let mut descriptor = loop {
        match inventory.step(&catalog, |bytes| {
            Ok::<_, ()>(bytes == b"target recoverable envelope")
        })? {
            TenantKeyInventoryStep::Pending { .. } => pending += 1,
            TenantKeyInventoryStep::Complete { objects } => break objects,
        }
    };
    assert!(pending >= 3);
    drop(inventory);
    // The Catalog must authenticate the complete descriptor group before any
    // exact-file exclusion is usable, including across an interrupted retry.
    let original = descriptor.first().ok_or("descriptor")?.canonical_bytes();
    let mut first_part = original.to_vec();
    first_part
        .get_mut(58..60)
        .ok_or("parts")?
        .copy_from_slice(&2u16.to_be_bytes());
    let mut last_part = first_part.get(..62).ok_or("header")?.to_vec();
    last_part
        .get_mut(56..58)
        .ok_or("part")?
        .copy_from_slice(&1u16.to_be_bytes());
    last_part
        .get_mut(60..62)
        .ok_or("count")?
        .copy_from_slice(&0u16.to_be_bytes());
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([10; 16])?,
            FormatEpoch::CATALOG_V2,
            vec![
                CatalogObject::new(first_part.clone())?,
                CatalogObject::new(b"unrelated recoverable envelope".to_vec())?,
            ],
        )?,
        Some(AuditIntent::new(b"incomplete descriptor fixture".to_vec())?),
    )?;
    assert!(catalog.reclaim_tenant_key_objects(target, proof).is_err());
    assert!(path.join("catalog/objects").join(&key_name).exists());
    descriptor = vec![
        CatalogObject::new(first_part)?,
        CatalogObject::new(last_part)?,
    ];
    descriptor.push(other);
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([7; 16])?,
            FormatEpoch::CATALOG_V2,
            descriptor,
        )?,
        Some(AuditIntent::new(b"purge authority".to_vec())?),
    )?;
    assert!(catalog.reclaim_tenant_key_objects(target, [9; 32]).is_err());
    let interrupted = super::super::storage::fault::with_catalog_fault_after(
        super::super::CatalogFileEvent::ReclaimKeyObject,
        1,
        || catalog.reclaim_tenant_key_objects(target, proof),
    );
    assert!(interrupted.is_err());
    assert!(!path.join("catalog/objects").join(&key_name).exists());
    assert!(staged.join(&key_name).exists());
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, secret())?;
    // A cold retry must use the committed inventory, even though one source
    // envelope has already gone and the other copy is still staged.
    catalog.prepare_tenant_key_reclamation(target, proof, |_| Err::<bool, _>(()))?;
    assert!(catalog.tenant_key_reclamation_prepared(target, proof)?);
    // Interruption after unlink but before fsync must be repeatable from the
    // last authenticated cursor. An invented ordinal cannot skip a file.
    let interrupted_sync = super::super::storage::fault::with_catalog_fault_after(
        super::super::CatalogFileEvent::SynchronizeReclaimedKeyDirectory,
        0,
        || catalog.reclaim_tenant_key_objects_step(target, proof, None),
    );
    assert!(interrupted_sync.is_err());
    let TenantKeyReclamationStep::Pending { mut cursor } =
        catalog.reclaim_tenant_key_objects_step(target, proof, None)?
    else {
        return Err("expected persisted progress".into());
    };
    let mut forged = cursor.clone();
    *forged.first_mut().ok_or("cursor")? ^= 1;
    assert!(
        catalog
            .reclaim_tenant_key_objects_step(target, proof, Some(&forged))
            .is_err()
    );
    assert!(
        catalog
            .reclaim_tenant_key_objects_step(target, [8; 32], Some(&cursor))
            .is_err()
    );
    // Repeating the same issued cursor is idempotent; only that exact file's
    // absence is accepted. The next issued cursor survives Catalog reopening.
    let next = catalog.reclaim_tenant_key_objects_step(target, proof, Some(&cursor))?;
    let repeated = catalog.reclaim_tenant_key_objects_step(target, proof, Some(&cursor))?;
    let (
        TenantKeyReclamationStep::Pending { cursor: next },
        TenantKeyReclamationStep::Pending { cursor: repeated },
    ) = (next, repeated)
    else {
        return Err("expected next progress".into());
    };
    assert_eq!(next, repeated);
    cursor = next;
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, secret())?;
    let completed = loop {
        match catalog.reclaim_tenant_key_objects_step(target, proof, Some(&cursor))? {
            TenantKeyReclamationStep::Pending { cursor: next } => cursor = next,
            TenantKeyReclamationStep::Complete(completed) => break completed,
        }
    };
    assert!(!path.join("catalog/objects").join(&key_name).exists());
    assert!(!staged.join(&key_name).exists());
    assert!(!rewrap_copy.exists());
    let old = Catalog::read_historical_snapshot(
        &authority,
        instance,
        secret(),
        &catalog.pin()?,
        historical.identity().to_bytes(),
        historical.number(),
    )?;
    assert_ne!(
        old.object(key_id)?,
        Some(b"target recoverable envelope".as_slice())
    );
    assert_eq!(
        old.object(other_id)?,
        Some(b"unrelated recoverable envelope".as_slice())
    );
    assert_eq!(completed.tenant_id(), target);
    assert_eq!(completed.proof_digest(), proof);
    let before = catalog.pin()?;
    drop(catalog);
    let catalog = Catalog::open(&authority, instance, secret())?;
    assert_eq!(catalog.pin()?.identity(), before.identity());
    assert_eq!(catalog.governance_audit_records()?.len(), 3);
    catalog.reclaim_tenant_key_objects(target, proof)?;
    catalog.rewrap(
        TransactionId::new([8; 16])?,
        CatalogWrappingKey::from_owned_at_epoch(Box::new([8; 32]), [9; 16], 2)?,
        AuditIntent::new(b"rotate after purge".to_vec())?,
    )?;
    drop(catalog);
    let secret =
        || CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([8; 32]), [9; 16], 2);
    let catalog = Catalog::open(&authority, instance, secret()?)?;
    catalog.reclaim_tenant_key_objects(target, proof)?;
    drop(catalog);
    let other_name = format!(
        "0000000002-{}.frame",
        other_id
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    std::fs::remove_file(path.join("catalog/objects").join(other_name))?;
    assert!(Catalog::open(&authority, instance, secret()?).is_err());
    drop(authority);
    std::fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn bounded_inventory_never_authorizes_partial_deletion() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "positron-bounded-purge-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&path)?;
    let authority = super::support::establish_catalog_authority_with_purge_pool(
        PrimaryDataVolume::acquire(&path, MountQualification::LocalHost)?,
        70_000_001,
        30_000_000,
        true,
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([1; 16])?,
        CatalogSecret::from_owned(Box::new([2; 32]), Box::new([3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x43; 16])?;
    // Unrecognized directory names still consume bounded traversal work.
    for number in 0..130 {
        std::fs::write(
            path.join("catalog/objects")
                .join(format!("unrelated-{number}")),
            [],
        )?;
    }
    let mut scan = catalog.begin_tenant_key_inventory(tenant, [5; 32])?;
    let first_visited = match scan.step(&catalog, |_| Ok::<_, ()>(false))? {
        TenantKeyInventoryStep::Pending { visited } => visited,
        TenantKeyInventoryStep::Complete { .. } => {
            return Err("scan exceeded directory turn bound".into());
        },
    };
    assert!(first_visited <= 64);
    assert!(matches!(
        scan.step(&catalog, |_| Ok::<_, ()>(false))?,
        TenantKeyInventoryStep::Pending { .. }
    ));
    let objects = loop {
        match scan.step(&catalog, |_| Ok::<_, ()>(false))? {
            TenantKeyInventoryStep::Pending { .. } => {},
            TenantKeyInventoryStep::Complete { objects } => break objects,
        }
    };
    assert_eq!(objects.len(), 1); // An empty complete inventory is explicit.
    assert!(
        catalog
            .reclaim_tenant_key_objects_step(tenant, [5; 32], None)
            .is_err()
    );
    drop(scan);
    std::fs::create_dir(
        path.join("catalog/staging")
            .join("ABCDABCDABCDABCDABCDABCDABCDABCD"),
    )?;
    let mut scan = catalog.begin_tenant_key_inventory(tenant, [5; 32])?;
    let refused = loop {
        match scan.step(&catalog, |_| Ok::<_, ()>(false)) {
            Ok(TenantKeyInventoryStep::Pending { .. }) => {},
            Ok(TenantKeyInventoryStep::Complete { .. }) => break false,
            Err(_) => break true,
        }
    };
    assert!(
        refused,
        "noncanonical transaction location cannot authorize a normalized path"
    );
    drop(scan);
    drop(catalog);
    drop(authority);
    std::fs::remove_dir_all(path)?;
    Ok(())
}
