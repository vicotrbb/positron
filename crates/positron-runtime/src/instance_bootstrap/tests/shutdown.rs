use super::super::*;
use super::support::Roots;
use positron_kernel::{Catalog, CatalogObject, CatalogProposal, FormatEpoch, TransactionId};

#[test]
fn graceful_record_rejects_authenticated_wrong_immutable_bindings()
-> Result<(), Box<dyn std::error::Error>> {
    for offset in [8, 24, 40, 48, 80, 88, 120, 152] {
        let roots = Roots::new()?;
        let instance =
            InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
        instance
            .publish_graceful_shutdown(&mut || false)
            .map_err(|_| "publish drain")?;
        drop(instance);
        let instance = InstanceBootstrap::reopen(&roots.paths())?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let basis = catalog.pin()?;
        let mut objects = Vec::new();
        for identity in basis.object_identities() {
            let mut bytes = basis.object(identity)?.ok_or("missing object")?.to_vec();
            if bytes.starts_with(b"POSSHUT1") {
                let value = bytes.get_mut(offset).ok_or("record field")?;
                *value ^= 1;
            }
            objects.push(CatalogObject::new(bytes)?);
        }
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new(instance.key.random_identifier()?)?,
                FormatEpoch::CATALOG_V1,
                objects,
            )?,
            None,
        )?;
        drop(catalog);
        let failure = instance
            .graceful_shutdown_record()
            .expect_err("a wrong authenticated record binding must not be accepted");
        assert_eq!(
            failure.code(),
            BootstrapFailureCode::CatalogUnavailable,
            "field offset {offset}"
        );
    }
    Ok(())
}

#[test]
fn legitimate_later_catalog_publication_preserves_historical_drain_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let instance =
        InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "publish drain")?;
    drop(instance);
    let instance = InstanceBootstrap::reopen(&roots.paths())?;
    let record = instance
        .graceful_shutdown_record()?
        .ok_or("missing record")?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance.key.catalog_secret(instance.instance)?,
    )?;
    let basis = catalog.pin()?;
    let mut objects = Vec::new();
    for identity in basis.object_identities() {
        objects.push(CatalogObject::new(
            basis.object(identity)?.ok_or("missing object")?.to_vec(),
        )?);
    }
    objects.push(CatalogObject::new(b"legitimate-later-object".to_vec())?);
    let committed = catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(instance.key.random_identifier()?)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert!(committed.number() > record.catalog_generation());
    drop(catalog);
    assert_eq!(instance.graceful_shutdown_record()?, Some(record));
    Ok(())
}

#[test]
fn malformed_and_duplicate_drain_records_are_closed_inspection_failures()
-> Result<(), Box<dyn std::error::Error>> {
    for duplicate in [false, true] {
        let roots = Roots::new()?;
        let instance =
            InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
        instance
            .publish_graceful_shutdown(&mut || false)
            .map_err(|_| "publish drain")?;
        drop(instance);
        let instance = InstanceBootstrap::reopen(&roots.paths())?;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let basis = catalog.pin()?;
        let mut objects = Vec::new();
        for identity in basis.object_identities() {
            let bytes = basis.object(identity)?.ok_or("missing object")?;
            if bytes.starts_with(b"POSSHUT1") {
                if duplicate {
                    objects.push(CatalogObject::new(bytes.to_vec())?);
                    let mut another = bytes.to_vec();
                    *another.get_mut(24).ok_or("transaction field")? ^= 1;
                    objects.push(CatalogObject::new(another)?);
                } else {
                    objects.push(CatalogObject::new(
                        bytes.get(..24).ok_or("record prefix")?.to_vec(),
                    )?);
                }
            } else {
                objects.push(CatalogObject::new(bytes.to_vec())?);
            }
        }
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new(instance.key.random_identifier()?)?,
                FormatEpoch::CATALOG_V1,
                objects,
            )?,
            None,
        )?;
        drop(catalog);
        assert_eq!(
            instance
                .graceful_shutdown_record()
                .expect_err("ambiguous record must fail closed")
                .code(),
            BootstrapFailureCode::CatalogUnavailable
        );
    }
    Ok(())
}

#[test]
fn final_drain_preserves_epoch_two_catalog() -> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let instance =
        InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
    assert_eq!(
        instance.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "publish drain")?;
    drop(instance);
    let reopened = InstanceBootstrap::reopen(&roots.paths())?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    assert!(reopened.graceful_shutdown_record()?.is_some());
    Ok(())
}
