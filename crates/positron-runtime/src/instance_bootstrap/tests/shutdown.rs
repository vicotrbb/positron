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

#[test]
fn graceful_drain_preserves_trusted_elapsed_time_for_cold_clock_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::time::UnixNanoseconds;
    use positron_kernel::{
        LifecycleClockFailure, LifecycleClockPolicy, LifecycleClockSource, LifecycleClockState,
        RetentionTimeAuthority,
    };

    struct FixedWall(UnixNanoseconds);
    impl LifecycleClockSource for FixedWall {
        fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
            Ok(self.0)
        }
    }

    let roots = Roots::new()?;
    let mut instance =
        InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
    let baseline = instance.retention_time.status().safe_anchor();
    let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(baseline);
    instance.install_retention_time_for_test(clock)?;
    {
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        catalog.checkpoint_lifecycle_time(&instance.retention_time)?;
    }
    // Genuine monotonic progress exceeds the default 300-second wall offset
    // bound. A successful Drain must retain it before releasing the instance.
    const ELAPSED: u64 = 601_000_000_000;
    elapsed.advance(ELAPSED)?;
    let expected = UnixNanoseconds::new(
        baseline
            .value()
            .checked_add(i64::try_from(ELAPSED)?)
            .ok_or("trusted time overflow")?,
    );
    instance
        .publish_graceful_shutdown(&mut || false)
        .map_err(|_| "publish drain")?;
    drop(instance);

    let reopened = InstanceBootstrap::reopen(&roots.paths())?;
    let record = reopened
        .graceful_shutdown_record()?
        .ok_or("missing Drain proof")?;
    let catalog = Catalog::open(
        &reopened._authority,
        reopened.instance,
        reopened.key.catalog_secret(reopened.instance)?,
    )?;
    let final_snapshot = catalog.pin()?;
    assert_eq!(final_snapshot.number(), record.catalog_generation());
    reopened.verify_graceful_shutdown_frontiers(&record)?;
    // The reopened instance uses the real System wall. Do not claim that
    // authority is Certain after synthetic future elapsed time. Recover the
    // actual authenticated final snapshot with the matching modeled wall.
    let cold_clock = RetentionTimeAuthority::establish_with_source(
        FixedWall(expected),
        LifecycleClockPolicy::default(),
    )?;
    cold_clock.recover_catalog_anchor(&final_snapshot)?;
    assert_eq!(cold_clock.status().state(), LifecycleClockState::Certain);
    assert!(cold_clock.status().safe_anchor() >= expected);
    Ok(())
}

#[test]
fn ungraceful_exit_and_wall_jump_do_not_fabricate_trusted_clock_progress()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_domain::time::UnixNanoseconds;
    use positron_kernel::{
        LifecycleClockFailure, LifecycleClockPolicy, LifecycleClockSource, LifecycleClockState,
        RetentionTimeAuthority,
    };
    struct FixedWall(UnixNanoseconds);
    impl LifecycleClockSource for FixedWall {
        fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
            Ok(self.0)
        }
    }
    for wall_jump_then_graceful in [false, true] {
        let roots = Roots::new()?;
        let mut instance =
            InstanceBootstrap::initialize(&roots.paths(), InitializationPlan::non_interactive())?;
        let baseline = instance.retention_time.status().safe_anchor();
        let (clock, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(baseline);
        instance.install_retention_time_for_test(clock)?;
        let seed = {
            let catalog = Catalog::open(
                &instance._authority,
                instance.instance,
                instance.key.catalog_secret(instance.instance)?,
            )?;
            catalog.checkpoint_lifecycle_time(&instance.retention_time)?;
            catalog.pin()?
        };
        let advanced = UnixNanoseconds::new(
            baseline
                .value()
                .checked_add(601_000_000_000)
                .ok_or("time overflow")?,
        );
        if wall_jump_then_graceful {
            // The wall moved without matching trusted monotonic elapsed. A
            // graceful marker cannot silently accept this discontinuity.
            let jumped = RetentionTimeAuthority::establish_with_source(
                FixedWall(advanced),
                LifecycleClockPolicy::default(),
            )?;
            jumped.recover_catalog_anchor(&seed)?;
            assert_eq!(jumped.status().state(), LifecycleClockState::ClockUncertain);
            instance.install_retention_time_for_test(jumped)?;
            instance
                .publish_graceful_shutdown(&mut || false)
                .map_err(|_| "publish uncertain drain")?;
        } else {
            elapsed.advance(601_000_000_000)?;
            // No Drain means no claim that the final trusted progress was
            // durably retained, even though this process observed it.
        }
        drop(instance);
        let reopened = InstanceBootstrap::reopen(&roots.paths())?;
        let record = reopened.graceful_shutdown_record()?;
        assert_eq!(record.is_some(), wall_jump_then_graceful);
        if let Some(record) = record {
            reopened.verify_graceful_shutdown_frontiers(&record)?;
        }
        let catalog = Catalog::open(
            &reopened._authority,
            reopened.instance,
            reopened.key.catalog_secret(reopened.instance)?,
        )?;
        let cold = RetentionTimeAuthority::establish_with_source(
            FixedWall(advanced),
            LifecycleClockPolicy::default(),
        )?;
        cold.recover_catalog_anchor(&catalog.pin()?)?;
        assert_eq!(cold.status().state(), LifecycleClockState::ClockUncertain);
        assert!(cold.status().safe_anchor() < advanced);
    }
    Ok(())
}
