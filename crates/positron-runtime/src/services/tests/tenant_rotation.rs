use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, request};
use positron_query::QueryBudget;
use prost::Message;
use std::error::Error;
use std::sync::Arc;

fn budget() -> Result<QueryBudget, Box<dyn Error>> {
    Ok(QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(15)?)
}

#[test]
fn zero_key_cache_lease_preserves_native_rotation_migration_and_reads_after_reopen()
-> Result<(), Box<dyn Error>> {
    use crate::{InitializationPlan, InstanceBootstrap};
    let fixture = Fixture::new()?;
    let paths =
        fixture
            .paths()?
            .with_key_cache_lease(positron_kernel::key_provider::KeyCacheLease::new(
                std::time::Duration::ZERO,
            )?);
    drop(InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        2,
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let ingest = claim.ingest_secret().ok_or("ingest credential")?.to_owned();
    let query = claim.query_secret().ok_or("query credential")?.to_owned();
    let administrator = claim.secret().to_owned();
    drop(claim);
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.ingest_otlp_logs(&ingest, request("zero-lease-old").encode_to_vec())?;
    let prepared = services.begin_tenant_key_rotation(&administrator, tenant)?;
    assert_eq!(prepared.active_epoch(), 1);
    assert_eq!(
        services
            .advance_tenant_key_rotation(&administrator, tenant)?
            .active_epoch(),
        1
    );
    assert_eq!(
        services
            .advance_tenant_key_rotation(&administrator, tenant)?
            .active_epoch(),
        2
    );
    let first = services.advance_tenant_key_migration(&administrator, tenant)?;
    assert!(first.migrated_segment());
    assert!(first.remaining_segments());
    let inventory = {
        let _gate = services
            .catalog_operation
            .lock()
            .map_err(|_| "Catalog gate")?;
        let catalog = super::schema_maintenance::open_catalog(&initialized)?;
        let basis = catalog.pin()?;
        let mut inventory = Vec::new();
        for id in basis.object_identities() {
            let bytes = basis.object(id)?.ok_or("managed object")?;
            if bytes.starts_with(b"PSEGMET1") {
                inventory.push((
                    bytes.get(10).copied(),
                    bytes.get(27).copied(),
                    bytes
                        .get(28..32)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u32::from_be_bytes),
                ));
            }
        }
        inventory.sort_unstable();
        inventory
    };
    let mut header_epochs = Vec::new();
    for entry in std::fs::read_dir(fixture.sealed_segments_directory())? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "segment")
        {
            let bytes = std::fs::read(path)?;
            header_epochs.push(
                bytes
                    .get(32..40)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .ok_or("header epoch")?,
            );
        }
    }
    header_epochs.sort_unstable();
    assert_eq!(
        inventory,
        [
            (Some(2), Some(1), Some(1)),
            (Some(2), Some(1), Some(1)),
            (Some(2), Some(2), Some(1))
        ]
    );
    assert_eq!(header_epochs, [1, 1, 1]);
    let second = services.advance_tenant_key_migration(&administrator, tenant)?;
    assert!(second.migrated_segment());
    assert!(second.remaining_segments());
    let third = services.advance_tenant_key_migration(&administrator, tenant)?;
    assert!(third.migrated_segment());
    assert!(!third.remaining_segments());
    services.ingest_otlp_logs(&ingest, request("zero-lease-new").encode_to_vec())?;
    let complete = services.advance_tenant_key_migration(&administrator, tenant)?;
    assert!(
        !complete.migrated_segment(),
        "new-write successor segment must not be classified as a predecessor migration"
    );
    assert!(!complete.remaining_segments());
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            budget()?
        )?,
        ["zero-lease-old", "zero-lease-new"]
    );
    assert!(initialized.data_protection_health()?.system_ready);
    drop((services, initialized));
    let reopened = Arc::new(InstanceBootstrap::reopen(&paths)?);
    assert!(reopened.data_protection_health()?.system_ready);
    let services = ServiceHandle::new(reopened)?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            budget()?
        )?,
        ["zero-lease-old", "zero-lease-new"]
    );
    Ok(())
}
#[test]
fn tenant_rotation_rolls_before_new_epoch_writes_and_preserves_old_reads_after_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
    let tenant = initialized.default_tenant_id();
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("before-tenant-rotation").encode_to_vec())?
            .accepted_records(),
        1
    );
    let prepared = services.begin_tenant_key_rotation(&administrator, tenant)?;
    assert_eq!(prepared.active_epoch(), 1);
    assert_eq!(prepared.successor_epoch(), Some(2));
    assert_eq!(
        services.ingest_otlp_logs(&ingest, request("deferred-during-rotation").encode_to_vec()),
        Err(crate::ServiceFailure::KeyRotationInProgress)
    );
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            budget()?
        )?,
        ["before-tenant-rotation"]
    );
    let progress = services.advance_tenant_key_rotation(&administrator, tenant)?;
    assert_eq!(progress.active_epoch(), 1);
    assert_eq!(progress.successor_epoch(), Some(2));
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            budget()?
        )?,
        ["before-tenant-rotation"]
    );
    drop((services, initialized));
    let initialized = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services.begin_tenant_key_rotation(&administrator, tenant)?,
        progress
    );
    let active = services.advance_tenant_key_rotation(&administrator, tenant)?;
    assert_eq!(active.active_epoch(), 2);
    assert_eq!(active.successor_epoch(), None);
    let migration = services.advance_tenant_key_migration(&administrator, tenant)?;
    assert!(migration.migrated_segment());
    assert!(migration.remaining_segments());
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("after-tenant-rotation").encode_to_vec())?
            .accepted_records(),
        1
    );
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            budget()?
        )?,
        ["before-tenant-rotation", "after-tenant-rotation"]
    );
    drop((services, initialized));
    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(reopened)?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            budget()?
        )?,
        ["before-tenant-rotation", "after-tenant-rotation"]
    );
    Ok(())
}

#[test]
fn tenant_cutover_publication_failure_keeps_durable_epoch_authority_and_resumes()
-> Result<(), Box<dyn Error>> {
    use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};
    for fault in [
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        CatalogPublicationFault::SynchronizeCommit,
    ] {
        let fixture = Fixture::new()?;
        let (initialized, ingest, query, administrator) = fixture.initialized_with_admin()?;
        let tenant = initialized.default_tenant_id();
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.ingest_otlp_logs(&ingest, request("before-fault").encode_to_vec())?;
        services.begin_tenant_key_rotation(&administrator, tenant)?;
        let progress = services.advance_tenant_key_rotation(&administrator, tenant)?;
        assert_eq!(progress.active_epoch(), 1);
        let failed = with_catalog_publication_fault_after(fault, 1, || {
            services.advance_tenant_key_rotation(&administrator, tenant)
        });
        assert_eq!(failed, Err(crate::ServiceFailure::CatalogUnavailable));
        drop((services, initialized));
        let initialized = fixture.reopen()?;
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        let resumed = services.advance_tenant_key_rotation(&administrator, tenant)?;
        assert_eq!(resumed.active_epoch(), 2);
        assert_eq!(resumed.successor_epoch(), None);
        assert_eq!(
            services.tenant_key_rotation_status(&administrator, tenant)?,
            resumed
        );
        services.ingest_otlp_logs(&ingest, request("after-fault").encode_to_vec())?;
        assert_eq!(
            services.query_log_bodies(
                &query,
                "logs | range query_time 0 100 | limit 16",
                budget()?
            )?,
            ["before-fault", "after-fault"]
        );
    }
    Ok(())
}
