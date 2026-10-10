//! Public provider expiry and live capability revocation outcomes.
use super::support::{TemporaryRoot, establish_authority};
use crate::{
    ActiveSegmentLedger, Catalog, CommittedLedgerReader, InstanceId, MountQualification,
    PreparedStoreBlock, PrimaryDataVolume, SegmentScope, StoreBlockIdentity,
};
use positron_domain::{
    identity::TenantId,
    routing::{SignalKind, VirtualShardId},
};
use std::error::Error;
thread_local! {
    static LEASE_CLOCK: std::cell::Cell<std::time::Instant> = std::cell::Cell::new(std::time::Instant::now());
}
fn lease_now() -> std::time::Instant {
    LEASE_CLOCK.with(std::cell::Cell::get)
}

#[test]
fn retained_reader_refreshes_an_expired_provider_lease_without_extending_it_on_clock_regression()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let secrets = root.path().join("secrets");
    std::fs::create_dir(&secrets)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
    let custody = crate::BootstrapKeyCustody::initialize(&secrets)?;
    let envelope = custody.provision_tenant_key_envelope(instance, tenant, [0xe3; 16], 1)?;
    let session = crate::RootRewrapSession::admit(&authority)?;
    let start = lease_now();
    let custody = session.lease_system_with_clock(
        custody,
        instance,
        crate::key_provider::KeyCacheLease::new(std::time::Duration::from_secs(1))?,
        lease_now,
    )?;
    let catalog = Catalog::open(&authority, instance, custody.catalog_secret(instance)?)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        session.tenant_segment_key(&custody, instance, scope, &envelope)?,
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0xe5; 16])?,
        b"expired-lease-reader".to_vec(),
    )?)?;
    ledger.seal()?;
    let reader = CommittedLedgerReader::open(
        &authority,
        &catalog,
        scope,
        session.tenant_segment_key(&custody, instance, scope, &envelope)?,
    )?;
    assert!(custody.provider_health()?.system_ready);
    let expiry = start
        .checked_add(std::time::Duration::from_secs(1))
        .ok_or("clock range")?;
    LEASE_CLOCK.with(|clock| clock.set(expiry));
    assert!(!custody.provider_health()?.system_ready);
    assert_eq!(
        reader
            .snapshot()?
            .blocks()
            .first()
            .ok_or("expired lease block")?
            .payload(),
        b"expired-lease-reader"
    );
    assert!(custody.provider_health()?.system_ready);
    LEASE_CLOCK.with(|clock| clock.set(start));
    assert!(custody.provider_health()?.system_ready);
    let next_expiry = expiry
        .checked_add(std::time::Duration::from_secs(1))
        .ok_or("clock range")?;
    LEASE_CLOCK.with(|clock| clock.set(next_expiry));
    assert!(!custody.provider_health()?.system_ready);
    custody.invalidate_for_rotation()?;
    assert!(reader.snapshot().is_err());
    Ok(())
}

#[test]
fn live_segment_wrapping_capability_cannot_outlive_provider_rotation_fencing()
-> Result<(), Box<dyn Error>> {
    for lease in [
        crate::key_provider::KeyCacheLease::default(),
        crate::key_provider::KeyCacheLease::new(std::time::Duration::ZERO)?,
    ] {
        let root = TemporaryRoot::new()?;
        let authority = establish_authority(PrimaryDataVolume::acquire(
            root.path(),
            MountQualification::LocalHost,
        )?)?;
        let instance = InstanceId::new([0xe1; 16])?;
        let tenant = TenantId::from_bytes([0x64; 16])?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
        let secrets = root.path().join("secrets");
        std::fs::create_dir(&secrets)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))?;
        let custody = crate::BootstrapKeyCustody::initialize(&secrets)?;
        let envelope = custody.provision_tenant_key_envelope(instance, tenant, [0xe3; 16], 1)?;
        let session = crate::RootRewrapSession::admit(&authority)?;
        let custody = session.lease_system(custody, instance, lease)?;
        let catalog = Catalog::open(&authority, instance, custody.catalog_secret(instance)?)?;
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            session.tenant_segment_key(&custody, instance, scope, &envelope)?,
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([0xe5; 16])?,
            b"live-lease-guard".to_vec(),
        )?)?;
        ledger.seal()?;
        let reader = CommittedLedgerReader::open(
            &authority,
            &catalog,
            scope,
            session.tenant_segment_key(&custody, instance, scope, &envelope)?,
        )?;
        let before = catalog.pin()?.identity();
        custody.invalidate_for_rotation()?;
        assert!(
            reader.snapshot().is_err(),
            "retained wrapping key bypassed the provider's rotation fence"
        );
        assert_eq!(catalog.pin()?.identity(), before);
    }
    Ok(())
}
