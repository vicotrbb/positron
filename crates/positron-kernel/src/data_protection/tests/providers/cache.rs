use super::*;

#[test]
fn full_tenant_key_identity_is_preserved_when_its_prefix_is_zero()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(&root.path)?)?;
    let tenant = positron_domain::identity::TenantId::from_bytes([31; 16])?;
    let mut id = [0; 32];
    id[16..].fill(9);
    let context = EnvelopeContext::new([1; 16], KeyScope::Tenant(tenant), id, 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::default(),
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    ready(cache.load(&envelope, context))?;
    let object = protection::FrameObjectContext::tenant_segment(
        tenant,
        positron_domain::routing::SignalKind::Logs,
        positron_domain::routing::VirtualShardId::new(7)?,
        protection::FrameObjectId::new([5; 16])?,
        protection::KeyEpoch::new(1),
        protection::FrameFormatEpoch::new(1)?,
    );
    let key = protection::ObjectDataKey::generate(object)?;
    let ciphertext = cache.wrap_object_key(context, &key)?;
    assert!(cache.open_object_key(context, &ciphertext, object).is_ok());
    Ok(())
}

#[test]
fn a_cold_cache_requires_the_real_wrap_unwrap_probe() -> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = ControlledLocal {
        inner: LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
            &root.path,
        )?)?,
        failure: std::cell::Cell::new(None),
        calls: std::cell::Cell::new(0),
        probe_failure: std::cell::Cell::new(None),
        wrap_failure: std::cell::Cell::new(None),
    };
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    provider
        .wrap_failure
        .set(Some(KeyProviderFailure::PermissionDenied));
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::default(),
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    assert_eq!(
        ready(cache.load(&envelope, context)),
        Err(KeyProviderFailure::PermissionDenied)
    );
    assert!(!cache.health().system_ready);
    assert_eq!(cache.resident_keys(), 0);
    Ok(())
}
#[test]
fn key_cache_lease_accepts_zero_and_defaults_to_fifteen_minutes() {
    use protection::key_provider::KeyCacheLease;
    use std::time::Duration;
    assert_eq!(
        KeyCacheLease::default().duration(),
        Duration::from_secs(900)
    );
    assert!(KeyCacheLease::new(Duration::ZERO).is_ok());
    assert!(KeyCacheLease::new(Duration::from_secs(3600)).is_ok());
    assert_eq!(
        KeyCacheLease::new(Duration::from_secs(3601)),
        Err(KeyProviderFailure::InvalidConfiguration)
    );
}

#[test]
fn valid_cached_kek_survives_outage_without_clearing_provider_degradation()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = ControlledLocal {
        inner: LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
            &root.path,
        )?)?,
        failure: std::cell::Cell::new(None),
        calls: std::cell::Cell::new(0),
        probe_failure: std::cell::Cell::new(None),
        wrap_failure: std::cell::Cell::new(None),
    };
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::default(),
        2,
        cache_reservation(&kernel, 2)?,
    )?;
    ready(cache.load(&envelope, context))?;
    let calls_before_outage = provider.calls.get();
    provider.failure.set(Some(KeyProviderFailure::Unavailable));
    assert_eq!(
        ready(cache.verify_live(context)),
        Err(KeyProviderFailure::Unavailable)
    );
    let object = protection::FrameObjectContext::system(
        protection::SystemObjectKind::Catalog,
        protection::FrameObjectId::new([5; 16])?,
        protection::KeyEpoch::new(1),
        protection::FrameFormatEpoch::new(1)?,
    );
    let key = protection::ObjectDataKey::generate(object)?;
    let wrapped = cache.wrap_object_key(context, &key)?;
    assert!(cache.open_object_key(context, &wrapped, object).is_ok());
    assert!(cache.health().provider_degraded);
    assert!(cache.health().system_ready);
    assert_eq!(provider.calls.get(), calls_before_outage);
    Ok(())
}

#[test]
fn zero_duration_cache_cannot_reopen_an_integrity_fenced_authority()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::new(std::time::Duration::ZERO)?,
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    assert_eq!(
        ready(cache.load(&envelope, wrong)),
        Err(KeyProviderFailure::ContextMismatch)
    );
    assert!(cache.health().storage_unhealthy);
    let object = protection::FrameObjectContext::system(
        protection::SystemObjectKind::Catalog,
        protection::FrameObjectId::new([5; 16])?,
        protection::KeyEpoch::new(1),
        protection::FrameFormatEpoch::new(1)?,
    );
    let key = protection::ObjectDataKey::generate(object)?;
    assert_eq!(
        ready(cache.wrap_object_key_live(&envelope, context, &key)),
        Err(KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}

#[test]
fn cached_leases_expire_exactly_and_release_governor_memory_on_drop()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{CacheInvalidation, KeyCacheLease, KeyProviderCache};
    use std::time::{Duration, Instant};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = ControlledLocal {
        inner: LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
            &root.path,
        )?)?,
        failure: std::cell::Cell::new(None),
        calls: std::cell::Cell::new(0),
        probe_failure: std::cell::Cell::new(None),
        wrap_failure: std::cell::Cell::new(None),
    };
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let kernel = cache_governor()?;
    let clock = std::cell::Cell::new(Instant::now());
    let start = clock.get();
    let reservation = cache_reservation(&kernel, 2)?;
    let granted = reservation
        .granted()
        .get(crate::ResourceDimension::MemoryBytes);
    let mut cache = KeyProviderCache::with_clock(
        &provider,
        KeyCacheLease::new(Duration::from_secs(10))?,
        2,
        reservation,
        || clock.get(),
    )?;
    ready(cache.load(&envelope, context))?;
    assert_eq!(
        kernel
            .governor()
            .inspect()?
            .usage(crate::ResourceDimension::MemoryBytes),
        granted
    );
    clock.set(start + Duration::from_secs(9));
    assert_eq!(cache.resident_keys(), 1);
    clock.set(start + Duration::from_secs(10));
    assert_eq!(cache.resident_keys(), 0);
    assert!(!cache.health().system_ready);
    provider.failure.set(Some(KeyProviderFailure::Unavailable));
    assert_eq!(
        ready(cache.load(&envelope, context)),
        Err(KeyProviderFailure::Unavailable)
    );
    assert!(cache.health().provider_degraded);
    provider.failure.set(None);
    ready(cache.load(&envelope, context))?;
    for cause in [
        CacheInvalidation::Rotation,
        CacheInvalidation::Revocation,
        CacheInvalidation::CredentialReload,
        CacheInvalidation::AdministrativePurge,
    ] {
        cache.invalidate(KeyScope::System, cause);
        assert_eq!(cache.resident_keys(), 0);
        ready(cache.load(&envelope, context))?;
    }
    drop(cache);
    assert_eq!(
        kernel
            .governor()
            .inspect()?
            .usage(crate::ResourceDimension::MemoryBytes),
        0
    );
    assert_eq!(
        kernel
            .governor()
            .inspect()?
            .usage(crate::ResourceDimension::LeaseSlots),
        0
    );
    Ok(())
}

#[test]
fn cache_memory_lock_failure_is_explicit_and_eviction_zeroizes_before_unlock()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{
        CacheInvalidation, KeyCacheLease, KeyProviderCache, observe_cache_release,
        with_cache_lock_failure,
    };
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::default(),
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    let failed = with_cache_lock_failure(|| ready(cache.load(&envelope, context)));
    assert_eq!(failed, Err(KeyProviderFailure::MemoryProtection));
    assert_eq!(cache.resident_keys(), 0);
    let (result, count, zeroized) = observe_cache_release(|| {
        ready(cache.load(&envelope, context))?;
        cache.invalidate(KeyScope::System, CacheInvalidation::AdministrativePurge);
        Ok::<_, KeyProviderFailure>(())
    });
    result?;
    assert_eq!(count, 1);
    assert!(zeroized);
    Ok(())
}

#[test]
fn rotation_can_establish_readiness_for_a_new_system_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{CacheInvalidation, KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(&root.path)?)?;
    let session = KeyProviderSession::new(&provider);
    let old = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let new = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let old_envelope = ready(session.wrap(SecretKek::generate()?, old))?;
    let new_envelope = ready(session.wrap(SecretKek::generate()?, new))?;
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::default(),
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    ready(cache.load(&old_envelope, old))?;
    assert!(cache.health().system_ready);
    cache.invalidate(KeyScope::System, CacheInvalidation::Rotation);
    ready(cache.load(&new_envelope, new))?;
    assert!(cache.health().system_ready);
    Ok(())
}

#[test]
fn zero_lease_success_verifies_system_readiness_without_retaining_keys()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::new(std::time::Duration::ZERO)?,
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    ready(cache.load(&envelope, context))?;
    assert_eq!(cache.resident_keys(), 0);
    assert!(cache.health().system_ready);
    Ok(())
}
#[test]
fn zero_lease_first_object_admission_requires_the_actual_wrap_probe()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = ControlledLocal {
        inner: LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
            &root.path,
        )?)?,
        failure: std::cell::Cell::new(None),
        calls: std::cell::Cell::new(0),
        probe_failure: std::cell::Cell::new(None),
        wrap_failure: std::cell::Cell::new(None),
    };
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    provider
        .wrap_failure
        .set(Some(KeyProviderFailure::PermissionDenied));
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::new(std::time::Duration::ZERO)?,
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    let object = protection::FrameObjectContext::system(
        protection::SystemObjectKind::Catalog,
        protection::FrameObjectId::new([5; 16])?,
        protection::KeyEpoch::new(1),
        protection::FrameFormatEpoch::new(1)?,
    );
    let key = protection::ObjectDataKey::generate(object)?;
    assert_eq!(
        ready(cache.wrap_object_key_live(&envelope, context, &key)).err(),
        Some(KeyProviderFailure::PermissionDenied)
    );
    provider.wrap_failure.set(None);
    assert!(ready(cache.wrap_object_key_live(&envelope, context, &key)).is_ok());
    cache.invalidate(
        KeyScope::System,
        protection::key_provider::CacheInvalidation::CredentialReload,
    );
    provider
        .wrap_failure
        .set(Some(KeyProviderFailure::PermissionDenied));
    assert_eq!(
        ready(cache.wrap_object_key_live(&envelope, context, &key)).err(),
        Some(KeyProviderFailure::PermissionDenied)
    );
    Ok(())
}

#[test]
fn zero_lease_opens_system_and_tenant_object_keys_live_and_fails_during_outage()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyCacheLease, KeyProviderCache};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = ControlledLocal {
        inner: LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
            &root.path,
        )?)?,
        failure: std::cell::Cell::new(None),
        calls: std::cell::Cell::new(0),
        probe_failure: std::cell::Cell::new(None),
        wrap_failure: std::cell::Cell::new(None),
    };
    let tenant = positron_domain::identity::TenantId::from_bytes([31; 16])?;
    let objects = [
        (
            KeyScope::System,
            protection::FrameObjectContext::system(
                protection::SystemObjectKind::Catalog,
                protection::FrameObjectId::new([5; 16])?,
                protection::KeyEpoch::new(1),
                protection::FrameFormatEpoch::new(1)?,
            ),
        ),
        (
            KeyScope::Tenant(tenant),
            protection::FrameObjectContext::tenant_segment(
                tenant,
                positron_domain::routing::SignalKind::Logs,
                positron_domain::routing::VirtualShardId::new(7)?,
                protection::FrameObjectId::new([6; 16])?,
                protection::KeyEpoch::new(1),
                protection::FrameFormatEpoch::new(1)?,
            ),
        ),
    ];
    let kernel = cache_governor()?;
    let mut cache = KeyProviderCache::new(
        &provider,
        KeyCacheLease::new(std::time::Duration::ZERO)?,
        1,
        cache_reservation(&kernel, 1)?,
    )?;
    for (scope, object) in objects {
        let context = EnvelopeContext::new([1; 16], scope, [2; 32], 1, 1)?;
        let envelope =
            ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
        let key = protection::ObjectDataKey::generate(object)?;
        let ciphertext = ready(cache.wrap_object_key_live(&envelope, context, &key))?;
        assert!(ready(cache.open_object_key_live(&envelope, context, &ciphertext, object)).is_ok());
        assert_eq!(cache.resident_keys(), 0);
        provider.failure.set(Some(KeyProviderFailure::Unavailable));
        assert_eq!(
            ready(cache.open_object_key_live(&envelope, context, &ciphertext, object)).err(),
            Some(KeyProviderFailure::Unavailable)
        );
        assert!(!cache.health().system_ready);
        provider.failure.set(None);
    }
    Ok(())
}
