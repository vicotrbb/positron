use super::*;
#[test]
fn admitted_provider_integrity_failure_publishes_a_durable_governance_record()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::*;
    let storage = protection::local_key::test_support::SecurityRoot::create()?;
    let volume = PrimaryDataVolume::acquire(&storage.path, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        volume, 70_000_001, 2_000_000,
    )?;
    let instance = InstanceId::new([1; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([11; 32]), Box::new([12; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([3; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"preserved catalog authority".to_vec())?],
        )?,
        None,
    )?;
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let foreign = cache_governor()?;
    let refused = protection::DataProtection::provider(
        &provider,
        protection::key_provider::KeyCacheLease::default(),
        1,
        cache_reservation(&foreign, 1)?,
        &catalog,
    )
    .err()
    .ok_or("foreign governor authority accepted")?;
    assert_eq!(
        refused.provider_failure(),
        KeyProviderFailure::InvalidConfiguration
    );
    let reservation =
        authority
            .governor()
            .reserve(WorkClaim::system_maintenance(ResourceAmounts::new([
            protection::key_provider::KeyProviderCache::<LocalKeyProvider>::required_memory_bytes(
                1,
            )?,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ]))?)?;
    let mut owner = protection::DataProtection::provider(
        &provider,
        protection::key_provider::KeyCacheLease::default(),
        1,
        reservation,
        &catalog,
    )?;
    ready(owner.verify_live(context))?;
    ready(owner.load(&envelope, context))?;
    let object = protection::FrameObjectContext::system(
        protection::SystemObjectKind::Catalog,
        protection::FrameObjectId::new([5; 16])?,
        protection::KeyEpoch::new(1),
        protection::FrameFormatEpoch::new(1)?,
    );
    let key = protection::ObjectDataKey::generate(object)?;
    let ciphertext = ready(owner.wrap_object_key(&envelope, context, &key))?;
    assert!(ready(owner.open_object_key(&envelope, context, &ciphertext, object)).is_ok());
    owner.invalidate(
        KeyScope::System,
        protection::key_provider::CacheInvalidation::Rotation,
    );
    ready(owner.load(&envelope, context))?;
    let failure = ready(owner.load(&envelope, wrong))
        .err()
        .ok_or("integrity mismatch admitted")?;
    assert!(owner.health().storage_unhealthy);
    assert_eq!(
        failure.provider_failure(),
        KeyProviderFailure::ContextMismatch
    );
    assert_eq!(failure.audit_position(), Some(1));
    assert_eq!(
        ready(owner.load(&envelope, wrong))
            .err()
            .and_then(|failure| failure.audit_position()),
        Some(1)
    );
    let records = catalog.governance_audit_records()?;
    assert_eq!(records.len(), 1);
    assert!(
        records
            .first()
            .is_some_and(|record| record.intent().starts_with(b"PKEYAUD1"))
    );
    drop(owner);
    drop(catalog);
    let reopened = Catalog::open(&authority, instance, secret())?;
    assert_eq!(reopened.governance_audit_records()?.len(), 1);
    assert_eq!(reopened.pin()?.object_count(), 1);
    Ok(())
}

#[test]
fn failed_governance_publication_is_explicit_and_does_not_unfence_keys()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::*;
    let storage = protection::local_key::test_support::SecurityRoot::create()?;
    let volume = PrimaryDataVolume::acquire(&storage.path, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        volume, 70_000_001, 2_000_000,
    )?;
    let instance = InstanceId::new([1; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([11; 32]), Box::new([12; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([3; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"preserved catalog authority".to_vec())?],
        )?,
        None,
    )?;
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let reservation =
        authority
            .governor()
            .reserve(WorkClaim::system_maintenance(ResourceAmounts::new([
            protection::key_provider::KeyProviderCache::<LocalKeyProvider>::required_memory_bytes(
                1,
            )?,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ]))?)?;
    let mut owner = protection::DataProtection::provider(
        &provider,
        protection::key_provider::KeyCacheLease::default(),
        1,
        reservation,
        &catalog,
    )?;
    let result =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteAudit, || {
            ready(owner.load(&envelope, wrong))
        });
    let failure = result.err().ok_or("corrupt envelope admitted")?;
    assert_eq!(
        failure.provider_failure(),
        KeyProviderFailure::ContextMismatch
    );
    assert_eq!(
        failure.audit_failure(),
        Some(CatalogFailureCode::StorageUnavailable)
    );
    assert_eq!(failure.audit_position(), None);
    assert!(owner.health().storage_unhealthy);
    assert!(catalog.governance_audit_records()?.is_empty());
    let retry = ready(owner.load(&envelope, context))
        .err()
        .ok_or("fenced owner reopened")?;
    assert_eq!(
        retry.audit_failure(),
        Some(CatalogFailureCode::StorageUnavailable)
    );
    assert!(catalog.governance_audit_records()?.is_empty());
    Ok(())
}

#[test]
fn an_uninitialized_catalog_does_not_claim_a_durable_integrity_record()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::*;
    let storage = protection::local_key::test_support::SecurityRoot::create()?;
    let volume = PrimaryDataVolume::acquire(&storage.path, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        volume, 70_000_001, 2_000_000,
    )?;
    let instance = InstanceId::new([1; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([11; 32]), Box::new([12; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let foreign = cache_governor()?;
    let refused = protection::DataProtection::provider(
        &provider,
        protection::key_provider::KeyCacheLease::default(),
        1,
        cache_reservation(&foreign, 1)?,
        &catalog,
    )
    .err()
    .ok_or("foreign governor authority accepted")?;
    assert_eq!(
        refused.provider_failure(),
        KeyProviderFailure::InvalidConfiguration
    );
    let reservation =
        authority
            .governor()
            .reserve(WorkClaim::system_maintenance(ResourceAmounts::new([
            protection::key_provider::KeyProviderCache::<LocalKeyProvider>::required_memory_bytes(
                1,
            )?,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ]))?)?;
    let mut owner = protection::DataProtection::provider(
        &provider,
        protection::key_provider::KeyCacheLease::default(),
        1,
        reservation,
        &catalog,
    )?;
    let foreign_context = EnvelopeContext::new([9; 16], KeyScope::System, [2; 32], 1, 1)?;
    let failure = ready(owner.load(&envelope, foreign_context))
        .err()
        .ok_or("cross-instance envelope admitted")?;
    assert_eq!(
        failure.provider_failure(),
        KeyProviderFailure::ContextMismatch
    );
    assert_eq!(
        failure.audit_failure(),
        Some(CatalogFailureCode::InvalidInput)
    );
    assert_eq!(failure.audit_position(), None);
    assert!(owner.health().storage_unhealthy);
    assert!(catalog.governance_audit_records()?.is_empty());
    assert_eq!(catalog.pin()?.format_epoch(), None);
    Ok(())
}

#[test]
fn provider_integrity_publication_refuses_unreserved_catalog_copies()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::*;
    let storage = protection::local_key::test_support::SecurityRoot::create()?;
    let volume = PrimaryDataVolume::acquire(&storage.path, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority_with_pool_units(
        volume, 70_000_001, 2_000_000,
    )?;
    let instance = InstanceId::new([1; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([11; 32]), Box::new([12; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([3; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"preserved catalog authority".to_vec())?],
        )?,
        None,
    )?;
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context))?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    let foreign = cache_governor()?;
    let refused = protection::DataProtection::provider(
        &provider,
        protection::key_provider::KeyCacheLease::default(),
        1,
        cache_reservation(&foreign, 1)?,
        &catalog,
    )
    .err()
    .ok_or("foreign governor authority accepted")?;
    assert_eq!(
        refused.provider_failure(),
        KeyProviderFailure::InvalidConfiguration
    );
    let reservation =
        authority
            .governor()
            .reserve(WorkClaim::system_maintenance(ResourceAmounts::new([
            protection::key_provider::KeyProviderCache::<LocalKeyProvider>::required_memory_bytes(
                1,
            )?,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ]))?)?;
    let mut owner = protection::DataProtection::provider(
        &provider,
        protection::key_provider::KeyCacheLease::default(),
        1,
        reservation,
        &catalog,
    )?;
    let capacity = authority.governor().inspect()?;
    let memory = ResourceDimension::MemoryBytes;
    let available = capacity.pool_capacity(OrdinaryPool::Shared, memory)
        + capacity.pool_capacity(OrdinaryPool::OrdinaryMaintenanceBackup, memory)
        - capacity.pool_usage(OrdinaryPool::OrdinaryMaintenanceBackup, memory)
        - capacity.pool_usage(OrdinaryPool::Shared, memory);
    let blocker =
        authority
            .governor()
            .reserve(WorkClaim::system_maintenance(ResourceAmounts::new([
                available, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]))?)?;
    let before = authority
        .governor()
        .inspect()?
        .usage(ResourceDimension::MemoryBytes);
    let failure = ready(owner.load(&envelope, wrong))
        .err()
        .ok_or("corrupt key admitted")?;
    assert_eq!(
        failure.provider_failure(),
        KeyProviderFailure::ContextMismatch
    );
    assert_eq!(
        failure.audit_failure(),
        Some(CatalogFailureCode::ResourceAdmissionRefused)
    );
    assert_eq!(failure.audit_position(), None);
    assert!(owner.health().storage_unhealthy);
    assert!(catalog.governance_audit_records()?.is_empty());
    assert_eq!(catalog.pin()?.number(), 1);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        before
    );
    drop(blocker);
    Ok(())
}
