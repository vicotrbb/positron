use super::*;
#[test]
fn restore_reserves_future_purged_tenant_identities_across_creation_and_migration()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PagedCatalogRoot::new()?;
    let instance = positron_kernel::InstanceId::new([0xe1; 16])?;
    let default_tenant = tenant(1)?;
    let authority = fixture_authority(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        default_tenant,
    )?;
    let keys = BootstrapKeyCustody::initialize(&root.secrets())?;
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let administrator = PrincipalId::from_bytes([0xe2; 16])?;
    let secret = [0xe3; 32];
    let salt = [0xe4; 32];
    let hash = keys.salted_secret_hash(&salt, &secret)?;
    let initial = crate::InitialGovernanceIntent::create_tenant(crate::InitialTenantIntent::new(
        instance.to_bytes(),
        default_tenant,
        TenantSlug::parse_canonical("default")?,
        "Default tenant",
        administrator,
        salt,
        hash,
        PrincipalId::from_bytes([0xe5; 16])?,
        [0xe6; 32],
        [0xe7; 32],
        PrincipalId::from_bytes([0xe8; 16])?,
        [0xe9; 32],
        [0xea; 32],
        [0xeb; 32],
        [0xec; 32],
        vec![0xed; 48],
        keys.tenant_key_envelope(instance, default_tenant)?,
        2_592_000,
        1,
        1,
        [16; 11],
        crate::InitialAuditContext::new(17, [0xee; 16], true)?,
    )?)?;
    let (governance, audit) = initial.into_parts();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xef; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance)?],
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    use crate::*;
    let basis = catalog.pin()?;
    let governance = basis.governance_object()?.0;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf0; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            vec![
                CatalogObject::new(basis.object(governance)?.ok_or("governance")?.to_vec())?,
                TenantAdministration::epoch_two_registry(&basis)?,
            ],
        )?,
        None,
    )?;
    let actor = Identity::open(&catalog.pin()?)?.attribute(
        &keys,
        PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let excluded = tenant(77)?;
    let exclusion = RestorePurgeExclusion::new(
        excluded,
        TenantSlug::parse_canonical("future-purged")?,
        [88; 32],
    )?;
    let basis = catalog.pin()?;
    let objects = TenantAdministration::apply_restore_purge_exclusions(&basis, &[exclusion])?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf1; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            objects,
        )?,
        None,
    )?;
    let request = |slug: &str,
                   key: u8,
                   identity|
     -> Result<TenantCreateCandidate, Box<dyn std::error::Error>> {
        Ok(TenantCreateRequest::new(
            actor,
            TenantCreateConfiguration::new(
                TenantSlug::parse_canonical(slug)?,
                "Restored tenant",
                60,
                1,
                [1; 11],
            ),
            AdministrativeIdempotencyKey::new([key; 16])?,
        )
        .with_generated_tenant(identity))
    };
    assert!(
        TenantAdministration::create(
            &catalog,
            &keys,
            instance,
            administrator,
            request("future-purged", 90, tenant(78)?)?
        )
        .is_err()
    );
    assert!(
        TenantAdministration::create(
            &catalog,
            &keys,
            instance,
            administrator,
            request("other-slug", 91, excluded)?
        )
        .is_err()
    );
    TenantAdministration::create(
        &catalog,
        &keys,
        instance,
        administrator,
        request("alive", 92, tenant(79)?)?,
    )?;
    assert!(
        TenantAdministration::create(
            &catalog,
            &keys,
            instance,
            administrator,
            request("future-purged", 93, tenant(80)?)?
        )
        .is_err()
    );
    let basis = catalog.pin()?;
    let mut objects = Vec::new();
    for id in basis.object_identities() {
        let bytes = basis.object(id)?.ok_or("object")?;
        if !is_registry(bytes) {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    objects.push(TenantAdministration::epoch_two_registry(&basis)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf2; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            objects,
        )?,
        None,
    )?;
    assert!(
        TenantAdministration::create(
            &catalog,
            &keys,
            instance,
            administrator,
            request("future-purged", 94, tenant(81)?)?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn restore_blocks_known_tenant_without_recovering_its_key_or_claiming_purge_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let root = PagedCatalogRoot::new()?;
    let instance = positron_kernel::InstanceId::new([0xe1; 16])?;
    let default_tenant = tenant(1)?;
    let authority = fixture_authority(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        default_tenant,
    )?;
    let keys = BootstrapKeyCustody::initialize(&root.secrets())?;
    let catalog = Catalog::open(&authority, instance, keys.catalog_secret(instance)?)?;
    let administrator = PrincipalId::from_bytes([0xe2; 16])?;
    let secret = [0xe3; 32];
    let salt = [0xe4; 32];
    let hash = keys.salted_secret_hash(&salt, &secret)?;
    let initial = crate::InitialGovernanceIntent::create_tenant(crate::InitialTenantIntent::new(
        instance.to_bytes(),
        default_tenant,
        TenantSlug::parse_canonical("default")?,
        "Default tenant",
        administrator,
        salt,
        hash,
        PrincipalId::from_bytes([0xe5; 16])?,
        [0xe6; 32],
        [0xe7; 32],
        PrincipalId::from_bytes([0xe8; 16])?,
        [0xe9; 32],
        [0xea; 32],
        [0xeb; 32],
        [0xec; 32],
        vec![0xed; 48],
        keys.tenant_key_envelope(instance, default_tenant)?,
        2_592_000,
        1,
        1,
        [16; 11],
        crate::InitialAuditContext::new(17, [0xee; 16], true)?,
    )?)?;
    let (governance, audit) = initial.into_parts();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xef; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance)?],
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    use crate::*;
    let basis = catalog.pin()?;
    let governance = basis.governance_object()?.0;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf0; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            vec![
                CatalogObject::new(basis.object(governance)?.ok_or("governance")?.to_vec())?,
                TenantAdministration::epoch_two_registry(&basis)?,
            ],
        )?,
        None,
    )?;
    let actor = Identity::open(&catalog.pin()?)?.attribute(
        &keys,
        PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let basis = catalog.pin()?;
    let (_, governance) = basis.governance_object()?;
    let original_envelope = governance.tenant_key_envelope().to_vec();
    let alias = positron_domain::identity::ExternalTenantAlias::parse("restore.default")?;
    let upgraded = governance.with_external_tenant_alias(alias.clone(), 2)?;
    let mut objects = vec![CatalogObject::new(upgraded)?];
    objects.push(TenantAdministration::epoch_two_registry(&basis)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf3; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            objects,
        )?,
        None,
    )?;
    let basis = catalog.pin()?;
    let exclusion = RestorePurgeExclusion::new(
        default_tenant,
        TenantSlug::parse_canonical("default")?,
        [88; 32],
    )?;
    let objects = TenantAdministration::apply_restore_purge_exclusions(&basis, &[exclusion])?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf4; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V2,
            objects,
        )?,
        None,
    )?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::inspect(&snapshot, default_tenant)?.lifecycle(),
        positron_domain::lifecycle::TenantLifecycleState::Purging
    );
    let (_, governance) = snapshot.governance_object()?;
    assert_eq!(governance.external_tenant_alias(), Some(alias));
    assert_ne!(governance.tenant_key_envelope(), original_envelope);
    assert!(
        keys.backup_tenant_key_identity(instance, default_tenant, governance.tenant_key_envelope())
            .is_err()
    );
    assert!(TenantAdministration::restore_catalog_objects(&snapshot, &keys, &[]).is_ok());
    assert!(
        TenantAdministration::restore_catalog_objects(
            &snapshot,
            &keys,
            &[(default_tenant, original_envelope)]
        )
        .is_err()
    );
    assert_eq!(
        Identity::open(&snapshot)?
            .attribute(
                &keys,
                PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
                RequestedIntent::SystemAdministration,
                CompatibilityHints::none()
            )?
            .principal_id(),
        actor.principal_id()
    );
    Ok(())
}
