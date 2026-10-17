//! Public Catalog fixture for Upgrade administration tests.
use super::*;
pub(super) struct Fixture {
    pub(super) _root: PagedCatalogRoot,
    pub(super) authority: StorageKernelResourceAuthority,
    pub(super) keys: BootstrapKeyCustody,
    pub(super) instance: positron_kernel::InstanceId,
    pub(super) actor: AuthorizedContext,
    pub(super) parameters: UpgradeParameters,
    pub(super) marker_id: [u8; 32],
    pub(super) registration_id: [u8; 32],
    pub(super) registration_row: positron_kernel::CatalogObjectId,
}
pub(super) fn fixture() -> Result<Fixture, Box<dyn Error>> {
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
    let integrity = keys.integrity_identity(&[0xeb; 32])?;
    let protected_integrity = keys.protect_instance_integrity_key(instance, &[0xeb; 32])?;
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
        integrity.public_key(),
        integrity.fingerprint(),
        protected_integrity,
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
    let actor = crate::Identity::open(&catalog.pin()?)
        .map_err(|error| format!("initial identity: {error}"))?
        .attribute(
            &keys,
            crate::PresentedCredential::parse(&format!("pos_{}", "e3".repeat(32)))?,
            crate::RequestedIntent::SystemAdministration,
            crate::CompatibilityHints::none(),
        )
        .map_err(|error| format!("attribute: {error}"))?;
    let repository = RepositoryOperationParameters::local(
        RepositoryAction::Verify,
        "/backup",
        [2; 16],
        [3; 32],
        [4; 32],
    )?;
    let registration = CatalogObject::new(b"upgrade repository".to_vec())?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|id| {
            CatalogObject::new(
                basis
                    .object(id)
                    .expect("object lookup")
                    .expect("object")
                    .to_vec(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let registration_row = registration.identity();
    let registration_id = registration_row.to_bytes();
    objects.push(registration);
    let marker = CatalogObject::new(b"authenticated Runtime final-marker fixture".to_vec())?;
    let marker_id = marker.identity().to_bytes();
    objects.push(marker);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([5; 16])?,
            positron_kernel::FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let backup = BackupSnapshotParameters::new(repository, 3600, registration_id)?;
    let source = UpgradeReleaseIdentity::new([6; 32], [7; 32], [0, 1, 0])?;
    let target = UpgradeReleaseIdentity::new([8; 32], [9; 32], [0, 1, 1])?;
    let parameters = UpgradeParameters::new(source, target, 1, [10; 32], backup)?;
    drop(catalog);
    Ok(Fixture {
        _root: root,
        authority,
        keys,
        instance,
        actor,
        parameters,
        registration_id,
        registration_row,
        marker_id,
    })
}
