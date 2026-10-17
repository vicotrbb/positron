//! Restore exclusions extend the existing immutable identity-reservation authority.
use super::tenant_administration_registry_codec::{
    is_registry, registry, registry_object_with_reservations,
};
use super::*;
use positron_kernel::{CatalogObject, CatalogSnapshot};
const MAX_EXCLUSIONS: usize = 4096;
/// Runtime supplies this only after Backup verifies the current signed Registry
/// and tombstone. It records restoration exclusion, not remote key destruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePurgeExclusion {
    tenant: TenantId,
    slug: TenantSlug,
    proof: [u8; 32],
    authorization: Option<([u8; 16], u64)>,
}
impl RestorePurgeExclusion {
    pub fn new(
        tenant: TenantId,
        slug: TenantSlug,
        proof: [u8; 32],
    ) -> Result<Self, TenantAdministrationFailure> {
        if proof == [0; 32] {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        Ok(Self {
            tenant,
            slug,
            proof,
            authorization: None,
        })
    }
    pub fn with_authorization(
        mut self,
        operation: [u8; 16],
        accepted_at: u64,
    ) -> Result<Self, TenantAdministrationFailure> {
        if operation == [0; 16] || accepted_at == 0 {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        self.authorization = Some((operation, accepted_at));
        Ok(self)
    }
    pub fn operation_id(&self) -> Option<[u8; 16]> {
        self.authorization.map(|value| value.0)
    }
    pub fn accepted_at_unix_seconds(&self) -> Option<u64> {
        self.authorization.map(|value| value.1)
    }
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.proof
    }
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    pub fn slug(&self) -> &str {
        self.slug.as_str()
    }
}
impl TenantAdministration {
    /// The canonical exclusion inventory persisted by an earlier restore plan.
    pub fn restore_purge_exclusions(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<RestorePurgeExclusion>, TenantAdministrationFailure> {
        Ok(registry(snapshot)?.map_or_else(Vec::new, |registry| registry.reserved))
    }
    pub fn restore_key_tenant_ids(
        snapshot: &CatalogSnapshot,
    ) -> Result<Vec<TenantId>, TenantAdministrationFailure> {
        let mut tenants = Self::registered_tenant_ids(snapshot)?;
        if let Some(registry) = registry(snapshot)? {
            tenants.retain(|tenant| {
                !registry
                    .reserved
                    .iter()
                    .any(|excluded| excluded.tenant == *tenant)
            });
        }
        Ok(tenants)
    }
    pub fn apply_restore_purge_exclusions(
        snapshot: &CatalogSnapshot,
        exclusions: &[RestorePurgeExclusion],
    ) -> Result<Vec<CatalogObject>, TenantAdministrationFailure> {
        if exclusions.len() > MAX_EXCLUSIONS {
            return Err(TenantAdministrationFailure::InvalidInput);
        }
        let inspections = Self::list(snapshot)?;
        let (governance_id, governance) = snapshot.governance_object().map_err(map_catalog)?;
        let mut registry =
            registry(snapshot)?.ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        for exclusion in exclusions {
            if inspections.iter().any(|tenant| {
                (tenant.tenant_id() == exclusion.tenant && tenant.slug() != exclusion.slug())
                    || (tenant.tenant_id() != exclusion.tenant && tenant.slug() == exclusion.slug())
            }) {
                return Err(TenantAdministrationFailure::InvalidInput);
            }
            if let Some(existing) = registry.reserved.iter_mut().find(|existing| {
                existing.tenant == exclusion.tenant || existing.slug == exclusion.slug
            }) {
                if existing.tenant != exclusion.tenant || existing.slug != exclusion.slug {
                    return Err(TenantAdministrationFailure::InvalidInput);
                }
                if existing.authorization.is_none() {
                    existing.authorization = exclusion.authorization;
                }
            } else {
                if registry.reserved.len() >= MAX_EXCLUSIONS {
                    return Err(TenantAdministrationFailure::InvalidInput);
                }
                registry
                    .reserved
                    .try_reserve_exact(1)
                    .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
                registry.reserved.push(exclusion.clone());
            }
        }
        registry
            .reserved
            .sort_by_key(RestorePurgeExclusion::tenant_id);
        let generation = ResourceGeneration::new(
            registry
                .generation
                .get()
                .checked_add(1)
                .ok_or(TenantAdministrationFailure::InvalidInput)?,
        )
        .map_err(|_| TenantAdministrationFailure::InvalidInput)?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        for id in snapshot.object_identities() {
            let bytes = snapshot
                .object(id)
                .map_err(map_catalog)?
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
            if is_registry(bytes) {
                continue;
            }
            let excluded = if id == governance_id {
                registry
                    .reserved
                    .iter()
                    .find(|value| value.tenant == governance.tenant())
            } else if crate::tenant_quota_record::is_tenant_record(bytes) {
                let record = crate::tenant_quota_record::tenant_record_metadata(bytes)?;
                registry
                    .reserved
                    .iter()
                    .find(|value| value.tenant == record.tenant)
            } else {
                None
            };
            let restored = if let Some(exclusion) = excluded {
                let mut marker = b"POSBPD01".to_vec();
                marker.extend_from_slice(&exclusion.tenant.to_bytes());
                marker.extend_from_slice(&exclusion.proof);
                if id == governance_id
                    && governance.lifecycle()
                        == positron_domain::lifecycle::TenantLifecycleState::Purged
                    && governance.tenant_key_envelope().is_empty()
                {
                    bytes.to_vec()
                } else if id == governance_id {
                    let state = if governance.lifecycle()
                        == positron_domain::lifecycle::TenantLifecycleState::Purged
                    {
                        governance.lifecycle()
                    } else {
                        positron_domain::lifecycle::TenantLifecycleState::Purging
                    };
                    let generation = if state == governance.lifecycle() {
                        governance.lifecycle_generation()
                    } else {
                        governance
                            .lifecycle_generation()
                            .checked_add(1)
                            .ok_or(TenantAdministrationFailure::InvalidInput)?
                    };
                    let encoded = governance
                        .with_lifecycle(state, generation)
                        .map_err(map_catalog)?;
                    positron_kernel::CatalogGovernanceObject::decode(&encoded)
                        .map_err(map_catalog)?
                        .with_tenant_key_envelope(&marker)
                        .map_err(map_catalog)?
                } else {
                    crate::tenant_quota_record::restore_excluded_record(bytes, &marker)?
                }
            } else {
                bytes.to_vec()
            };
            objects.push(CatalogObject::new(restored).map_err(map_catalog)?);
        }
        objects.push(registry_object_with_reservations(
            positron_kernel::InstanceId::new(governance.instance()).map_err(map_catalog)?,
            generation,
            &registry.tenants,
            &registry.reserved,
        )?);
        Ok(objects)
    }
}
pub(super) fn encode_reservations(
    values: &[RestorePurgeExclusion],
    bytes: &mut Vec<u8>,
    authorization: bool,
) -> Result<(), TenantAdministrationFailure> {
    if values.len() > MAX_EXCLUSIONS {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    bytes.extend_from_slice(&(values.len() as u16).to_be_bytes());
    for value in values {
        bytes.extend_from_slice(&value.tenant.to_bytes());
        bytes.push(value.slug().len() as u8);
        bytes.extend_from_slice(value.slug().as_bytes());
        bytes.extend_from_slice(&value.proof);
        if authorization {
            match value.authorization {
                Some((operation, accepted)) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&operation);
                    bytes.extend_from_slice(&accepted.to_be_bytes());
                },
                None => bytes.push(0),
            }
        }
    }
    Ok(())
}
pub(super) fn reservation_tail(
    bytes: &[u8],
    start: usize,
) -> Result<usize, TenantAdministrationFailure> {
    let mut cursor = Cursor(
        bytes
            .get(start..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let count = usize::from(u16::from_be_bytes(cursor.array()?));
    if count == 0 || count > MAX_EXCLUSIONS {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    for _ in 0..count {
        TenantId::from_bytes(cursor.array()?)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let length = usize::from(
            *cursor
                .take(1)?
                .first()
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        );
        TenantSlug::parse_canonical(
            std::str::from_utf8(cursor.take(length)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        if cursor.array::<32>()? == [0; 32] {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        if bytes.starts_with(b"POSTRG04") {
            cursor.authorization()?;
        }
    }
    if !cursor.0.is_empty() {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    Ok(count)
}
pub(super) fn decode_reservations(
    bytes: &[u8],
    start: usize,
) -> Result<Vec<RestorePurgeExclusion>, TenantAdministrationFailure> {
    let count = reservation_tail(bytes, start)?;
    let mut cursor = Cursor(
        bytes
            .get(start + 2..)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
    );
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    for _ in 0..count {
        let tenant = TenantId::from_bytes(cursor.array()?)
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let length = usize::from(
            *cursor
                .take(1)?
                .first()
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
        );
        let slug = TenantSlug::parse_canonical(
            std::str::from_utf8(cursor.take(length)?)
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        let proof = cursor.array()?;
        let authorization = if bytes.starts_with(b"POSTRG04") {
            cursor.authorization()?
        } else {
            None
        };
        if values
            .last()
            .is_some_and(|last: &RestorePurgeExclusion| last.tenant >= tenant)
            || values
                .iter()
                .any(|last: &RestorePurgeExclusion| last.slug == slug)
        {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        values.push(RestorePurgeExclusion {
            tenant,
            slug,
            proof,
            authorization,
        });
    }
    Ok(values)
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TenantAdministrationFailure> {
        let (value, rest) = self
            .0
            .split_at_checked(n)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        self.0 = rest;
        Ok(value)
    }
    fn authorization(&mut self) -> Result<Option<([u8; 16], u64)>, TenantAdministrationFailure> {
        match self.array::<1>()? {
            [0] => Ok(None),
            [1] => {
                let operation = self.array()?;
                let accepted = u64::from_be_bytes(self.array()?);
                if operation == [0; 16] || accepted == 0 {
                    return Err(TenantAdministrationFailure::PersistenceUnavailable);
                }
                Ok(Some((operation, accepted)))
            },
            _ => Err(TenantAdministrationFailure::PersistenceUnavailable),
        }
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], TenantAdministrationFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)
    }
}
