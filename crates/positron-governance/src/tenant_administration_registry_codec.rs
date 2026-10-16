use std::collections::BTreeSet;

use positron_domain::identity::TenantId;
use positron_kernel::{CatalogObject, CatalogSnapshot};

use super::{TenantAdministrationFailure, generation_at, map_catalog};
use crate::ResourceGeneration;

const TENANT_REGISTRY_V1_MAGIC: [u8; 8] = *b"POSTRG01";
const TENANT_REGISTRY_V3_MAGIC: [u8; 8] = *b"POSTRG03";
pub(super) const TENANT_REGISTRY_V2_MAGIC: [u8; 8] = *b"POSTRG02";

pub(super) struct TenantRegistry {
    pub(super) generation: ResourceGeneration,
    pub(super) tenants: Vec<TenantId>,
    pub(super) reserved: Vec<super::RestorePurgeExclusion>,
}

pub(crate) fn is_registry(bytes: &[u8]) -> bool {
    bytes.starts_with(&TENANT_REGISTRY_V1_MAGIC)
        || bytes.starts_with(&TENANT_REGISTRY_V2_MAGIC)
        || bytes.starts_with(&TENANT_REGISTRY_V3_MAGIC)
}

pub(super) fn registry(
    snapshot: &CatalogSnapshot,
) -> Result<Option<TenantRegistry>, TenantAdministrationFailure> {
    let mut found = None;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        if is_registry(bytes) {
            if found.is_some() {
                return Err(TenantAdministrationFailure::PersistenceUnavailable);
            }
            found = Some(decode_registry(bytes)?);
        }
    }
    Ok(found)
}

pub(crate) fn registry_count(
    bytes: &[u8],
    maximum_objects: usize,
) -> Result<usize, TenantAdministrationFailure> {
    generation_at(bytes, 24)?;
    if bytes.starts_with(&TENANT_REGISTRY_V1_MAGIC) {
        return if bytes.len() == 32 {
            Ok(0)
        } else {
            Err(TenantAdministrationFailure::PersistenceUnavailable)
        };
    }
    if !bytes.starts_with(&TENANT_REGISTRY_V2_MAGIC)
        && !bytes.starts_with(&TENANT_REGISTRY_V3_MAGIC)
    {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    let count = usize::from(u16::from_be_bytes(
        bytes
            .get(32..34)
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
            .try_into()
            .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
    ));
    let expected = count
        .checked_mul(16)
        .and_then(|n| n.checked_add(34))
        .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
    let valid_length = if bytes.starts_with(&TENANT_REGISTRY_V3_MAGIC) {
        super::tenant_restore::reservation_tail(bytes, expected).is_ok()
    } else {
        bytes.len() == expected
    };
    if count == 0 || count > maximum_objects || !valid_length {
        return Err(TenantAdministrationFailure::PersistenceUnavailable);
    }
    Ok(count)
}

pub(super) fn decode_registry(bytes: &[u8]) -> Result<TenantRegistry, TenantAdministrationFailure> {
    let generation = generation_at(bytes, 24)?;
    if bytes.starts_with(&TENANT_REGISTRY_V1_MAGIC) {
        if bytes.len() != 32 {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        return Ok(TenantRegistry {
            generation,
            tenants: Vec::new(),
            reserved: Vec::new(),
        });
    }
    let count = registry_count(bytes, usize::MAX)?;
    let mut tenants = Vec::new();
    tenants
        .try_reserve(count)
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
    let mut unique = BTreeSet::new();
    for index in 0..count {
        let offset = 34_usize
            .checked_add(
                index
                    .checked_mul(16)
                    .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?,
            )
            .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?;
        let tenant = TenantId::from_bytes(
            bytes
                .get(offset..offset + 16)
                .ok_or(TenantAdministrationFailure::PersistenceUnavailable)?
                .try_into()
                .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| TenantAdministrationFailure::PersistenceUnavailable)?;
        if !unique.insert(tenant) {
            return Err(TenantAdministrationFailure::PersistenceUnavailable);
        }
        tenants.push(tenant);
    }
    let reserved = if bytes.starts_with(&TENANT_REGISTRY_V3_MAGIC) {
        super::tenant_restore::decode_reservations(bytes, 34 + count * 16)?
    } else {
        Vec::new()
    };
    Ok(TenantRegistry {
        generation,
        tenants,
        reserved,
    })
}

pub(super) fn registry_object(
    instance: positron_kernel::InstanceId,
    generation: ResourceGeneration,
    tenants: &[TenantId],
) -> Result<CatalogObject, TenantAdministrationFailure> {
    registry_object_with_reservations(instance, generation, tenants, &[])
}

pub(super) fn registry_object_with_reservations(
    instance: positron_kernel::InstanceId,
    generation: ResourceGeneration,
    tenants: &[TenantId],
    reserved: &[super::RestorePurgeExclusion],
) -> Result<CatalogObject, TenantAdministrationFailure> {
    if tenants.is_empty() || tenants.len() > u16::MAX as usize {
        return Err(TenantAdministrationFailure::InvalidInput);
    }
    let mut encoded = Vec::with_capacity(34 + tenants.len() * 16);
    encoded.extend_from_slice(if reserved.is_empty() {
        &TENANT_REGISTRY_V2_MAGIC
    } else {
        &TENANT_REGISTRY_V3_MAGIC
    });
    encoded.extend_from_slice(&instance.to_bytes());
    encoded.extend_from_slice(&generation.get().to_be_bytes());
    encoded.extend_from_slice(&(tenants.len() as u16).to_be_bytes());
    for tenant in tenants {
        encoded.extend_from_slice(&tenant.to_bytes());
    }
    if !reserved.is_empty() {
        super::tenant_restore::encode_reservations(reserved, &mut encoded)?;
    }
    CatalogObject::new(encoded).map_err(map_catalog)
}

/// Valid v3 reservations reach bounded decoding before hostile mutations.
#[cfg(fuzzing)]
pub(crate) fn fuzz_registry(data: &[u8]) {
    let _ = decode_registry(data);
    let tenant = TenantId::from_bytes([0x41; 16]).expect("fuzz tenant");
    let exclusion = super::RestorePurgeExclusion::new(
        tenant,
        positron_domain::identity::TenantSlug::parse_canonical("purged").expect("slug"),
        [0x42; 32],
    )
    .expect("exclusion");
    let mut bytes = TENANT_REGISTRY_V3_MAGIC.to_vec();
    bytes.extend_from_slice(&[0x43; 16]);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&tenant.to_bytes());
    super::tenant_restore::encode_reservations(&[exclusion], &mut bytes)
        .expect("v3 reservation seed");
    let decoded = decode_registry(&bytes).expect("valid v3 registry");
    assert_eq!(decoded.reserved.len(), 1);
    for mutation in data.chunks(3).take(64) {
        if let [high, low, value] = mutation {
            let position = usize::from(u16::from_be_bytes([*high, *low])) % bytes.len();
            if let Some(byte) = bytes.get_mut(position) {
                *byte ^= value;
            }
        }
    }
    let _ = decode_registry(&bytes);
    let _ = decode_registry(&bytes[..bytes.len().saturating_sub(1)]);
}
