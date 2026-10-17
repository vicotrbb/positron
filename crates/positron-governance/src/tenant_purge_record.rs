//! Minimal terminal tenant identity and immutable alias reservation evidence.
use super::*;
use positron_domain::identity::ExternalTenantAlias;
pub(super) struct PurgedTenantRecord {
    pub tenant: TenantId,
    pub slug: TenantSlug,
    pub generation: ResourceGeneration,
    pub proof: [u8; 32],
    pub alias: Option<ExternalTenantAlias>,
}
pub(super) fn decode(
    bytes: &[u8],
) -> Result<Option<PurgedTenantRecord>, TenantAdministrationFailure> {
    if !bytes.starts_with(b"POSTPT01") {
        return Ok(None);
    }
    let bad = || TenantAdministrationFailure::PersistenceUnavailable;
    let mut rest = bytes.get(8..).ok_or_else(bad)?;
    let mut take = |len: usize| -> Result<&[u8], TenantAdministrationFailure> {
        let (value, next) = rest.split_at_checked(len).ok_or_else(bad)?;
        rest = next;
        Ok(value)
    };
    let tenant =
        TenantId::from_bytes(take(16)?.try_into().map_err(|_| bad())?).map_err(|_| bad())?;
    let len = usize::from(*take(1)?.first().ok_or_else(bad)?);
    let slug = TenantSlug::parse_canonical(std::str::from_utf8(take(len)?).map_err(|_| bad())?)
        .map_err(|_| bad())?;
    let generation =
        ResourceGeneration::new(u64::from_be_bytes(take(8)?.try_into().map_err(|_| bad())?))
            .map_err(|_| bad())?;
    let proof = take(32)?.try_into().map_err(|_| bad())?;
    let len = usize::from(*take(1)?.first().ok_or_else(bad)?);
    let alias = if len == 0 {
        None
    } else {
        Some(
            ExternalTenantAlias::parse(std::str::from_utf8(take(len)?).map_err(|_| bad())?)
                .map_err(|_| bad())?,
        )
    };
    if !rest.is_empty() || proof == [0; 32] {
        return Err(bad());
    }
    Ok(Some(PurgedTenantRecord {
        tenant,
        slug,
        generation,
        proof,
        alias,
    }))
}
pub(super) fn encode(
    value: PurgedTenantRecord,
) -> Result<positron_kernel::CatalogObject, TenantAdministrationFailure> {
    let mut bytes = b"POSTPT01".to_vec();
    bytes.extend_from_slice(&value.tenant.to_bytes());
    bytes.push(value.slug.as_str().len() as u8);
    bytes.extend_from_slice(value.slug.as_str().as_bytes());
    bytes.extend_from_slice(&value.generation.get().to_be_bytes());
    bytes.extend_from_slice(&value.proof);
    match value.alias {
        Some(alias) => {
            bytes.push(alias.as_str().len() as u8);
            bytes.extend_from_slice(alias.as_str().as_bytes());
        },
        None => bytes.push(0),
    }
    positron_kernel::CatalogObject::new(bytes).map_err(map_catalog)
}
