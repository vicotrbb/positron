//! Terminal default-tenant identity alongside the surviving instance authority.
use super::*;
const MAGIC: &[u8; 8] = b"POSGOV09";
impl CatalogGovernanceObject {
    pub fn with_purged_tenant(
        &self,
        generation: u64,
        proof: [u8; 32],
    ) -> Result<Vec<u8>, CatalogFailure> {
        if self.lifecycle != TenantLifecycleState::Purging || generation == 0 || proof == [0; 32] {
            return Err(corrupt());
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&self.instance);
        bytes.extend_from_slice(&self.tenant.to_bytes());
        bytes.push(self.tenant_slug.as_str().len() as u8);
        bytes.extend_from_slice(self.tenant_slug.as_str().as_bytes());
        match &self.external_alias {
            Some(alias) => {
                bytes.push(alias.as_str().len() as u8);
                bytes.extend_from_slice(alias.as_str().as_bytes());
            },
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.alias_generation.to_be_bytes());
        bytes.extend_from_slice(&generation.to_be_bytes());
        bytes.extend_from_slice(&proof);
        bytes.extend_from_slice(&self.integrity_public_key);
        bytes.extend_from_slice(&self.integrity_key_fingerprint);
        bytes.extend_from_slice(&(self.protected_integrity_key.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.protected_integrity_key);
        let credentials = self
            .credentials
            .iter()
            .copied()
            .filter(|value| value.scope == 4)
            .collect::<Vec<_>>();
        encode_credentials(&bytes, self.credential_generation, &credentials)
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<CatalogGovernanceObject, CatalogFailure> {
    let mut cursor = codec::Cursor::new(bytes);
    if cursor.take_array::<8>()? != *MAGIC {
        return Err(corrupt());
    }
    let instance = cursor.take_array::<16>()?;
    codec::require_nonzero(instance)?;
    let tenant = TenantId::from_bytes(cursor.take_array::<16>()?).map_err(|_| corrupt())?;
    let tenant_slug =
        TenantSlug::parse_canonical(cursor.take_text_u8(63)?).map_err(|_| corrupt())?;
    let external_alias = match cursor.take_text_u8(128)? {
        "" => None,
        value => Some(ExternalTenantAlias::parse(value).map_err(|_| corrupt())?),
    };
    let alias_generation = cursor.take_u64()?;
    if alias_generation == 0 {
        return Err(corrupt());
    }
    let lifecycle_generation = cursor.take_u64()?;
    let proof = cursor.take_array::<32>()?;
    if lifecycle_generation == 0 || proof == [0; 32] {
        return Err(corrupt());
    }
    let integrity_public_key = cursor.take_array::<32>()?;
    codec::require_nonzero(integrity_public_key)?;
    let integrity_key_fingerprint = cursor.take_array::<32>()?;
    codec::require_nonzero(integrity_key_fingerprint)?;
    let protected_integrity_key = cursor.take_u16_bytes()?.to_vec();
    if protected_integrity_key.is_empty() {
        return Err(corrupt());
    }
    let prefix_end = bytes
        .len()
        .checked_sub(cursor.remaining.len())
        .ok_or_else(corrupt)?;
    let credential_generation = cursor.take_u64()?;
    if credential_generation == 0 || cursor.take_u16()? != 1 {
        return Err(corrupt());
    }
    let principal = PrincipalId::from_bytes(cursor.take_array::<16>()?).map_err(|_| corrupt())?;
    if cursor.take_u8()? != 4 {
        return Err(corrupt());
    }
    let active = match cursor.take_u8()? {
        0 => false,
        1 => true,
        _ => return Err(corrupt()),
    };
    let expiry = cursor.take_u64()?;
    let salt = cursor.take_array::<32>()?;
    let hash = cursor.take_array::<32>()?;
    if !cursor.is_empty() {
        return Err(corrupt());
    }
    let credential = CatalogCredential::new(
        principal,
        4,
        active,
        (expiry != 0).then_some(expiry),
        salt,
        hash,
    )?;
    Ok(CatalogGovernanceObject {
        version: CatalogGovernanceVersion::V9,
        instance,
        tenant,
        tenant_slug,
        external_alias,
        // Tenant profile fields are absent in V9. Public profile accessors
        // return None; these zeroed codec offsets never authorize a mutation.
        display_name: String::new(),
        principal,
        salt,
        hash,
        ingest: None,
        query: None,
        retention_seconds: 0,
        retention_offset: 0,
        quota_generation: 0,
        quota_weight: 0,
        quota_resources: [0; 11],
        quota_offset: 0,
        integrity_public_key,
        integrity_key_fingerprint,
        protected_integrity_key,
        tenant_key_envelope: Vec::new(),
        lifecycle: TenantLifecycleState::Purged,
        #[cfg(feature = "test-support")]
        lifecycle_end: 0,
        lifecycle_generation,
        display_generation: 0,
        retention_generation: 0,
        alias_generation,
        credentials: vec![credential],
        credential_generation,
        credential_prefix: bytes.get(..prefix_end).ok_or_else(corrupt)?.to_vec(),
    })
}
