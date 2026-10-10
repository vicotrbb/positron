use super::*;
impl CatalogGovernanceObject {
    /// Replaces only the bounded opaque tenant envelope; caller verifies its custody context.
    pub fn with_tenant_key_envelope(&self, envelope: &[u8]) -> Result<Vec<u8>, CatalogFailure> {
        if envelope.is_empty() || envelope.len() > 16_384 {
            return Err(corrupt());
        }
        let length_at = self
            .retention_offset
            .checked_sub(self.tenant_key_envelope.len())
            .and_then(|offset| offset.checked_sub(2))
            .ok_or_else(corrupt)?;
        let prefix = &self.credential_prefix;
        let mut successor = Vec::new();
        successor
            .try_reserve_exact(
                prefix
                    .len()
                    .checked_sub(self.tenant_key_envelope.len())
                    .and_then(|length| length.checked_add(envelope.len()))
                    .ok_or_else(corrupt)?,
            )
            .map_err(|_| corrupt())?;
        successor.extend_from_slice(prefix.get(..length_at).ok_or_else(corrupt)?);
        successor.extend_from_slice(
            &u16::try_from(envelope.len())
                .map_err(|_| corrupt())?
                .to_be_bytes(),
        );
        successor.extend_from_slice(envelope);
        successor.extend_from_slice(prefix.get(self.retention_offset..).ok_or_else(corrupt)?);
        encode_credentials(&successor, self.credential_generation, &self.credentials)
    }
}
