use super::object::{open_object, wrap_object};
use super::*;
impl<P: KeyProvider, C: Fn() -> Instant> KeyProviderCache<'_, P, C> {
    /// Wraps a segment or system-object DEK. No KEK escapes the lease authority.
    pub(crate) fn wrap_object_key(
        &mut self,
        parent: EnvelopeContext,
        key: &crate::data_protection::ObjectDataKey,
    ) -> Result<Vec<u8>, KeyProviderFailure> {
        let wrapping = self.key(parent)?;
        let result = wrap_object(&wrapping, parent, key);
        self.record_integrity(&result);
        result
    }
    pub(crate) fn open_object_key(
        &mut self,
        parent: EnvelopeContext,
        ciphertext: &[u8],
        object: crate::data_protection::FrameObjectContext,
    ) -> Result<crate::data_protection::ObjectDataKey, KeyProviderFailure> {
        let wrapping = self.key(parent)?;
        let result = open_object(&wrapping, parent, ciphertext, object);
        self.record_integrity(&result);
        result
    }
    /// Zero-duration policy revalidates at object-key admission, never per frame.
    pub(crate) async fn wrap_object_key_live(
        &mut self,
        envelope: &KeyEnvelope,
        parent: EnvelopeContext,
        key: &crate::data_protection::ObjectDataKey,
    ) -> Result<Vec<u8>, KeyProviderFailure> {
        self.ensure_healthy()?;
        if !self.lease.0.is_zero() {
            self.load(envelope, parent).await?;
            return self.wrap_object_key(parent, key);
        }
        let key_encryption_key = self.live_key(envelope, parent).await?;
        let wrapping = key_encryption_key.temporary_key()?;
        let result = wrap_object(&wrapping, parent, key);
        self.record_integrity(&result);
        result
    }

    /// Opens a child DEK at object admission, including when caching is disabled.
    pub(crate) async fn open_object_key_live(
        &mut self,
        envelope: &KeyEnvelope,
        parent: EnvelopeContext,
        ciphertext: &[u8],
        object: crate::data_protection::FrameObjectContext,
    ) -> Result<crate::data_protection::ObjectDataKey, KeyProviderFailure> {
        self.ensure_healthy()?;
        if !self.lease.0.is_zero() {
            self.load(envelope, parent).await?;
            return self.open_object_key(parent, ciphertext, object);
        }
        let key_encryption_key = self.live_key(envelope, parent).await?;
        let wrapping = key_encryption_key.temporary_key()?;
        let result = open_object(&wrapping, parent, ciphertext, object);
        self.record_integrity(&result);
        result
    }
    async fn live_key(
        &mut self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<LockedKek, KeyProviderFailure> {
        self.expire();
        self.ensure_healthy()?;
        if context.scope == KeyScope::System && self.required_system.is_none() {
            self.required_system = Some(context);
        }
        if !self.live_verified {
            self.verify_live(context).await?;
        }
        let result = self
            .session
            .unwrap(envelope, context)
            .await
            .and_then(LockedKek::new);
        self.record(&result);
        if result.is_ok() && context.scope == KeyScope::System {
            self.zero_system_verified = true;
        }
        self.expire();
        result
    }
}
