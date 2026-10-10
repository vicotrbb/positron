//! Admitted Data Protection operations publish integrity failures through the
//! existing Catalog owner. Bootstrap probes precede Catalog and fail closed;
//! they cannot claim a durable audit record before that owner is available.
use super::*;
use crate::{Catalog, CatalogFailureCode, ResourceReservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAdmissionFailure {
    Provider(KeyProviderFailure),
    Integrity {
        failure: KeyProviderFailure,
        audit: Result<u64, CatalogFailureCode>,
    },
}
impl ProviderAdmissionFailure {
    pub const fn provider_failure(self) -> KeyProviderFailure {
        match self {
            Self::Provider(failure) | Self::Integrity { failure, .. } => failure,
        }
    }
    pub fn audit_failure(self) -> Option<CatalogFailureCode> {
        match self {
            Self::Integrity {
                audit: Err(code), ..
            } => Some(code),
            _ => None,
        }
    }
    pub fn audit_position(self) -> Option<u64> {
        match self {
            Self::Integrity {
                audit: Ok(position),
                ..
            } => Some(position),
            _ => None,
        }
    }
}
impl std::fmt::Display for ProviderAdmissionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("data protection provider admission failed")
    }
}
impl std::error::Error for ProviderAdmissionFailure {}
impl From<KeyProviderFailure> for ProviderAdmissionFailure {
    fn from(failure: KeyProviderFailure) -> Self {
        Self::Provider(failure)
    }
}

pub(crate) struct DataProtectionProvider<'a, 'authority, P> {
    cache: KeyProviderCache<'a, P>,
    catalog: &'a Catalog<'authority>,
    integrity_audit: Option<Result<u64, CatalogFailureCode>>,
}
impl<'a, 'authority, P: KeyProvider> DataProtectionProvider<'a, 'authority, P> {
    pub(crate) fn new(
        provider: &'a P,
        lease: KeyCacheLease,
        capacity: usize,
        reservation: ResourceReservation<'a>,
        catalog: &'a Catalog<'authority>,
    ) -> Result<Self, ProviderAdmissionFailure> {
        if !catalog.provider_reservation_matches(&reservation) {
            return Err(KeyProviderFailure::InvalidConfiguration.into());
        }
        Ok(Self {
            cache: KeyProviderCache::new(provider, lease, capacity, reservation)?,
            catalog,
            integrity_audit: None,
        })
    }
    pub(crate) fn health(&mut self) -> KeyCacheHealth {
        self.cache.health()
    }
    pub(crate) fn invalidate(&mut self, scope: KeyScope, cause: CacheInvalidation) {
        self.cache.invalidate(scope, cause);
    }
    fn context_matches(&mut self, context: EnvelopeContext) -> Result<(), KeyProviderFailure> {
        if context.instance == self.catalog.instance().to_bytes() {
            Ok(())
        } else {
            let failure = Err(KeyProviderFailure::ContextMismatch);
            self.cache.record(&failure);
            failure
        }
    }
    fn complete<T>(
        &mut self,
        context: EnvelopeContext,
        result: Result<T, KeyProviderFailure>,
    ) -> Result<T, ProviderAdmissionFailure> {
        result.map_err(|failure| {
            if matches!(
                failure,
                KeyProviderFailure::WrongKey | KeyProviderFailure::ContextMismatch
            ) {
                let audit = match self.integrity_audit {
                    Some(audit) => audit,
                    None => {
                        let audit = self
                            .catalog
                            .publish_provider_integrity_failure(context, failure)
                            .map_err(|failure| failure.code());
                        self.integrity_audit = Some(audit);
                        audit
                    },
                };
                ProviderAdmissionFailure::Integrity { failure, audit }
            } else {
                ProviderAdmissionFailure::Provider(failure)
            }
        })
    }
    pub(crate) async fn verify_live(
        &mut self,
        context: EnvelopeContext,
    ) -> Result<(), ProviderAdmissionFailure> {
        let result = match self.context_matches(context) {
            Ok(()) => self.cache.verify_live(context).await,
            Err(failure) => Err(failure),
        };
        self.complete(context, result)
    }
    pub(crate) async fn load(
        &mut self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<(), ProviderAdmissionFailure> {
        let result = match self.context_matches(context) {
            Ok(()) => self.cache.load(envelope, context).await,
            Err(failure) => Err(failure),
        };
        self.complete(context, result)
    }
    pub(crate) async fn wrap_object_key(
        &mut self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
        key: &crate::data_protection::ObjectDataKey,
    ) -> Result<Vec<u8>, ProviderAdmissionFailure> {
        let result = match self.context_matches(context) {
            Ok(()) => {
                self.cache
                    .wrap_object_key_live(envelope, context, key)
                    .await
            },
            Err(failure) => Err(failure),
        };
        self.complete(context, result)
    }
    pub(crate) async fn open_object_key(
        &mut self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
        ciphertext: &[u8],
        object: crate::data_protection::FrameObjectContext,
    ) -> Result<crate::data_protection::ObjectDataKey, ProviderAdmissionFailure> {
        let result = match self.context_matches(context) {
            Ok(()) => {
                self.cache
                    .open_object_key_live(envelope, context, ciphertext, object)
                    .await
            },
            Err(failure) => Err(failure),
        };
        self.complete(context, result)
    }
}
