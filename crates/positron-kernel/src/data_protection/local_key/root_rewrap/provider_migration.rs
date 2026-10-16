//! Verified native custody and bounded durable recovery routing.
use super::*;
use crate::data_protection::SecretKeyBytes;
use crate::data_protection::key_provider::{
    CustodyKeyProvider, KeyCacheLease, KeyProvider, KeyProviderCache, KeyProviderFailure,
    KeyProviderSession, NativeRootConfiguration, NativeRootProvider, ProviderKeyUri,
};
use std::time::Instant;

fn native_identity(
    context: EnvelopeContext,
    provider: &ProviderKeyUri,
) -> Result<BootstrapKeyIdentity, KeyProviderFailure> {
    let fingerprint = context.digest(provider)?;
    let key_id = fingerprint
        .get(..16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(KeyProviderFailure::ContextMismatch)?;
    BootstrapKeyIdentity::from_parts(key_id, fingerprint, 0)
        .map_err(|_| KeyProviderFailure::ContextMismatch)
}

/// Verified destination envelope; its owning Catalog publishes before activation.
pub struct PreparedProviderMigration {
    envelope: Vec<u8>,
    target: ProviderKeyUri,
    identity: BootstrapKeyIdentity,
    activation: super::super::VerifiedRootActivation,
}
impl PreparedProviderMigration {
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub fn target_identity(&self) -> &ProviderKeyUri {
        &self.target
    }
    pub fn root_identity(&self) -> BootstrapKeyIdentity {
        self.identity
    }
    pub fn into_activation(self) -> super::super::VerifiedRootActivation {
        self.activation
    }
}
impl<'a> RootRewrapSession<'a> {
    /// Two maximum envelopes plus three bridges coexist during publication.
    pub fn admit_provider(
        authority: &'a StorageKernelResourceAuthority,
    ) -> Result<Self, BootstrapKeyFailure> {
        const PEAK: usize = 3 * MAX_BRIDGE_BYTES + 2 * 8956;
        let memory = u64::try_from(PEAK).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let growth =
            u64::try_from(MAX_BRIDGE_BYTES).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let claim = WorkClaim::system_security(ResourceAmounts::new([
            memory, 1, 1, 0, 4, 0, 0, 1, 1, 4, growth,
        ]))
        .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let reservation = authority
            .governor()
            .reserve(claim)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        Ok(Self {
            _reservation: reservation,
            authority,
        })
    }
    pub fn active_system_envelope(
        &self,
        current: &BootstrapKeyCustody,
        instance: InstanceId,
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        current.stored_system_envelope(instance)
    }
    /// Both grants are admitted before any credential or network operation.
    pub fn native_provider(
        &self,
        configuration: NativeRootConfiguration,
    ) -> Result<NativeRootProvider, KeyProviderFailure> {
        let native = self
            .authority
            .governor()
            .reserve(
                WorkClaim::system_security(configuration.required_resources())
                    .map_err(|_| KeyProviderFailure::LimitExceeded)?,
            )
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        let bridge = self
            .authority
            .governor()
            .reserve(
                WorkClaim::system_security(NativeRootProvider::required_resources())
                    .map_err(|_| KeyProviderFailure::LimitExceeded)?,
            )
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        NativeRootProvider::from_configuration(configuration, native, bridge)
    }
    pub async fn open_provider_system(
        &self,
        provider: NativeRootProvider,
        instance: InstanceId,
        anchor: BootstrapKeyIdentity,
        epoch: u64,
        encoded: &[u8],
        lease: KeyCacheLease,
    ) -> Result<BootstrapKeyCustody, KeyProviderFailure> {
        let (context, envelope) = checked_envelope(instance, anchor, epoch, encoded)?;
        let reservation = self.cache_reservation()?;
        let started = Instant::now();
        let key = KeyProviderSession::new(&provider)
            .unwrap(&envelope, context)
            .await?;
        self.adopt_provider_system(
            provider,
            anchor,
            epoch,
            envelope,
            key,
            lease,
            started,
            reservation,
        )
    }
    pub fn open_provider_system_blocking(
        &self,
        provider: NativeRootProvider,
        instance: InstanceId,
        anchor: BootstrapKeyIdentity,
        epoch: u64,
        encoded: &[u8],
        lease: KeyCacheLease,
    ) -> Result<BootstrapKeyCustody, KeyProviderFailure> {
        let (context, envelope) = checked_envelope(instance, anchor, epoch, encoded)?;
        let reservation = self.cache_reservation()?;
        let started = Instant::now();
        let key = CustodyKeyProvider::Native(provider.clone())
            .verified_unwrap_blocking(&envelope, context)?;
        self.adopt_provider_system(
            provider,
            anchor,
            epoch,
            envelope,
            key,
            lease,
            started,
            reservation,
        )
    }
    /// Independently recovers an exact retained Backup Envelope Overlay target.
    /// A historical route may use different ciphertext from the current route;
    /// its authoritative context and recovered stable SYSTEM KEK must match.
    pub fn verify_backup_provider_root_envelope(
        &self,
        configuration: NativeRootConfiguration,
        current: &BootstrapKeyCustody,
        instance: InstanceId,
        root_epoch: u64,
        encoded: &[u8],
    ) -> Result<(), KeyProviderFailure> {
        let provider = self.native_provider(configuration)?;
        let recovered = self.open_provider_system_blocking(
            provider,
            instance,
            current.bootstrap_identity(),
            root_epoch,
            encoded,
            KeyCacheLease::default(),
        )?;
        recovered
            .verify_recovered_system_matches(current)
            .map_err(|failure| match failure {
                BootstrapKeyFailure::LimitExceeded => KeyProviderFailure::LimitExceeded,
                BootstrapKeyFailure::Custody | BootstrapKeyFailure::Entropy => {
                    KeyProviderFailure::Unavailable
                },
                BootstrapKeyFailure::Authentication | BootstrapKeyFailure::InvalidInput => {
                    KeyProviderFailure::WrongKey
                },
            })
    }
    pub fn prepare_provider_migration_blocking(
        &self,
        current: &BootstrapKeyCustody,
        provider: NativeRootProvider,
        instance: InstanceId,
        epoch: u64,
    ) -> Result<PreparedProviderMigration, KeyProviderFailure> {
        let (source, context) = prepare_context(current, &provider, instance, epoch)?;
        let reservation = self.cache_reservation()?;
        let original = current
            .control_system_key(instance)
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        let dispatcher = CustodyKeyProvider::Native(provider.clone());
        let started = Instant::now();
        let envelope = dispatcher.verified_wrap_blocking(
            SecretKek::from_owned(Box::new(*original.expose_to_backend())),
            context,
        )?;
        let verified = dispatcher.verified_unwrap_blocking(&envelope, context)?;
        self.finish_migration(
            current,
            provider,
            epoch,
            source,
            envelope,
            verified,
            original,
            started,
            reservation,
        )
    }
    pub async fn prepare_provider_migration(
        &self,
        current: &BootstrapKeyCustody,
        provider: NativeRootProvider,
        instance: InstanceId,
        epoch: u64,
    ) -> Result<PreparedProviderMigration, KeyProviderFailure> {
        let (source, context) = prepare_context(current, &provider, instance, epoch)?;
        let reservation = self.cache_reservation()?;
        let original = current
            .control_system_key(instance)
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        let session = KeyProviderSession::new(&provider);
        let started = Instant::now();
        let envelope = session
            .wrap(
                SecretKek::from_owned(Box::new(*original.expose_to_backend())),
                context,
            )
            .await?;
        let verified = session.unwrap(&envelope, context).await?;
        self.finish_migration(
            current,
            provider,
            epoch,
            source,
            envelope,
            verified,
            original,
            started,
            reservation,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "verified handoff keeps source receipt and secret ownership together"
    )]
    fn finish_migration(
        &self,
        current: &BootstrapKeyCustody,
        provider: NativeRootProvider,
        epoch: u64,
        source: super::super::RootAdmissionReceipt,
        envelope: KeyEnvelope,
        verified: SecretKek,
        original: SecretKeyBytes,
        started: Instant,
        reservation: ResourceReservation<'_>,
    ) -> Result<PreparedProviderMigration, KeyProviderFailure> {
        use subtle::ConstantTimeEq;
        if !bool::from(
            original
                .expose_to_backend()
                .ct_eq(verified.0.expose_to_backend()),
        ) {
            return Err(KeyProviderFailure::WrongKey);
        }
        drop(original);
        if current
            .root_admission_receipt()
            .map_err(|_| KeyProviderFailure::Unavailable)?
            != source
        {
            return Err(KeyProviderFailure::WrongKey);
        }
        let identity = native_identity(envelope.context, provider.identity())?;
        let target = provider.identity().clone();
        let encoded = envelope.encode();
        let successor = self.adopt_provider_system(
            provider,
            current.bootstrap_identity(),
            epoch,
            envelope,
            verified,
            current
                .cache_lease()
                .map_err(|_| KeyProviderFailure::Unavailable)?,
            started,
            reservation,
        )?;
        Ok(PreparedProviderMigration {
            envelope: encoded,
            target,
            identity,
            activation: super::super::VerifiedRootActivation::new(successor, source),
        })
    }
    fn cache_reservation(&self) -> Result<ResourceReservation<'_>, KeyProviderFailure> {
        let memory = KeyProviderCache::<CustodyKeyProvider>::required_memory_bytes(1)?;
        self.authority
            .governor()
            .reserve(
                WorkClaim::system_security(ResourceAmounts::new([
                    memory, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
                ]))
                .map_err(|_| KeyProviderFailure::LimitExceeded)?,
            )
            .map_err(|_| KeyProviderFailure::LimitExceeded)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "one verified system-key handoff transfers its admitted cache once"
    )]
    fn adopt_provider_system(
        &self,
        provider: NativeRootProvider,
        anchor: BootstrapKeyIdentity,
        epoch: u64,
        envelope: KeyEnvelope,
        key: SecretKek,
        lease: KeyCacheLease,
        started: Instant,
        reservation: ResourceReservation<'_>,
    ) -> Result<BootstrapKeyCustody, KeyProviderFailure> {
        let context = envelope.context;
        let identity = native_identity(context, provider.identity())?;
        let mut cache = KeyProviderCache::from_owned(
            CustodyKeyProvider::Native(provider),
            lease,
            1,
            reservation,
        )?;
        cache.accept_verified_system(&envelope, context, key, started)?;
        BootstrapKeyCustody::from_provider_cache(
            cache,
            context,
            envelope,
            identity,
            anchor,
            epoch,
            self.authority,
        )
    }
    pub fn prepare_provider_activation(
        &self,
        current: &BootstrapKeyCustody,
        provider: NativeRootProvider,
        instance: InstanceId,
        epoch: u64,
        encoded: &[u8],
    ) -> Result<super::super::VerifiedRootActivation, KeyProviderFailure> {
        let source = current
            .root_admission_receipt()
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        let source_epoch = source.epoch();
        if source_epoch != epoch && source_epoch.checked_add(1) != Some(epoch) {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        if source_epoch == epoch
            && (current
                .active_provider_identity()
                .map_err(|_| KeyProviderFailure::Unavailable)?
                != *provider.identity()
                || current
                    .stored_system_envelope(instance)
                    .map_err(|_| KeyProviderFailure::Unavailable)?
                    != encoded)
        {
            return Err(KeyProviderFailure::WrongKey);
        }
        let successor = self.open_provider_system_blocking(
            provider,
            instance,
            current.bootstrap_identity(),
            epoch,
            encoded,
            current
                .cache_lease()
                .map_err(|_| KeyProviderFailure::Unavailable)?,
        )?;
        successor
            .verify_recovered_system_matches(current)
            .map_err(|_| KeyProviderFailure::WrongKey)?;
        if current
            .root_admission_receipt()
            .map_err(|_| KeyProviderFailure::Unavailable)?
            != source
        {
            return Err(KeyProviderFailure::WrongKey);
        }
        Ok(super::super::VerifiedRootActivation::new(successor, source))
    }
    pub fn publish_provider_routes(
        &self,
        access: &crate::BootstrapArtifactAccess,
        current: &BootstrapKeyCustody,
        instance: InstanceId,
        target: BootstrapKeyIdentity,
        epoch: u64,
        encoded: &[u8],
    ) -> Result<(), BootstrapKeyFailure> {
        let (source, source_epoch) = current.active_root_route()?;
        if source_epoch.checked_add(1) != Some(epoch) || source == target {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        let original = current.stored_system_envelope(instance)?;
        let context = binding(instance, current.bootstrap_identity())?;
        let envelope =
            KeyEnvelope::decode(encoded).map_err(|_| BootstrapKeyFailure::Authentication)?;
        envelope
            .check(envelope.identity(), context)
            .map_err(|_| BootstrapKeyFailure::Authentication)?;
        if native_identity(context, envelope.identity())
            .map_err(|_| BootstrapKeyFailure::Authentication)?
            != target
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_BRIDGE_BYTES)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        bytes.extend_from_slice(PROVIDER_BRIDGE_MAGIC);
        bytes.extend_from_slice(&instance.to_bytes());
        write_identity(&mut bytes, current.bootstrap_identity());
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        for (root, epoch, envelope) in [
            (source, source_epoch, original.as_slice()),
            (target, epoch, encoded),
        ] {
            if envelope.is_empty() || envelope.len() > 8956 {
                return Err(BootstrapKeyFailure::LimitExceeded);
            }
            write_identity(&mut bytes, root);
            bytes.extend_from_slice(&epoch.to_be_bytes());
            bytes.extend_from_slice(
                &u32::try_from(envelope.len())
                    .map_err(|_| BootstrapKeyFailure::LimitExceeded)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(envelope);
        }
        if access
            .exists(crate::BootstrapArtifact::SystemKeyEnvelope)
            .map_err(|_| BootstrapKeyFailure::Custody)?
        {
            let previous = access.read_system_key_envelope()?;
            if previous != bytes {
                let bridge = parse_bridge(&previous)?;
                let route = bridge
                    .routes
                    .first()
                    .ok_or(BootstrapKeyFailure::Authentication)?;
                if bridge.instance != instance
                    || bridge.anchor != current.bootstrap_identity()
                    || bridge.routes.len() != 1
                    || route.root != source
                    || route.epoch != source_epoch
                    || route.envelope != original
                {
                    return Err(BootstrapKeyFailure::Authentication);
                }
            }
            access.replace_recovered_system_envelope(&previous, &bytes)
        } else {
            access.publish_recovered_system_envelope(&bytes)
        }
    }
    /// The untrusted locator never authorizes a route; Runtime authenticates
    /// bootstrap and committed Catalog before exposing the returned custody.
    pub fn open_provider_recovery(
        &self,
        access: &crate::BootstrapArtifactAccess,
        configuration: NativeRootConfiguration,
        lease: KeyCacheLease,
    ) -> Result<BootstrapKeyCustody, KeyProviderFailure> {
        let bytes = access
            .read_system_key_envelope()
            .map_err(|_| KeyProviderFailure::Unavailable)?;
        if bytes.get(..8) != Some(PROVIDER_BRIDGE_MAGIC.as_slice()) {
            return Err(KeyProviderFailure::ContextMismatch);
        }
        let bridge = parse_bridge(&bytes).map_err(|_| KeyProviderFailure::ContextMismatch)?;
        let mut selected = None;
        for route in &bridge.routes {
            let envelope = KeyEnvelope::decode(route.envelope)?;
            if envelope.identity() == configuration.identity() {
                if selected.is_some() {
                    return Err(KeyProviderFailure::ContextMismatch);
                }
                selected = Some(route);
            }
        }
        let route = selected.ok_or(KeyProviderFailure::WrongKey)?;
        let provider = self.native_provider(configuration)?;
        let custody = self.open_provider_system_blocking(
            provider,
            bridge.instance,
            bridge.anchor,
            route.epoch,
            route.envelope,
            lease,
        )?;
        if custody
            .active_root_identity()
            .map_err(|_| KeyProviderFailure::Unavailable)?
            != route.root
        {
            return Err(KeyProviderFailure::WrongKey);
        }
        Ok(custody)
    }
    pub fn verify_provider_recovery(
        &self,
        current: &BootstrapKeyCustody,
        recovered: &BootstrapKeyCustody,
        instance: InstanceId,
    ) -> Result<(), BootstrapKeyFailure> {
        if current.active_root_route()? != recovered.active_root_route()?
            || current.active_provider_identity()? != recovered.active_provider_identity()?
            || current.stored_system_envelope(instance)?
                != recovered.stored_system_envelope(instance)?
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        recovered.verify_recovered_system_matches(current)
    }
}
fn checked_envelope(
    instance: InstanceId,
    anchor: BootstrapKeyIdentity,
    epoch: u64,
    encoded: &[u8],
) -> Result<(EnvelopeContext, KeyEnvelope), KeyProviderFailure> {
    if epoch < 2 || encoded.len() > 8956 {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    let context = binding(instance, anchor).map_err(|_| KeyProviderFailure::ContextMismatch)?;
    Ok((context, KeyEnvelope::decode(encoded)?))
}
fn prepare_context(
    current: &BootstrapKeyCustody,
    provider: &NativeRootProvider,
    instance: InstanceId,
    epoch: u64,
) -> Result<(super::super::RootAdmissionReceipt, EnvelopeContext), KeyProviderFailure> {
    let source = current
        .root_admission_receipt()
        .map_err(|_| KeyProviderFailure::Unavailable)?;
    let predecessor_epoch = source.epoch();
    if predecessor_epoch.checked_add(1) != Some(epoch)
        || current
            .active_provider_identity()
            .map_err(|_| KeyProviderFailure::Unavailable)?
            == *provider.identity()
    {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    let context = binding(instance, current.bootstrap_identity())
        .map_err(|_| KeyProviderFailure::ContextMismatch)?;
    Ok((source, context))
}
#[cfg(any(test, feature = "test-support"))]
impl RootRewrapSession<'_> {
    #[doc(hidden)]
    pub fn with_native_fixture_system_payload<T>(
        &self,
        custody: &BootstrapKeyCustody,
        instance: InstanceId,
        provider: &ProviderKeyUri,
        fixture: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, BootstrapKeyFailure> {
        let context = binding(instance, custody.bootstrap_identity())?;
        let system = custody.control_system_key(instance)?;
        let key = SecretKek::from_owned(Box::new(*system.expose_to_backend()));
        let payload = SecretWrappedKeyPayload::encode(&key, context, provider)
            .map_err(|_| BootstrapKeyFailure::Authentication)?;
        Ok(fixture(&payload.0.bytes))
    }
}
