//! Root wrapping changes preserve the system hierarchy and immutable frames.
use super::{BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity};
use crate::data_protection::DataProtection;
use crate::data_protection::key_provider::{
    EnvelopeContext, KeyEnvelope, KeyScope, LocalKeyProvider, SecretKek, SecretWrappedKeyPayload,
};
use crate::{
    InstanceId, ResourceAmounts, ResourceReservation, StorageKernelResourceAuthority, WorkClaim,
};
mod retirement;
#[cfg(feature = "test-support")]
pub use retirement::RootCustodyPublicationFault;
pub use retirement::RootPredecessorEnvelope;

/// Holds the grant before root wrapping, copying or verification begins.
pub struct RootRewrapSession<'a> {
    _reservation: ResourceReservation<'a>,
    authority: &'a StorageKernelResourceAuthority,
}

impl<'a> RootRewrapSession<'a> {
    /// Derives a retained key capability without filesystem growth. The admitted
    /// session stays private so this grant cannot authorize custody publication.
    pub fn derive_tenant_segment_key(
        authority: &'a StorageKernelResourceAuthority,
        custody: &BootstrapKeyCustody,
        instance: InstanceId,
        scope: crate::SegmentScope,
        envelope: &[u8],
    ) -> Result<crate::SegmentProtectionKey, BootstrapKeyFailure> {
        let claim = WorkClaim::system_security(ResourceAmounts::new([
            32_768, 1, 1, 0, 4, 0, 0, 1, 1, 4, 0,
        ]))
        .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let reservation = authority
            .governor()
            .reserve(claim)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let session = Self {
            _reservation: reservation,
            authority,
        };
        session.tenant_segment_key(custody, instance, scope, envelope)
    }
    pub(crate) fn resource_authority(&self) -> &StorageKernelResourceAuthority {
        self.authority
    }
    /// Transfers the bounded key capability's charge beyond this operation.
    pub fn tenant_segment_key(
        &self,
        custody: &BootstrapKeyCustody,
        instance: InstanceId,
        scope: crate::SegmentScope,
        envelope: &[u8],
    ) -> Result<crate::SegmentProtectionKey, BootstrapKeyFailure> {
        let retained_bytes = u64::try_from(custody.retained_segment_context_bytes(envelope))
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?
            .checked_add(if custody.retained_segment_context_bytes(envelope) == 0 {
                2048
            } else {
                6144
            })
            .ok_or(BootstrapKeyFailure::LimitExceeded)?;
        let claim = WorkClaim::system_security(ResourceAmounts::new([
            retained_bytes,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
        ]))
        .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let capacity = self
            .authority
            .governor()
            .reserve(claim)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        custody
            .segment_key_from_tenant_envelope(instance, scope, envelope)
            .map(|key| key.with_capacity(capacity.transfer()))
    }
    pub fn rotation_catalog_secret(
        &self,
        custody: &BootstrapKeyCustody,
        instance: InstanceId,
    ) -> Result<crate::CatalogSecret, BootstrapKeyFailure> {
        let system = custody.control_system_key(instance)?;
        BootstrapKeyCustody::catalog_from_system(instance, &system)
    }
    pub fn confirm_active_provider(
        &self,
        custody: &BootstrapKeyCustody,
        identity: BootstrapKeyIdentity,
        epoch: u64,
    ) -> Result<(), BootstrapKeyFailure> {
        custody.confirm_provider(identity, epoch)
    }
    pub fn publish_successor_routes(
        &self,
        access: &crate::BootstrapArtifactAccess,
        current: &BootstrapKeyCustody,
        successor: &BootstrapKeyCustody,
        instance: InstanceId,
        epoch: u64,
    ) -> Result<(), BootstrapKeyFailure> {
        let (identity, current_epoch) = current.active_root_route()?;
        if current_epoch.checked_add(1) != Some(epoch) {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        let original = self.wrap_system(current, current, instance, current_epoch)?;
        let replacement = self.wrap_system(current, successor, instance, epoch)?;
        let mut bytes = Vec::with_capacity(4096);
        bytes.extend_from_slice(BRIDGE_MAGIC);
        bytes.extend_from_slice(&instance.to_bytes());
        write_identity(&mut bytes, current.bootstrap_identity());
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        for (identity, epoch, envelope) in [
            (identity, current_epoch, original),
            (successor.identity(), epoch, replacement),
        ] {
            write_identity(&mut bytes, identity);
            bytes.extend_from_slice(&epoch.to_be_bytes());
            let length =
                u32::try_from(envelope.len()).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&envelope);
        }
        if access
            .exists(crate::BootstrapArtifact::SystemKeyEnvelope)
            .map_err(|_| BootstrapKeyFailure::Custody)?
        {
            let previous = access.read_system_key_envelope()?;
            if previous != bytes {
                let bridge = parse_bridge(&previous)?;
                let only = bridge
                    .routes
                    .first()
                    .ok_or(BootstrapKeyFailure::Authentication)?;
                if bridge.instance != instance
                    || bridge.anchor != current.bootstrap_identity()
                    || bridge.routes.len() != 1
                    || only.epoch != current_epoch
                    || only.root != identity
                    || only.envelope
                        != self.wrap_system(current, current, instance, current_epoch)?
                {
                    return Err(BootstrapKeyFailure::Authentication);
                }
            }
            access.replace_recovered_system_envelope(&previous, &bytes)
        } else {
            access.publish_recovered_system_envelope(&bytes)
        }
    }
    pub fn prepare_activation(
        &self,
        current: &BootstrapKeyCustody,
        successor: BootstrapKeyCustody,
        instance: InstanceId,
        epoch: u64,
        envelope: &[u8],
    ) -> Result<super::VerifiedRootActivation, BootstrapKeyFailure> {
        let (predecessor, predecessor_epoch) = current.active_root_route()?;
        if predecessor_epoch.checked_add(1) != Some(epoch) {
            return Err(BootstrapKeyFailure::InvalidInput);
        }
        let verified = self.open_system(
            successor,
            instance,
            current.bootstrap_identity(),
            epoch,
            envelope,
        )?;
        use subtle::ConstantTimeEq;
        let original_system = current.control_system_key(instance)?;
        let successor_system = verified.system_kek(instance)?;
        if !bool::from(
            original_system
                .expose_to_backend()
                .ct_eq(successor_system.expose_to_backend()),
        ) {
            return Err(BootstrapKeyFailure::Authentication);
        }
        drop(original_system);
        drop(successor_system);
        let successor = self.lease_system(verified, instance, current.cache_lease()?)?;
        Ok(super::VerifiedRootActivation::new(
            successor,
            predecessor,
            predecessor_epoch,
        ))
    }
    pub fn admit(
        authority: &'a StorageKernelResourceAuthority,
    ) -> Result<Self, BootstrapKeyFailure> {
        let claim = WorkClaim::system_security(ResourceAmounts::new([
            32_768, 1, 1, 0, 4, 0, 0, 1, 1, 4, 16_384,
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

    pub fn prepare_successor(
        &self,
        access: &crate::BootstrapArtifactAccess,
        epoch: u64,
    ) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        access.prepare_successor_key(epoch)
    }
    pub fn open_successor(
        &self,
        access: &crate::BootstrapArtifactAccess,
        epoch: u64,
    ) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        access.open_successor_key(epoch)
    }
    pub fn lease_system(
        &self,
        custody: BootstrapKeyCustody,
        instance: InstanceId,
        lease: crate::data_protection::key_provider::KeyCacheLease,
    ) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        self.lease_system_with_clock(custody, instance, lease, std::time::Instant::now)
    }
    /// Binds the existing provider cache to the owning runtime's monotonic clock.
    pub fn lease_system_with_clock(
        &self,
        custody: BootstrapKeyCustody,
        instance: InstanceId,
        lease: crate::data_protection::key_provider::KeyCacheLease,
        clock: fn() -> std::time::Instant,
    ) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        use crate::data_protection::key_provider::KeyProviderCache;
        let memory = KeyProviderCache::<LocalKeyProvider>::required_memory_bytes(1)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let amounts =
            ResourceAmounts::new(
                crate::ResourceDimension::ALL.map(|dimension| match dimension {
                    crate::ResourceDimension::MemoryBytes => memory,
                    crate::ResourceDimension::LeaseSlots => 1,
                    _ => 0,
                }),
            );
        let claim =
            WorkClaim::system_security(amounts).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let reservation = self
            .authority
            .governor()
            .reserve(claim)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let encoded =
            self.wrap_system(&custody, &custody, instance, custody.active_root_epoch()?)?;
        let context = binding(instance, custody.bootstrap_identity())?;
        let envelope =
            KeyEnvelope::decode(&encoded).map_err(|_| BootstrapKeyFailure::Authentication)?;
        let custody =
            custody.into_leased(instance, context, envelope, lease, reservation, clock)?;
        custody.attach_segment_reference_authority(self.authority)?;
        Ok(custody)
    }

    pub fn system_context(
        &self,
        instance: InstanceId,
        anchor: BootstrapKeyIdentity,
    ) -> Result<EnvelopeContext, BootstrapKeyFailure> {
        binding(instance, anchor)
    }

    /// Adds a successor recovery route for the existing system KEK. The child
    /// key, its original identity and its epoch stay unchanged.
    pub fn wrap_system(
        &self,
        source: &BootstrapKeyCustody,
        destination: &BootstrapKeyCustody,
        instance: InstanceId,
        root_epoch: u64,
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        let encoded = wrap_system_at(source, destination, instance, root_epoch)?;
        // Verify the successor route against independently retained source material.
        let context = binding(instance, source.bootstrap_identity())?;
        let provider = LocalKeyProvider::identity_for_custody(destination, root_epoch)
            .map_err(|_| BootstrapKeyFailure::InvalidInput)?;
        let envelope =
            KeyEnvelope::decode(&encoded).map_err(|_| BootstrapKeyFailure::Authentication)?;
        envelope
            .check(&provider, context)
            .map_err(|_| BootstrapKeyFailure::Authentication)?;
        let payload = destination
            .provider_unwrap(envelope.ciphertext())
            .map_err(|_| BootstrapKeyFailure::Authentication)?;
        let recovered = SecretWrappedKeyPayload(payload)
            .verify(context, &provider)
            .map_err(|_| BootstrapKeyFailure::Authentication)?;
        let system = source.system_kek(instance)?;
        use subtle::ConstantTimeEq;
        if !bool::from(
            system
                .expose_to_backend()
                .ct_eq(recovered.0.expose_to_backend()),
        ) {
            return Err(BootstrapKeyFailure::Authentication);
        }
        Ok(encoded)
    }

    /// Authoritative bootstrap identity must be pinned by the owning instance,
    /// independently of the presented envelope's routing fields.
    pub fn open_system(
        &self,
        custody: BootstrapKeyCustody,
        instance: InstanceId,
        anchor: BootstrapKeyIdentity,
        root_epoch: u64,
        encoded: &[u8],
    ) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
        open_system(custody, instance, anchor, root_epoch, encoded)
    }
}

pub(super) fn open_system(
    mut custody: BootstrapKeyCustody,
    instance: InstanceId,
    anchor: BootstrapKeyIdentity,
    root_epoch: u64,
    encoded: &[u8],
) -> Result<BootstrapKeyCustody, BootstrapKeyFailure> {
    if encoded.len() > 1024 {
        return Err(BootstrapKeyFailure::LimitExceeded);
    }
    let context = binding(instance, anchor)?;
    let provider = LocalKeyProvider::identity_for_custody(&custody, root_epoch)
        .map_err(|_| BootstrapKeyFailure::InvalidInput)?;
    let envelope = KeyEnvelope::decode(encoded).map_err(|_| BootstrapKeyFailure::Authentication)?;
    envelope
        .check(&provider, context)
        .map_err(|_| BootstrapKeyFailure::Authentication)?;
    let payload = custody
        .provider_unwrap(envelope.ciphertext())
        .map_err(|_| BootstrapKeyFailure::Authentication)?;
    let system = SecretWrappedKeyPayload(payload)
        .verify(context, &provider)
        .map_err(|_| BootstrapKeyFailure::Authentication)?;
    custody.anchor = anchor;
    custody.system = Some((instance, system.0, anchor));
    custody.root_epoch = root_epoch;
    Ok(custody)
}

pub(super) fn wrap_system(
    custody: &BootstrapKeyCustody,
    instance: InstanceId,
) -> Result<Vec<u8>, BootstrapKeyFailure> {
    wrap_system_at(custody, custody, instance, custody.active_root_epoch()?)
}

fn wrap_system_at(
    source: &BootstrapKeyCustody,
    destination: &BootstrapKeyCustody,
    instance: InstanceId,
    root_epoch: u64,
) -> Result<Vec<u8>, BootstrapKeyFailure> {
    let context = binding(instance, source.bootstrap_identity())?;
    let provider = LocalKeyProvider::identity_for_custody(destination, root_epoch)
        .map_err(|_| BootstrapKeyFailure::InvalidInput)?;
    let key = SecretKek(source.system_kek(instance)?);
    let payload = SecretWrappedKeyPayload::encode(&key, context, &provider)
        .map_err(|_| BootstrapKeyFailure::Authentication)?;
    LocalKeyProvider::wrap_for_epoch(destination, root_epoch, payload, context)
        .map(|envelope| envelope.encode())
        .map_err(|_| BootstrapKeyFailure::Authentication)
}

fn binding(
    instance: InstanceId,
    anchor: BootstrapKeyIdentity,
) -> Result<EnvelopeContext, BootstrapKeyFailure> {
    let mut identity = Vec::with_capacity(128);
    identity.extend_from_slice(b"positron-stable-system-kek-identity-v1\0");
    identity.extend_from_slice(&instance.to_bytes());
    identity.extend_from_slice(&anchor.key_id());
    identity.extend_from_slice(&anchor.fingerprint());
    identity.extend_from_slice(&anchor.created_at_unix_seconds().to_be_bytes());
    let key_id =
        DataProtection::hash(&identity).map_err(|_| BootstrapKeyFailure::Authentication)?;
    EnvelopeContext::new(instance.to_bytes(), KeyScope::System, key_id, 1, 1)
        .map_err(|_| BootstrapKeyFailure::Authentication)
}

const BRIDGE_MAGIC: &[u8; 8] = b"POSSEK01";
pub(super) const MAX_BRIDGE_BYTES: usize = 16_384;

impl BootstrapKeyCustody {
    pub(crate) fn write_root_envelope(
        file: &mut std::fs::File,
        bytes: &[u8],
    ) -> Result<(), BootstrapKeyFailure> {
        super::initialization_io::write_new_key(file, bytes)
            .map_err(|_| BootstrapKeyFailure::Custody)?;
        super::initialization_io::synchronize_key_file(file)
            .map_err(|_| BootstrapKeyFailure::Custody)
    }
    pub(crate) fn synchronize_root_envelope_directory(
        directory: &std::fs::File,
    ) -> Result<(), BootstrapKeyFailure> {
        super::initialization_io::synchronize_security_directory(directory)
            .map_err(|_| BootstrapKeyFailure::Custody)
    }
    pub(crate) fn verify_recovery_envelope(&self, bytes: &[u8]) -> Result<(), BootstrapKeyFailure> {
        let bridge = parse_bridge(bytes)?;
        let (instance, anchor) = self
            .system_route()?
            .ok_or(BootstrapKeyFailure::Authentication)?;
        if bridge.instance != instance || bridge.anchor != anchor {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let root = self.active_root_identity()?;
        let epoch = self.active_root_epoch()?;
        let route = bridge
            .routes
            .iter()
            .find(|route| route.root == root && route.epoch == epoch)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        let canonical = wrap_system(self, instance)?;
        if route.envelope != canonical {
            return Err(BootstrapKeyFailure::Authentication);
        }
        Ok(())
    }
    pub(crate) fn verify_recovered_system_matches(
        &self,
        original: &Self,
    ) -> Result<(), BootstrapKeyFailure> {
        use subtle::ConstantTimeEq;
        let (instance, anchor) = self
            .system_route()?
            .ok_or(BootstrapKeyFailure::Authentication)?;
        if original.bootstrap_identity() != anchor {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let recovered = self.system_kek(instance)?;
        let previous = original.system_kek(instance)?;
        if !bool::from(
            recovered
                .expose_to_backend()
                .ct_eq(previous.expose_to_backend()),
        ) {
            return Err(BootstrapKeyFailure::Authentication);
        }
        Ok(())
    }

    pub(crate) fn root_recovery_envelope(&self) -> Result<Option<Vec<u8>>, BootstrapKeyFailure> {
        let Some((instance, anchor)) = self.system_route()? else {
            return Ok(None);
        };
        let wrapped = wrap_system(self, instance)?;
        let mut bytes = Vec::with_capacity(150 + wrapped.len());
        bytes.extend_from_slice(BRIDGE_MAGIC);
        bytes.extend_from_slice(&instance.to_bytes());
        write_identity(&mut bytes, anchor);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        write_identity(&mut bytes, self.active_root_identity()?);
        bytes.extend_from_slice(&self.active_root_epoch()?.to_be_bytes());
        let length =
            u32::try_from(wrapped.len()).map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&wrapped);
        Ok(Some(bytes))
    }

    /// The route is verified before any bootstrap object or Catalog is opened.
    /// The recovered original identity is subsequently checked against the
    /// authenticated initialized bootstrap record by its owning Runtime.
    pub(crate) fn open_root_envelope(self, bytes: &[u8]) -> Result<Self, BootstrapKeyFailure> {
        let bridge = parse_bridge(bytes)?;
        let route = bridge
            .routes
            .iter()
            .find(|route| route.root == self.identity())
            .ok_or(BootstrapKeyFailure::Authentication)?;
        open_system(
            self,
            bridge.instance,
            bridge.anchor,
            route.epoch,
            route.envelope,
        )
    }

    /// Opens an available protected candidate; the authenticated Catalog chooses
    /// the active epoch after the immutable bootstrap anchor is verified.
    pub(crate) fn open_successor_candidate(
        directory: &std::fs::File,
        bytes: &[u8],
    ) -> Result<Self, BootstrapKeyFailure> {
        let bridge = parse_bridge(bytes)?;
        for route in &bridge.routes {
            if route.epoch < 2 {
                continue;
            }
            let name = format!("local-root-key.epoch-{}.v1", route.epoch);
            match rustix::fs::statat(
                directory,
                name.as_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(rustix::io::Errno::NOENT) => continue,
                Err(_) => return Err(BootstrapKeyFailure::Custody),
                Ok(_) => {},
            }
            let custody = Self::open_epoch_in(directory, route.epoch)?;
            if custody.identity() != route.root {
                return Err(BootstrapKeyFailure::Authentication);
            }
            return open_system(
                custody,
                bridge.instance,
                bridge.anchor,
                route.epoch,
                route.envelope,
            );
        }
        Err(BootstrapKeyFailure::Custody)
    }
}

struct BridgeRoute<'a> {
    root: BootstrapKeyIdentity,
    epoch: u64,
    envelope: &'a [u8],
}
struct Bridge<'a> {
    instance: InstanceId,
    anchor: BootstrapKeyIdentity,
    routes: Vec<BridgeRoute<'a>>,
}
fn parse_bridge(bytes: &[u8]) -> Result<Bridge<'_>, BootstrapKeyFailure> {
    if bytes.len() > MAX_BRIDGE_BYTES || bytes.get(..8) != Some(BRIDGE_MAGIC.as_slice()) {
        return Err(BootstrapKeyFailure::Authentication);
    }
    let mut cursor = BridgeCursor(bytes.get(8..).ok_or(BootstrapKeyFailure::Authentication)?);
    let instance =
        InstanceId::new(cursor.array()?).map_err(|_| BootstrapKeyFailure::Authentication)?;
    let anchor = cursor.identity()?;
    let count = u16::from_be_bytes(cursor.array()?);
    if !(1..=16).contains(&count) {
        return Err(BootstrapKeyFailure::LimitExceeded);
    }
    let mut routes = Vec::<BridgeRoute<'_>>::new();
    routes
        .try_reserve_exact(usize::from(count))
        .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
    let mut preceding_epoch = 0;
    for _ in 0..count {
        let root = cursor.identity()?;
        let epoch = u64::from_be_bytes(cursor.array()?);
        if epoch <= preceding_epoch || routes.iter().any(|route| route.root == root) {
            return Err(BootstrapKeyFailure::Authentication);
        }
        preceding_epoch = epoch;
        let length = u32::from_be_bytes(cursor.array()?);
        if length == 0 || length > 1024 {
            return Err(BootstrapKeyFailure::LimitExceeded);
        }
        routes.push(BridgeRoute {
            root,
            epoch,
            envelope: cursor.take(length as usize)?,
        });
    }
    if !cursor.0.is_empty() {
        return Err(BootstrapKeyFailure::Authentication);
    }
    Ok(Bridge {
        instance,
        anchor,
        routes,
    })
}

fn write_identity(bytes: &mut Vec<u8>, identity: BootstrapKeyIdentity) {
    bytes.extend_from_slice(&identity.key_id());
    bytes.extend_from_slice(&identity.fingerprint());
    bytes.extend_from_slice(&identity.created_at_unix_seconds().to_be_bytes());
}

struct BridgeCursor<'a>(&'a [u8]);
impl<'a> BridgeCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], BootstrapKeyFailure> {
        let (head, tail) = self
            .0
            .split_at_checked(length)
            .ok_or(BootstrapKeyFailure::Authentication)?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BootstrapKeyFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| BootstrapKeyFailure::Authentication)
    }
    fn identity(&mut self) -> Result<BootstrapKeyIdentity, BootstrapKeyFailure> {
        BootstrapKeyIdentity::from_parts(
            self.array()?,
            self.array()?,
            u64::from_be_bytes(self.array()?),
        )
        .map_err(|_| BootstrapKeyFailure::Authentication)
    }
}
