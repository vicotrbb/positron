//! Bootstrap hands its root to the existing provider and its system KEK to the lease.
use super::*;
use crate::ResourceReservation;
use crate::data_protection::key_provider::{
    EnvelopeContext, KeyCacheLease, KeyEnvelope, KeyProviderCache, LocalKeyProvider,
};
use std::sync::{Arc, Mutex};

pub(super) enum RootCustody {
    Bootstrap(VerifiedLocalKey),
    Leased(Arc<Mutex<SystemLease>>),
}

pub(super) struct SystemLease {
    cache: Option<KeyProviderCache<'static, LocalKeyProvider>>,
    envelope: KeyEnvelope,
    context: EnvelopeContext,
    identity: BootstrapKeyIdentity,
    epoch: u64,
    admission: LeaseAdmission,
    pub(super) references: Option<(
        crate::active_segment_ledger::snapshot_protection::SnapshotProtectionRegistry,
        Arc<std::sync::RwLock<()>>,
    )>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum LeaseAdmission {
    Ready,
    RotationUncertain,
    Closed,
}
/// Verified, admitted successor custody awaiting the owning Catalog cutover.
pub struct VerifiedRootActivation {
    successor: BootstrapKeyCustody,
    predecessor: BootstrapKeyIdentity,
    predecessor_epoch: u64,
}
impl VerifiedRootActivation {
    pub fn activate(self, current: &BootstrapKeyCustody) -> Result<(), BootstrapKeyFailure> {
        if current.anchor != self.successor.anchor {
            return Err(BootstrapKeyFailure::Authentication);
        }
        match (&current.key, self.successor.key) {
            (RootCustody::Leased(current), RootCustody::Leased(successor)) => {
                let replacement = Arc::try_unwrap(successor)
                    .map_err(|_| BootstrapKeyFailure::Custody)?
                    .into_inner()
                    .map_err(|_| BootstrapKeyFailure::Custody)?;
                let mut current = current.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
                if current.admission == LeaseAdmission::Closed {
                    return Err(BootstrapKeyFailure::Custody);
                }
                if current.identity != self.predecessor || current.epoch != self.predecessor_epoch {
                    return Err(BootstrapKeyFailure::Authentication);
                }
                *current = replacement;
                Ok(())
            },
            _ => Err(BootstrapKeyFailure::Custody),
        }
    }
    pub(in crate::data_protection::local_key) fn new(
        successor: BootstrapKeyCustody,
        predecessor: BootstrapKeyIdentity,
        predecessor_epoch: u64,
    ) -> Self {
        Self {
            successor,
            predecessor,
            predecessor_epoch,
        }
    }
}
impl SystemLease {
    pub(super) fn system_key(
        &mut self,
        instance: InstanceId,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        if self.admission != LeaseAdmission::Ready {
            return Err(BootstrapKeyFailure::Custody);
        }
        self.verified_key(instance)
    }
    fn verified_key(
        &mut self,
        instance: InstanceId,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        if self.context.instance != instance.to_bytes() {
            return Err(BootstrapKeyFailure::Authentication);
        }
        self.cache
            .as_mut()
            .ok_or(BootstrapKeyFailure::Custody)?
            .local_system_key(&self.envelope, self.context)
            .map_err(|_| BootstrapKeyFailure::Custody)
    }
}
impl BootstrapKeyCustody {
    /// Closes process-owned key derivation after final publication secrets have
    /// been acquired. Dropping the cache zeroizes its provider and resident keys
    /// before releasing the cache's transferred reservation.
    pub fn close_for_shutdown(&self) -> Result<(), BootstrapKeyFailure> {
        let RootCustody::Leased(lease) = &self.key else {
            return Err(BootstrapKeyFailure::Custody);
        };
        let mut lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
        lease.admission = LeaseAdmission::Closed;
        drop(lease.cache.take());
        Ok(())
    }
    pub(in crate::data_protection::local_key) fn attach_segment_reference_authority(
        &self,
        authority: &crate::StorageKernelResourceAuthority,
    ) -> Result<(), BootstrapKeyFailure> {
        let RootCustody::Leased(lease) = &self.key else {
            return Err(BootstrapKeyFailure::Custody);
        };
        lease
            .lock()
            .map_err(|_| BootstrapKeyFailure::Custody)?
            .references = Some((
            authority.snapshot_protection(),
            authority.shared_snapshot_barrier(),
        ));
        Ok(())
    }
    /// Reports whether rotation has fenced normal data-protection admission.
    pub fn rotation_requires_confirmation(&self) -> Result<bool, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => Ok(false),
            RootCustody::Leased(lease) => Ok(lease
                .lock()
                .map_err(|_| BootstrapKeyFailure::Custody)?
                .admission
                == LeaseAdmission::RotationUncertain),
        }
    }
    /// Revokes live data-protection admission while cutover authority is uncertain.
    pub fn invalidate_for_rotation(&self) -> Result<(), BootstrapKeyFailure> {
        let RootCustody::Leased(lease) = &self.key else {
            return Err(BootstrapKeyFailure::Custody);
        };
        let mut lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
        if lease.admission == LeaseAdmission::Closed {
            return Err(BootstrapKeyFailure::Custody);
        }
        lease.admission = LeaseAdmission::RotationUncertain;
        lease
            .cache
            .as_mut()
            .ok_or(BootstrapKeyFailure::Custody)?
            .invalidate(
                crate::key_provider::KeyScope::System,
                crate::key_provider::CacheInvalidation::Rotation,
            );
        Ok(())
    }
    pub(in crate::data_protection::local_key) fn control_system_key(
        &self,
        instance: InstanceId,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => self.system_kek(instance),
            RootCustody::Leased(lease) => {
                let mut lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
                let key = lease.verified_key(instance);
                if lease.admission == LeaseAdmission::RotationUncertain {
                    lease
                        .cache
                        .as_mut()
                        .ok_or(BootstrapKeyFailure::Custody)?
                        .invalidate(
                            crate::key_provider::KeyScope::System,
                            crate::key_provider::CacheInvalidation::Rotation,
                        );
                }
                key
            },
        }
    }
    pub(in crate::data_protection::local_key) fn confirm_provider(
        &self,
        identity: BootstrapKeyIdentity,
        epoch: u64,
    ) -> Result<(), BootstrapKeyFailure> {
        let RootCustody::Leased(lease) = &self.key else {
            return Err(BootstrapKeyFailure::Custody);
        };
        let mut lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
        if lease.identity != identity || lease.epoch != epoch {
            return Err(BootstrapKeyFailure::Authentication);
        }
        let instance = InstanceId::new(lease.context.instance)
            .map_err(|_| BootstrapKeyFailure::Authentication)?;
        drop(lease.verified_key(instance)?);
        lease.admission = LeaseAdmission::Ready;
        Ok(())
    }
    pub(in crate::data_protection::local_key) fn active_root_route(
        &self,
    ) -> Result<(BootstrapKeyIdentity, u64), BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => Ok((self.identity, self.root_epoch)),
            RootCustody::Leased(lease) => {
                let lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
                Ok((lease.identity, lease.epoch))
            },
        }
    }
    pub fn active_root_identity(&self) -> Result<BootstrapKeyIdentity, BootstrapKeyFailure> {
        self.active_root_route().map(|(identity, _)| identity)
    }
    pub fn active_root_epoch(&self) -> Result<u64, BootstrapKeyFailure> {
        self.active_root_route().map(|(_, epoch)| epoch)
    }
    pub(in crate::data_protection::local_key) fn cache_lease(
        &self,
    ) -> Result<KeyCacheLease, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => Err(BootstrapKeyFailure::Custody),
            RootCustody::Leased(lease) => Ok(lease
                .lock()
                .map_err(|_| BootstrapKeyFailure::Custody)?
                .cache
                .as_ref()
                .ok_or(BootstrapKeyFailure::Custody)?
                .lease()),
        }
    }
    pub fn provider_health(
        &self,
    ) -> Result<crate::data_protection::key_provider::KeyCacheHealth, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => Err(BootstrapKeyFailure::Custody),
            RootCustody::Leased(lease) => Ok(lease
                .lock()
                .map_err(|_| BootstrapKeyFailure::Custody)?
                .cache
                .as_mut()
                .ok_or(BootstrapKeyFailure::Custody)?
                .health()),
        }
    }

    pub(in crate::data_protection::local_key) fn system_route(
        &self,
    ) -> Result<Option<(InstanceId, BootstrapKeyIdentity)>, BootstrapKeyFailure> {
        if let Some((instance, _, anchor)) = &self.system {
            return Ok(Some((*instance, *anchor)));
        }
        if let RootCustody::Leased(lease) = &self.key {
            let lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
            return Ok(Some((
                InstanceId::new(lease.context.instance)
                    .map_err(|_| BootstrapKeyFailure::Authentication)?,
                self.anchor,
            )));
        }
        Ok(None)
    }
    pub(in crate::data_protection::local_key) fn has_system_route(&self) -> bool {
        self.system.is_some() || matches!(self.key, RootCustody::Leased(_))
    }

    pub(in crate::data_protection::local_key) fn with_root_key<T>(
        &self,
        operation: impl FnOnce(&SecretKeyBytes) -> T,
    ) -> Result<T, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(key) => Ok(operation(&key.root_key.0)),
            RootCustody::Leased(lease) => {
                let lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
                if lease.admission != LeaseAdmission::Ready {
                    return Err(BootstrapKeyFailure::Custody);
                }
                Ok(operation(
                    lease
                        .cache
                        .as_ref()
                        .ok_or(BootstrapKeyFailure::Custody)?
                        .local_provider()
                        .root(),
                ))
            },
        }
    }
    pub(in crate::data_protection::local_key) fn into_leased(
        self,
        instance: InstanceId,
        context: EnvelopeContext,
        envelope: KeyEnvelope,
        lease: KeyCacheLease,
        reservation: ResourceReservation<'_>,
        clock: fn() -> std::time::Instant,
    ) -> Result<Self, BootstrapKeyFailure> {
        let identity = self.identity;
        let anchor = self.anchor;
        let root_epoch = self.root_epoch;
        let provider =
            LocalKeyProvider::from_custody(self).map_err(|_| BootstrapKeyFailure::Custody)?;
        let cache = KeyProviderCache::from_owned_with_clock(provider, lease, 1, reservation, clock)
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let mut system = SystemLease {
            cache: Some(cache),
            context,
            envelope,
            identity,
            epoch: root_epoch,
            admission: LeaseAdmission::Ready,
            references: None,
        };
        drop(system.system_key(instance)?);
        // Unit-test secret values carry an Rc zeroization observer. Production
        // custody is Send + Sync; sharing the owner does not share plaintext.
        #[cfg_attr(test, expect(clippy::arc_with_non_send_sync))]
        let owner = Arc::new(Mutex::new(system));
        Ok(Self {
            key: RootCustody::Leased(owner),
            identity,
            anchor,
            root_epoch,
            system: None,
        })
    }
}
