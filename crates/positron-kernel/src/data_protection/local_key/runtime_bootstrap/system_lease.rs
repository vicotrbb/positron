//! Bootstrap hands its root to the existing provider and its system KEK to the lease.
use super::*;
use crate::ResourceReservation;
use crate::data_protection::key_provider::{
    CustodyKeyProvider, EnvelopeContext, KeyCacheLease, KeyEnvelope, KeyProviderCache,
    LocalKeyProvider, ProviderKeyUri,
};
use std::sync::{Arc, Mutex};
mod admission;
use admission::KeyAdmission;

pub(super) enum RootCustody {
    Bootstrap(VerifiedLocalKey),
    Leased(Arc<Mutex<SystemLease>>),
}

pub(super) struct SystemLease {
    cache: Option<KeyProviderCache<'static, CustodyKeyProvider>>,
    available: Arc<std::sync::Condvar>,
    envelope: KeyEnvelope,
    context: EnvelopeContext,
    identity: BootstrapKeyIdentity,
    epoch: u64,
    admission: LeaseAdmission,
    revision: u64,
    policy: KeyCacheLease,
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
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RootAdmissionReceipt {
    identity: BootstrapKeyIdentity,
    epoch: u64,
    revision: Option<u64>,
    uncertain: bool,
}
impl RootAdmissionReceipt {
    #[must_use]
    pub fn identity(self) -> BootstrapKeyIdentity {
        self.identity
    }
    #[must_use]
    pub fn epoch(self) -> u64 {
        self.epoch
    }
    #[must_use]
    pub fn requires_reconfirmation(self) -> bool {
        self.uncertain
    }
}
pub struct VerifiedRootActivation {
    successor: BootstrapKeyCustody,
    source: RootAdmissionReceipt,
}
impl VerifiedRootActivation {
    /// The owning Catalog may authorize recovery after an uncertain publication.
    /// Fresh source and destination admission binds a new exact source receipt;
    /// the original activation remains invalid after any revision change.
    pub fn revalidate(
        self,
        current: &BootstrapKeyCustody,
        instance: InstanceId,
    ) -> Result<Self, BootstrapKeyFailure> {
        let source = current.root_admission_receipt()?;
        if current.anchor != self.successor.anchor
            || source.epoch.checked_add(1) != Some(self.successor.active_root_epoch()?)
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        self.successor.verify_recovered_system_matches(current)?;
        if current.root_admission_receipt()? != source {
            return Err(BootstrapKeyFailure::Authentication);
        }
        // Instance is checked independently by both live admissions.
        drop(current.control_system_key(instance)?);
        if current.root_admission_receipt()? != source {
            return Err(BootstrapKeyFailure::Authentication);
        }
        Ok(Self { source, ..self })
    }
    pub fn activate(self, current: &BootstrapKeyCustody) -> Result<(), BootstrapKeyFailure> {
        if current.anchor != self.successor.anchor {
            return Err(BootstrapKeyFailure::Authentication);
        }
        match (&current.key, self.successor.key) {
            (RootCustody::Leased(current), RootCustody::Leased(successor)) => {
                let mut replacement = Arc::try_unwrap(successor)
                    .map_err(|_| BootstrapKeyFailure::Custody)?
                    .into_inner()
                    .map_err(|_| BootstrapKeyFailure::Custody)?;
                let mut current = current.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
                if current.admission == LeaseAdmission::Closed {
                    return Err(BootstrapKeyFailure::Custody);
                }
                if current.identity != self.source.identity
                    || current.epoch != self.source.epoch
                    || Some(current.revision) != self.source.revision
                {
                    return Err(BootstrapKeyFailure::Authentication);
                }
                replacement.revision = current
                    .revision
                    .checked_add(1)
                    .ok_or(BootstrapKeyFailure::LimitExceeded)?;
                replacement.available = Arc::clone(&current.available);
                let previous = std::mem::replace(&mut *current, replacement);
                current.available.notify_all();
                drop(current);
                drop(previous);
                Ok(())
            },
            _ => Err(BootstrapKeyFailure::Custody),
        }
    }
    pub(in crate::data_protection::local_key) fn new(
        successor: BootstrapKeyCustody,
        source: RootAdmissionReceipt,
    ) -> Self {
        Self { successor, source }
    }
}
impl SystemLease {
    fn warm_system_key(
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
            .custody_system_key(&self.envelope, self.context)
            .map_err(|_| BootstrapKeyFailure::Custody)
    }
}
impl BootstrapKeyCustody {
    pub fn root_admission_receipt(&self) -> Result<RootAdmissionReceipt, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => Ok(RootAdmissionReceipt {
                identity: self.identity,
                epoch: self.root_epoch,
                revision: None,
                uncertain: false,
            }),
            RootCustody::Leased(owner) => {
                let lease = owner.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
                if lease.admission == LeaseAdmission::Closed {
                    return Err(BootstrapKeyFailure::Custody);
                }
                Ok(RootAdmissionReceipt {
                    identity: lease.identity,
                    epoch: lease.epoch,
                    revision: Some(lease.revision),
                    uncertain: lease.admission == LeaseAdmission::RotationUncertain,
                })
            },
        }
    }
    pub(in crate::data_protection::local_key) fn from_provider_cache(
        cache: KeyProviderCache<'static, CustodyKeyProvider>,
        context: EnvelopeContext,
        envelope: KeyEnvelope,
        identity: BootstrapKeyIdentity,
        anchor: BootstrapKeyIdentity,
        root_epoch: u64,
        authority: &crate::StorageKernelResourceAuthority,
    ) -> Result<Self, crate::data_protection::key_provider::KeyProviderFailure> {
        let policy = cache.lease();
        let system = SystemLease {
            cache: Some(cache),
            available: Arc::new(std::sync::Condvar::new()),
            context,
            envelope,
            identity,
            epoch: root_epoch,
            admission: LeaseAdmission::Ready,
            revision: 0,
            policy,
            references: Some((
                authority.snapshot_protection(),
                authority.shared_snapshot_barrier(),
            )),
        };
        #[cfg_attr(test, expect(clippy::arc_with_non_send_sync))]
        let owner = Arc::new(Mutex::new(system));
        Ok(Self {
            key: RootCustody::Leased(owner),
            identity,
            anchor,
            system: None,
            root_epoch,
        })
    }
    pub fn active_provider_identity(&self) -> Result<ProviderKeyUri, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => {
                LocalKeyProvider::identity_for_custody(self, self.root_epoch)
                    .map_err(|_| BootstrapKeyFailure::Custody)
            },
            RootCustody::Leased(lease) => Ok(lease
                .lock()
                .map_err(|_| BootstrapKeyFailure::Custody)?
                .envelope
                .identity()
                .clone()),
        }
    }
    /// Closes process-owned key derivation after final publication secrets have
    /// been acquired. Dropping the cache zeroizes its provider and resident keys
    /// before releasing the cache's transferred reservation.
    pub fn close_for_shutdown(&self) -> Result<(), BootstrapKeyFailure> {
        let RootCustody::Leased(lease) = &self.key else {
            return Err(BootstrapKeyFailure::Custody);
        };
        let mut lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
        lease.revision = lease
            .revision
            .checked_add(1)
            .ok_or(BootstrapKeyFailure::LimitExceeded)?;
        lease.admission = LeaseAdmission::Closed;
        lease.available.notify_all();
        let cache = lease.cache.take();
        drop(lease);
        drop(cache);
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
        lease.available.notify_all();
        lease.revision = lease
            .revision
            .checked_add(1)
            .ok_or(BootstrapKeyFailure::LimitExceeded)?;
        if let Some(cache) = lease.cache.as_mut() {
            cache.invalidate(
                crate::key_provider::KeyScope::System,
                crate::key_provider::CacheInvalidation::Rotation,
            );
        }
        Ok(())
    }
    pub(in crate::data_protection::local_key) fn stored_system_envelope(
        &self,
        instance: InstanceId,
    ) -> Result<Vec<u8>, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Leased(owner) => {
                let lease = owner.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
                if lease.admission == LeaseAdmission::Closed {
                    return Err(BootstrapKeyFailure::Custody);
                }
                if lease.context.instance != instance.to_bytes() {
                    return Err(BootstrapKeyFailure::Authentication);
                }
                Ok(lease.envelope.encode())
            },
            RootCustody::Bootstrap(_) => Err(BootstrapKeyFailure::Custody),
        }
    }
    pub(in crate::data_protection::local_key) fn control_system_key(
        &self,
        instance: InstanceId,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        match &self.key {
            RootCustody::Bootstrap(_) => self.system_kek(instance),
            RootCustody::Leased(lease) => {
                SystemLease::admit_key(lease, instance, KeyAdmission::Control)
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
        let (instance, revision) = {
            let lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
            if lease.identity != identity
                || lease.epoch != epoch
                || lease.admission == LeaseAdmission::Closed
            {
                return Err(BootstrapKeyFailure::Authentication);
            }
            (
                InstanceId::new(lease.context.instance)
                    .map_err(|_| BootstrapKeyFailure::Authentication)?,
                lease.revision,
            )
        };
        drop(SystemLease::admit_key(
            lease,
            instance,
            KeyAdmission::Confirmation,
        )?);
        let mut lease = lease.lock().map_err(|_| BootstrapKeyFailure::Custody)?;
        if lease.identity != identity
            || lease.epoch != epoch
            || lease.revision != revision
            || lease.admission == LeaseAdmission::Closed
        {
            return Err(BootstrapKeyFailure::Authentication);
        }
        lease.revision = lease
            .revision
            .checked_add(1)
            .ok_or(BootstrapKeyFailure::LimitExceeded)?;
        lease.admission = LeaseAdmission::Ready;
        lease.available.notify_all();
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
                .policy),
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
                        .custody_provider()
                        .local_root()
                        .map_err(|_| BootstrapKeyFailure::Custody)?,
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
        let cache = KeyProviderCache::from_owned_with_clock(
            CustodyKeyProvider::Local(provider),
            lease,
            1,
            reservation,
            clock,
        )
        .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        let mut system = SystemLease {
            cache: Some(cache),
            available: Arc::new(std::sync::Condvar::new()),
            context,
            envelope,
            identity,
            epoch: root_epoch,
            admission: LeaseAdmission::Ready,
            revision: 0,
            policy: lease,
            references: None,
        };
        drop(system.warm_system_key(instance)?);
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
