//! Monotonic, governor-accounted KEK leases. No provider call on a child-key path.
use super::*;
use crate::data_protection::SecretKeyBytes;
use crate::{ResourceDimension, ResourceReservation};
use std::time::{Duration, Instant};
mod memory;
mod object;
mod object_admission;
use memory::{BLOCK_BYTES, LockedKek};
#[cfg(test)]
pub(in crate::data_protection) use memory::{observe_cache_release, with_cache_lock_failure};
// Includes construction's aligned block and bounded codec/backend temporaries.
const SCRATCH_BYTES: usize = 2 * BLOCK_BYTES + 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCacheLease(Duration);
impl Default for KeyCacheLease {
    fn default() -> Self {
        Self(Duration::from_secs(900))
    }
}
impl KeyCacheLease {
    pub fn new(duration: Duration) -> Result<Self, KeyProviderFailure> {
        if duration > Duration::from_secs(3600) {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(Self(duration))
    }
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheInvalidation {
    Rotation,
    Revocation,
    CredentialReload,
    AdministrativePurge,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyCacheHealth {
    pub provider_degraded: bool,
    pub system_ready: bool,
    pub storage_unhealthy: bool,
}

struct Entry {
    context: EnvelopeContext,
    envelope_digest: [u8; 32],
    deadline: Instant,
    key: LockedKek,
}

/// Owning lease authority. The reservation cannot be resized or released while
/// keys remain resident. The clock must be the runtime's monotonic process clock.
/// Clock injection allows the same public outcomes to be tested without sleeps.
pub struct KeyProviderCache<'a, P, C = fn() -> Instant> {
    session: KeyProviderSession<'a, P>,
    lease: KeyCacheLease,
    entries: Vec<Entry>,
    capacity: usize,
    clock: C,
    last_now: Instant,
    health: KeyCacheHealth,
    required_system: Option<EnvelopeContext>,
    live_verified: bool,
    zero_system_verified: bool,
    // Last field releases accounted memory only after resident keys are dropped.
    _reservation: ResourceReservation<'a>,
}
impl<'a, P: KeyProvider> KeyProviderCache<'a, P> {
    pub fn new(
        provider: &'a P,
        lease: KeyCacheLease,
        capacity: usize,
        reservation: ResourceReservation<'a>,
    ) -> Result<Self, KeyProviderFailure> {
        Self::with_clock(provider, lease, capacity, reservation, Instant::now)
    }
}
impl<'a, P: KeyProvider, C: Fn() -> Instant> KeyProviderCache<'a, P, C> {
    pub fn required_memory_bytes(capacity: usize) -> Result<u64, KeyProviderFailure> {
        if capacity == 0 || capacity > 128 {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let bytes = capacity
            // Account for at most one alignment padding span per allocation.
            .checked_mul(2 * BLOCK_BYTES + std::mem::size_of::<Entry>())
            .and_then(|size| size.checked_add(SCRATCH_BYTES))
            .ok_or(KeyProviderFailure::LimitExceeded)?;
        u64::try_from(bytes).map_err(|_| KeyProviderFailure::LimitExceeded)
    }
    pub fn with_clock(
        provider: &'a P,
        lease: KeyCacheLease,
        capacity: usize,
        reservation: ResourceReservation<'a>,
        clock: C,
    ) -> Result<Self, KeyProviderFailure> {
        let required = Self::required_memory_bytes(capacity)?;
        if !reservation.is_active()
            || reservation.granted().get(ResourceDimension::MemoryBytes) < required
            || reservation.granted().get(ResourceDimension::LeaseSlots) < capacity as u64
        {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(capacity)
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        if entries.capacity() != capacity {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let last_now = clock();
        Ok(Self {
            session: KeyProviderSession::new(provider),
            lease,
            entries,
            capacity,
            clock,
            last_now,
            required_system: None,
            live_verified: false,
            zero_system_verified: false,
            health: KeyCacheHealth {
                provider_degraded: false,
                system_ready: false,
                storage_unhealthy: false,
            },
            _reservation: reservation,
        })
    }
    fn expire(&mut self) -> Instant {
        let now = (self.clock)().max(self.last_now);
        self.last_now = now;
        self.entries.retain(|entry| entry.deadline > now);
        self.health.system_ready = if self.lease.0.is_zero() {
            self.zero_system_verified
                && !self.health.provider_degraded
                && !self.health.storage_unhealthy
        } else {
            self.entries
                .iter()
                .any(|entry| Some(entry.context) == self.required_system)
        };
        now
    }
    #[must_use]
    pub fn health(&mut self) -> KeyCacheHealth {
        self.expire();
        self.health
    }
    #[must_use]
    pub fn resident_keys(&mut self) -> usize {
        self.expire();
        self.entries.len()
    }
    /// Startup/restore always call the live probe, regardless of cached leases.
    pub async fn verify_live(
        &mut self,
        context: EnvelopeContext,
    ) -> Result<(), KeyProviderFailure> {
        self.ensure_healthy()?;
        let result = self.session.verify_live(context).await;
        self.record(&result);
        if result.is_ok() {
            self.live_verified = true;
        }
        result
    }
    pub async fn load(
        &mut self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<(), KeyProviderFailure> {
        self.ensure_healthy()?;
        let now = self.expire();
        if context.scope == KeyScope::System && self.required_system.is_none() {
            self.required_system = Some(context);
        }
        let digest = crate::data_protection::DataProtection::hash(&envelope.encode())
            .map_err(|_| KeyProviderFailure::ContextMismatch)?;
        if self
            .entries
            .iter()
            .any(|entry| entry.context == context && entry.envelope_digest == digest)
        {
            return Ok(());
        }
        if !self.live_verified {
            self.verify_live(context).await?;
        }
        let result = self.session.unwrap(envelope, context).await;
        self.record(&result);
        let key = result?;
        // A zero lease permits the live verification but retains no plaintext.
        if self.lease.0.is_zero() {
            if context.scope == KeyScope::System {
                self.zero_system_verified = true;
            }
            self.expire();
            return Ok(());
        }
        self.entries.retain(|entry| entry.context != context);
        if self.entries.len() == self.capacity {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let deadline = now
            .checked_add(self.lease.0)
            .ok_or(KeyProviderFailure::InvalidConfiguration)?;
        // Lease begins before provider I/O, so slow responses cannot extend it.
        if (self.clock)() >= deadline {
            return Err(KeyProviderFailure::Unavailable);
        }
        let key = LockedKek::new(key)?;
        self.entries.push(Entry {
            context,
            envelope_digest: digest,
            deadline,
            key,
        });
        self.health.system_ready = self
            .entries
            .iter()
            .any(|entry| Some(entry.context) == self.required_system);
        Ok(())
    }
    pub(super) fn record<T>(&mut self, result: &Result<T, KeyProviderFailure>) {
        match result {
            Ok(_) => self.health.provider_degraded = false,
            Err(KeyProviderFailure::ContextMismatch | KeyProviderFailure::WrongKey) => {
                self.zero_system_verified = false;
                self.health.storage_unhealthy = true;
                self.entries.clear();
                self.health.system_ready = false;
            },
            Err(_) => {
                self.zero_system_verified = false;
                self.health.provider_degraded = true;
            },
        }
    }
    /// Rotation, revocation and purge remove matching scope/epoch immediately.
    /// Credential reload clears every lease held by this provider authority.
    pub fn invalidate(&mut self, scope: KeyScope, cause: CacheInvalidation) {
        if scope == KeyScope::System || cause == CacheInvalidation::CredentialReload {
            self.required_system = None;
            self.live_verified = false;
            self.zero_system_verified = false;
        }
        if cause == CacheInvalidation::CredentialReload {
            self.entries.clear();
        } else {
            self.entries.retain(|entry| entry.context.scope != scope);
        }
        self.expire();
    }
    fn key(&mut self, context: EnvelopeContext) -> Result<SecretKeyBytes, KeyProviderFailure> {
        self.expire();
        self.ensure_healthy()?;
        self.entries
            .iter()
            .find(|entry| entry.context == context)
            .ok_or(KeyProviderFailure::Unavailable)?
            .key
            .temporary_key()
    }
    fn ensure_healthy(&self) -> Result<(), KeyProviderFailure> {
        if self.health.storage_unhealthy {
            Err(KeyProviderFailure::ContextMismatch)
        } else {
            Ok(())
        }
    }
    fn record_integrity<T>(&mut self, result: &Result<T, KeyProviderFailure>) {
        if matches!(
            result,
            Err(KeyProviderFailure::ContextMismatch | KeyProviderFailure::WrongKey)
        ) {
            self.record(result);
        }
    }
}
