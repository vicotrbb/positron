use super::super as protection;
use super::super::key_provider::{
    EnvelopeContext, KeyProviderSession, KeyScope, LocalKeyProvider, SecretKek,
};
use super::super::key_provider::{KeyProviderFailure, ProviderFamily, ProviderKeyUri};
use crate::resource_governor::tests::resource_governor_test_support as governor_support;

fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("local provider unexpectedly deferred"),
    }
}

struct ControlledLocal {
    inner: LocalKeyProvider,
    failure: std::cell::Cell<Option<KeyProviderFailure>>,
    calls: std::cell::Cell<usize>,
    probe_failure: std::cell::Cell<Option<KeyProviderFailure>>,
    wrap_failure: std::cell::Cell<Option<KeyProviderFailure>>,
}
impl super::super::key_provider::KeyProvider for ControlledLocal {
    fn credential_model(&self) -> &super::super::key_provider::ProviderCredentialModel {
        self.inner.credential_model()
    }
    fn identity(&self) -> &ProviderKeyUri {
        self.inner.identity()
    }
    async fn probe(
        &self,
        context: EnvelopeContext,
    ) -> Result<super::super::key_provider::ProviderCapabilities, KeyProviderFailure> {
        if let Some(failure) = self.probe_failure.get() {
            return Err(failure);
        }
        if let Some(failure) = self.failure.get() {
            return Err(failure);
        }
        self.inner.probe(context).await
    }
    async fn wrap(
        &self,
        payload: super::super::key_provider::SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<super::super::key_provider::KeyEnvelope, KeyProviderFailure> {
        if let Some(failure) = self.wrap_failure.get() {
            return Err(failure);
        }
        self.inner.wrap(payload, context).await
    }
    async fn unwrap(
        &self,
        envelope: &super::super::key_provider::KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<super::super::key_provider::SecretWrappedKeyPayload, KeyProviderFailure> {
        self.calls.set(self.calls.get() + 1);
        if let Some(failure) = self.failure.get() {
            return Err(failure);
        }
        self.inner.unwrap(envelope, context).await
    }
}
pub(in crate::data_protection) fn cache_governor()
-> Result<governor_support::TestKernel, Box<dyn std::error::Error>> {
    provider_governor(20_000_000)
}
pub(in crate::data_protection) fn provider_governor(
    amount: u64,
) -> Result<governor_support::TestKernel, Box<dyn std::error::Error>> {
    use crate::*;
    let total = ResourceAmounts::new([amount; 11]);
    let raw = governor_support::raw_capacity_for_governed_work(total, 8)?;
    let reserve = governor_support::minimum_recovery_reserve_for_tenants(1)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw)?,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(ResourceAmounts::new([reserve; 11]))?,
        InventoryCardinalityLimits::new(1, 8)?,
        DiskPressureThresholds::new(reserve, reserve + 1, reserve + 2, reserve + 3)?,
        DiskObservation::new(20_000_000),
    )?;
    let tenant = positron_domain::identity::TenantId::from_bytes([31; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(
            tenant,
            1,
            ResourceAmounts::new([amount / 2; 11]),
        )?],
        OrdinaryPoolPolicy::new(
            ResourceAmounts::new([amount / 5; 11]),
            ResourceAmounts::new([amount * 3 / 20; 11]),
            ResourceAmounts::new([amount / 10; 11]),
            ResourceAmounts::new([amount / 20; 11]),
        )?,
    )?;
    governor_support::TestKernel::establish(inventory, policy)
}
pub(in crate::data_protection) fn cache_reservation(
    kernel: &governor_support::TestKernel,
    capacity: usize,
) -> Result<crate::ResourceReservation<'_>, Box<dyn std::error::Error>> {
    use super::super::key_provider::KeyProviderCache;
    let memory = KeyProviderCache::<LocalKeyProvider>::required_memory_bytes(capacity)?;
    let amounts = crate::ResourceAmounts::new([memory, 0, 0, 0, 0, capacity as u64, 0, 0, 0, 0, 0]);
    Ok(kernel.reserve(crate::WorkClaim::system_maintenance(amounts)?)?)
}

mod cache;
mod conformance;
mod contracts;

mod audit;
