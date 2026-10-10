//! Live segment capabilities retain ciphertext and the existing provider lease owner.
use super::*;
use std::sync::{Arc, Mutex};

#[cfg_attr(test, derive(Clone))]
pub(crate) struct LocalSegmentKeySource {
    lease: Arc<Mutex<system_lease::SystemLease>>,
    instance: InstanceId,
    scope: SegmentScope,
    envelope: Vec<u8>,
    _reference: Arc<crate::active_segment_ledger::snapshot_protection::SnapshotProtection>,
}

impl LocalSegmentKeySource {
    pub(crate) fn predecessor_route(
        &self,
        before: u64,
    ) -> Result<Option<crate::data_protection::SegmentEnvelopeRoute>, BootstrapKeyFailure> {
        tenant_epochs::predecessor_route(&self.envelope, before)
    }

    pub(crate) fn is_single_route(
        &self,
        route: crate::data_protection::SegmentEnvelopeRoute,
    ) -> Result<bool, BootstrapKeyFailure> {
        tenant_epochs::is_single_route(&self.envelope, route)
    }

    pub(crate) fn key(
        &self,
        route: crate::data_protection::SegmentEnvelopeRoute,
    ) -> Result<SecretKeyBytes, BootstrapKeyFailure> {
        // The shared owner enforces expiry, live zero-lease unwrap, and rotation
        // fencing before the temporary tenant/segment wrapping key is derived.
        let system = self
            .lease
            .lock()
            .map_err(|_| BootstrapKeyFailure::Custody)?
            .system_key(self.instance)?;
        tenant_epochs::segment_key_from_system(
            &system,
            self.instance,
            self.scope,
            &self.envelope,
            route,
        )
    }
}

impl BootstrapKeyCustody {
    pub(in crate::data_protection::local_key) fn retained_segment_context_bytes(
        &self,
        envelope: &[u8],
    ) -> usize {
        if matches!(self.key, RootCustody::Leased(_)) {
            envelope.len()
        } else {
            0
        }
    }
    pub(super) fn leased_segment_source(
        &self,
        instance: InstanceId,
        scope: SegmentScope,
        envelope: &[u8],
    ) -> Result<Option<LocalSegmentKeySource>, BootstrapKeyFailure> {
        let RootCustody::Leased(lease) = &self.key else {
            return Ok(None);
        };
        let (registry, barrier) = lease
            .lock()
            .map_err(|_| BootstrapKeyFailure::Custody)?
            .references
            .clone()
            .ok_or(BootstrapKeyFailure::Custody)?;
        let reference = tenant_epochs::register_segment_references(
            envelope,
            scope.tenant_id(),
            registry,
            &barrier,
        )?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(envelope.len())
            .map_err(|_| BootstrapKeyFailure::LimitExceeded)?;
        encoded.extend_from_slice(envelope);
        Ok(Some(LocalSegmentKeySource {
            lease: Arc::clone(lease),
            instance,
            scope,
            envelope: encoded,
            _reference: Arc::new(reference),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_protection::local_key::test_support::SecurityRoot;
    use positron_domain::routing::{SignalKind, VirtualShardId};

    #[test]
    fn shutdown_closes_cache_before_grant_release_and_refuses_retained_derivation()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::data_protection::key_provider::{KeyCacheLease, observe_cache_release};
        for duration in [
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(900),
        ] {
            let root = SecurityRoot::create()?;
            let successor_root = SecurityRoot::create()?;
            let custody = BootstrapKeyCustody::initialize(&root.path)?;
            let successor = BootstrapKeyCustody::initialize(&successor_root.path)?;
            let instance = InstanceId::new([0xe4; 16])?;
            let tenant = TenantId::from_bytes([0xe5; 16])?;
            let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
            let authority = crate::data_protection::recovery_tests::authority()?;
            let before = authority.governor().inspect()?;
            let session = crate::data_protection::local_key::RootRewrapSession::admit(&authority)?;
            let envelope = session.wrap_system(&custody, &successor, instance, 2)?;
            let key = session.lease_system(custody, instance, KeyCacheLease::new(duration)?)?;
            let activation = session.prepare_activation(&key, successor, instance, 2, &envelope)?;
            let tenant_envelope =
                key.provision_tenant_key_envelope(instance, tenant, [0xe6; 16], 1)?;
            let retained = key
                .leased_segment_source(instance, scope, &tenant_envelope)?
                .ok_or("leased reader")?;
            let route = crate::data_protection::SegmentEnvelopeRoute {
                provider_family: 1,
                provider_reference: [1; 16],
                provider_key_epoch: 1,
            };
            drop(retained.key(route)?);
            // The prepared replacement is separately admitted; discard it after
            // proving that closed custody cannot be reopened by activation.
            let (closed, released, zeroized) = observe_cache_release(|| key.close_for_shutdown());
            closed?;
            if duration != std::time::Duration::ZERO {
                assert!(released > 0);
            }
            assert!(zeroized);
            assert!(
                key.protect(
                    instance,
                    BootstrapObjectPurpose::Initialized,
                    b"after shutdown"
                )
                .is_err()
            );
            assert!(retained.key(route).is_err());
            assert!(key.invalidate_for_rotation().is_err());
            assert!(activation.activate(&key).is_err());
            key.close_for_shutdown()?;
            drop((retained, session));
            let after = authority.governor().inspect()?;
            assert_eq!(after.outstanding_total(), before.outstanding_total());
            assert_eq!(
                after.usage(crate::ResourceDimension::MemoryBytes),
                before.usage(crate::ResourceDimension::MemoryBytes)
            );
            assert_eq!(
                after.usage(crate::ResourceDimension::LeaseSlots),
                before.usage(crate::ResourceDimension::LeaseSlots)
            );
        }
        Ok(())
    }
}
