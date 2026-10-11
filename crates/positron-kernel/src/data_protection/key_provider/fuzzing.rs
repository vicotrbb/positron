use super::*;
use crate::data_protection::{CryptoBackend, RustCryptoBackend, SecretKeyBytes};
use std::cell::Cell;
use std::time::{Duration, Instant};

pub fn fuzz_key_provider_envelope(data: &[u8]) {
    let bounded = data.get(..data.len().min(9001)).unwrap_or_default();
    if let Ok(envelope) = KeyEnvelope::decode(bounded) {
        assert_eq!(KeyEnvelope::decode(&envelope.encode()), Ok(envelope));
    }
    // Pure bounded native wire decoding, never an emulated named provider.
    let aws = ProviderKeyUri::new(
        ProviderFamily::AwsKms,
        "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "immutable",
    )
    .expect("published AWS example identity");
    let _ = aws::protocol::verify_metadata(bounded, &aws);
    drop(aws::protocol::wrapped_response(bounded, &aws));
    drop(aws::protocol::plaintext_response(bounded, &aws));
    for operation in [
        aws::protocol::Operation::Describe,
        aws::protocol::Operation::Encrypt,
        aws::protocol::Operation::Decrypt,
    ] {
        let status = 400 + u16::from(bounded.first().copied().unwrap_or_default());
        let _ = aws::protocol::classify(operation, status, bounded);
    }
    let context =
        EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1).expect("fixed context");
    let identity = ProviderKeyUri::new(ProviderFamily::LocalFile, "fuzz-local-corpus", "v1")
        .expect("fixed identity");
    if let Ok(payload) = SecretWrappedKeyPayload::from_provider_plaintext(bounded.to_vec()) {
        // Exercise canonical Protobuf validation and secret release, without
        // exposing the recovered key or printing untrusted plaintext.
        drop(payload.verify(context, &identity));
    }
}

// Fuzz-only corpus adapter for the local algorithm and port failure boundary.
// It is not a named external provider or a provider conformance claim.
struct CorpusProvider {
    identity: ProviderKeyUri,
    root: SecretKeyBytes,
    unavailable: Cell<bool>,
}
impl KeyProvider for CorpusProvider {
    fn identity(&self) -> &ProviderKeyUri {
        &self.identity
    }
    fn credential_model(&self) -> &ProviderCredentialModel {
        &ProviderCredentialModel::LocalFile
    }
    async fn probe(
        &self,
        _context: EnvelopeContext,
    ) -> Result<ProviderCapabilities, KeyProviderFailure> {
        if self.unavailable.get() {
            return Err(KeyProviderFailure::Unavailable);
        }
        Ok(ProviderCapabilities {
            interface_version: 1,
            identity: self.identity.clone(),
            verified_tls: false,
            can_wrap: true,
            can_unwrap: true,
        })
    }
    async fn wrap(
        &self,
        payload: SecretWrappedKeyPayload,
        context: EnvelopeContext,
    ) -> Result<KeyEnvelope, KeyProviderFailure> {
        if self.unavailable.get() {
            return Err(KeyProviderFailure::Unavailable);
        }
        let ciphertext = RustCryptoBackend
            .wrap_key_aes_256_kwp(&self.root, payload.as_provider_plaintext())
            .map_err(|_| KeyProviderFailure::ContextMismatch)?;
        KeyEnvelope::from_provider_response(
            self.identity.clone(),
            context,
            WrappingAlgorithm::Aes256Kwp,
            ciphertext,
        )
    }
    async fn unwrap(
        &self,
        envelope: &KeyEnvelope,
        context: EnvelopeContext,
    ) -> Result<SecretWrappedKeyPayload, KeyProviderFailure> {
        if self.unavailable.get() {
            return Err(KeyProviderFailure::Unavailable);
        }
        envelope.check(&self.identity, context)?;
        RustCryptoBackend
            .unwrap_key_aes_256_kwp(&self.root, envelope.ciphertext())
            .map(SecretWrappedKeyPayload)
            .map_err(|_| KeyProviderFailure::ContextMismatch)
    }
}
fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("corpus adapter is synchronous"),
    }
}
pub fn fuzz_key_cache_stateful(data: &[u8]) {
    if let Err(failure) = cache_scenario(data) {
        panic!("fixed cache fixture failed: {failure}");
    }
}
fn cache_scenario(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::*;
    let provider = CorpusProvider {
        identity: ProviderKeyUri::new(ProviderFamily::LocalFile, "fuzz-local-corpus", "v1")?,
        root: SecretKeyBytes::from_owned(Box::new([73; 32])),
        unavailable: Cell::new(false),
    };
    let system = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let tenant = positron_domain::identity::TenantId::from_bytes([3; 16])?;
    let tenant_context = EnvelopeContext::new([1; 16], KeyScope::Tenant(tenant), [4; 32], 1, 1)?;
    let session = KeyProviderSession::new(&provider);
    let system_envelope = ready(session.wrap(SecretKek::generate()?, system))?;
    let tenant_envelope = ready(session.wrap(SecretKek::generate()?, tenant_context))?;
    let uniform = |value| ResourceAmounts::new([value; 11]);
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(uniform(4_000_000))?,
        OperatorLimits::new(uniform(4_000_000))?,
        RecoveryReserve::new(uniform(12))?,
        InventoryCardinalityLimits::new(1, 8)?,
        DiskPressureThresholds::new(12, 13, 14, 15)?,
        DiskObservation::new(4_000_000),
    )?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(2_000_000))?],
        OrdinaryPoolPolicy::new(
            uniform(800_000),
            uniform(600_000),
            uniform(400_000),
            uniform(200_000),
        )?,
    )?;
    let recovery = RecoveryPoolCapacities::new(
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(1),
    )?;
    let kernel = StorageKernelResourceAuthority::establish_for_fuzz(inventory, policy, recovery)?;
    let memory = KeyProviderCache::<CorpusProvider>::required_memory_bytes(2)?;
    let reservation =
        kernel
            .governor()
            .reserve(WorkClaim::system_maintenance(ResourceAmounts::new([
                memory, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
            ]))?)?;
    let clock = Cell::new(Instant::now());
    let lease = KeyCacheLease::new(Duration::from_secs(u64::from(
        data.first().copied().unwrap_or(1) % 4,
    )))?;
    let mut cache = KeyProviderCache::with_clock(&provider, lease, 2, reservation, || clock.get())?;
    let object = crate::data_protection::FrameObjectContext::system(
        crate::data_protection::SystemObjectKind::Catalog,
        crate::data_protection::FrameObjectId::new([5; 16])?,
        crate::data_protection::KeyEpoch::new(1),
        crate::data_protection::FrameFormatEpoch::new(1)?,
    );
    let object_key = crate::data_protection::ObjectDataKey::generate(object)?;
    for operation in data.iter().take(128) {
        match operation % 10 {
            0 => {
                check_outcome(ready(cache.load(&system_envelope, system)));
            },
            1 => {
                check_outcome(ready(cache.load(&tenant_envelope, tenant_context)));
            },
            2 => clock.set(clock.get() + Duration::from_secs(1)),
            3 => provider.unavailable.set(true),
            4 => provider.unavailable.set(false),
            5 => cache.invalidate(KeyScope::System, CacheInvalidation::Rotation),
            6 => cache.invalidate(
                KeyScope::Tenant(tenant),
                CacheInvalidation::AdministrativePurge,
            ),
            7 => {
                check_outcome(ready(cache.verify_live(system)));
            },
            8 => {
                let result =
                    ready(cache.wrap_object_key_live(&system_envelope, system, &object_key));
                match result {
                    Ok(ciphertext) => check_outcome(
                        ready(cache.open_object_key_live(
                            &system_envelope,
                            system,
                            &ciphertext,
                            object,
                        ))
                        .map(drop),
                    ),
                    Err(failure) => check_outcome(Err(failure)),
                }
            },
            _ => {
                check_outcome(
                    ready(cache.open_object_key_live(&system_envelope, system, data, object))
                        .map(drop),
                );
            },
        }
        assert!(cache.resident_keys() <= 2);
        assert_eq!(
            kernel
                .governor()
                .inspect()?
                .usage(ResourceDimension::MemoryBytes),
            memory
        );
    }
    drop(cache);
    assert_eq!(
        kernel
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        0
    );
    Ok(())
}

fn check_outcome(outcome: Result<(), KeyProviderFailure>) {
    if let Err(failure) = outcome {
        assert!(matches!(
            failure,
            KeyProviderFailure::Unavailable
                | KeyProviderFailure::ContextMismatch
                | KeyProviderFailure::LimitExceeded
                | KeyProviderFailure::MemoryProtection
        ));
    }
}
