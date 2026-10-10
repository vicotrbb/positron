//! Real local custody is the shipped conformance target. Cloud families are
//! deliberately not simulated; their adapters run this harness on real services.
#![cfg(unix)]
use positron_kernel::BootstrapKeyCustody;
use positron_kernel::key_provider::{
    EnvelopeContext, KeyEnvelope, KeyProviderConformance, KeyScope, LocalKeyProvider,
    ProviderConformanceTarget, ProviderFamily,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::fs::canonicalize(std::env::temp_dir())?.join(format!(
            "positron-provider-integration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("local provider fixture cleanup failed: {error}");
        }
    }
}
fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("local provider deferred"),
    }
}
fn target() -> Result<ProviderConformanceTarget, Box<dyn std::error::Error>> {
    Ok(ProviderConformanceTarget::new(
        ProviderFamily::LocalFile,
        "Positron protected local-file provider",
        "v1",
        "native filesystem and pinned RustCrypto backend",
    )?)
}

#[test]
fn system_and_tenant_envelopes_pass_real_provider_migration_and_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let destination_root = Root::new()?;
    let source = LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&root.0)?)?;
    let destination =
        LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&destination_root.0)?)?;
    let tenant = positron_domain::identity::TenantId::from_bytes([3; 16])?;
    for scope in [KeyScope::System, KeyScope::Tenant(tenant)] {
        let context = EnvelopeContext::new([1; 16], scope, [2; 32], 7, 1)?;
        let first = ready(KeyProviderConformance::healthy(&source, target()?, context))?;
        let second = ready(first.rotation_and_migration(&source, &destination, target()?))?;
        ready(first.recovery(&source))?;
        ready(second.recovery(&destination))?;
    }
    Ok(())
}

#[test]
fn only_opaque_envelopes_survive_an_adapter_restart() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root::new()?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 7, 1)?;
    let provider = LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&root.0)?)?;
    let envelope = ready(provider.create_envelope(context))?;
    let encoded = envelope.encode();
    assert!(encoded.len() <= 9000);
    drop(provider);
    let provider = LocalKeyProvider::from_custody(BootstrapKeyCustody::open(&root.0)?)?;
    let recovered = KeyEnvelope::decode(&encoded)?;
    ready(provider.verify_envelope(&recovered, context))?;
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 8, 1)?;
    assert_eq!(
        ready(provider.verify_envelope(&recovered, wrong)),
        Err(positron_kernel::key_provider::KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}
