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

fn aws_provider(
    root: &Root,
) -> Result<
    (
        positron_kernel::StorageKernelResourceAuthority,
        positron_kernel::key_provider::AwsKmsKeyProvider,
        tokio::runtime::Runtime,
    ),
    Box<dyn std::error::Error>,
> {
    use positron_kernel::key_provider::{AwsKmsKeyProvider, ProviderKeyUri};
    use positron_kernel::{
        DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits, MountQualification,
        ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
        RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
        ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
        StorageKernelResourceAuthority, TenantQuota, WorkClaim, WorkKind,
    };
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let observed =
        ObservedResourceEnvironment::observe(&volume, RegisteredResourceBounds::new([1_000; 7])?)?;
    let detected = observed.detected_capacity();
    let capacity =
        ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| detected.amount(dimension)));
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(capacity)?,
        RecoveryReserve::new(ResourceAmounts::new([20; 11]))?,
        InventoryCardinalityLimits::new(1, 8)?,
        DiskPressureThresholds::new(disk / 10, disk / 5, disk / 3, disk / 2)?,
    )?;
    let tenant = positron_domain::identity::TenantId::from_bytes([31; 16])?;
    let required = AwsKmsKeyProvider::required_resources();
    let quota = ResourceAmounts::new(
        ResourceDimension::ALL.map(|dimension| required.get(dimension).max(3)),
    );
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, quota)?],
        OrdinaryPoolPolicy::new(
            quota,
            ResourceAmounts::new([2; 11]),
            ResourceAmounts::new([1; 11]),
            ResourceAmounts::new([1; 11]),
        )?,
    )?;
    let one = ResourceAmounts::new([1; 11]);
    let two = ResourceAmounts::new([2; 11]);
    let three = ResourceAmounts::new([3; 11]);
    let recovery = RecoveryPoolCapacities::new(three, two, three, two, three, one, one)?;
    let authority = StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, recovery)?,
    )?;
    let grant = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        required,
    )?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Construction installs the official chain but never resolves credentials.
    let provider = runtime.block_on(AwsKmsKeyProvider::from_standard_chain(
        ProviderKeyUri::new(
            ProviderFamily::AwsKms,
            "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "immutable",
        )?,
        grant,
    ))?;
    Ok((authority, provider, runtime))
}

#[test]
fn aws_custody_holds_admission_and_refuses_foreign_envelopes_without_identity_io()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::{KeyProviderFailure, ProviderKeyUri, WrappingAlgorithm};
    let root = Root::new()?;
    let (authority, provider, _runtime) = aws_provider(&root)?;
    let governor = authority.governor();
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 7, 1)?;
    let secrets = Root::new()?;
    let local = LocalKeyProvider::from_custody(BootstrapKeyCustody::initialize(&secrets.0)?)?;
    let envelope = ready(local.create_envelope(context))?;
    assert_eq!(
        ready(provider.verify_envelope(&envelope, context)),
        Err(KeyProviderFailure::WrongKey)
    );
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 8, 1)?;
    let envelope = KeyEnvelope::from_provider_response(
        ProviderKeyUri::new(
            ProviderFamily::AwsKms,
            "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "immutable",
        )?,
        context,
        WrappingAlgorithm::AwsKmsSymmetricDefault,
        vec![9; 48],
    )?;
    assert_eq!(
        ready(provider.verify_envelope(&envelope, wrong)),
        Err(KeyProviderFailure::ContextMismatch)
    );
    drop(provider);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn native_identity_failure_is_closed_before_http_and_reconciles_before_runtime_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::key_provider::KeyProviderFailure;
    const CHILD: &str = "POSITRON_TEST_AWS_IDENTITY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let root = Root::new()?;
        let config = root.0.join("config");
        std::fs::write(
            &config,
            "[default]\ncredential_process = printf 'credential-output-canary'\n",
        )?;
        let credentials = root.0.join("credentials");
        std::fs::write(&credentials, "")?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "native_identity_failure_is_closed_before_http_and_reconciles_before_runtime_shutdown", "--nocapture"])
            .env_clear()
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)))
            .env(CHILD, "1")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &root.0)
            .env("AWS_CONFIG_FILE", config)
            .env("AWS_SHARED_CREDENTIALS_FILE", credentials)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .status()?;
        assert!(status.success(), "isolated native identity contract failed");
        return Ok(());
    }
    let root = Root::new()?;
    let events = std::sync::Arc::new(std::sync::Mutex::new(
        zeroize::Zeroizing::new(String::new()),
    ));
    tracing::subscriber::set_global_default(IdentityEvents(events.clone()))?;
    let (authority, provider, runtime) = aws_provider(&root)?;
    let governor = authority.governor();
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 7, 1)?;
    let failure = runtime
        .block_on(provider.create_envelope(context))
        .err()
        .ok_or("native identity failure unexpectedly produced an envelope")?;
    assert_eq!(failure, KeyProviderFailure::Unavailable);
    assert!(!format!("{failure:?}{failure}").contains("credential-output-canary"));
    assert!(
        !events
            .lock()
            .map_err(|_| "event capture poisoned")?
            .contains("credential-output-canary")
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    drop(provider);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    drop(runtime);
    Ok(())
}

struct IdentityEvents(std::sync::Arc<std::sync::Mutex<zeroize::Zeroizing<String>>>);
impl tracing::Subscriber for IdentityEvents {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields<'a>(&'a mut String);
        impl tracing::field::Visit for Fields<'_> {
            fn record_debug(&mut self, _: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                if self.0.len() < 65_536 {
                    let _ = write!(self.0, "{value:?}");
                }
            }
        }
        if let Ok(mut bytes) = self.0.lock() {
            event.record(&mut Fields(&mut bytes));
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
