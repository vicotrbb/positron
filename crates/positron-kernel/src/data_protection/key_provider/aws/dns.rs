//! One admitted native resolver worker; cancellation never releases its owner.
use super::*;
use std::net::{IpAddr, SocketAddr};
mod resolver;
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct Resources {
    _grant: TransferredResourceReservation,
    dns_busy: AtomicBool,
    process_busy: AtomicBool,
}
impl Resources {
    pub(super) fn new(grant: TransferredResourceReservation) -> Arc<Self> {
        Arc::new(Self {
            _grant: grant,
            dns_busy: AtomicBool::new(false),
            process_busy: AtomicBool::new(false),
        })
    }
    pub(super) fn busy(&self) -> bool {
        self.dns_busy.load(Ordering::Acquire) || self.process_busy.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(super) struct ProcessAdmission(pub(super) Arc<Resources>);
struct ProcessLease(Arc<Resources>);
impl Drop for ProcessLease {
    fn drop(&mut self) {
        self.0.process_busy.store(false, Ordering::Release);
    }
}
impl aws_config::credential_process::CredentialProcessAdmission for ProcessAdmission {
    fn try_acquire(
        &self,
    ) -> Option<Box<dyn aws_config::credential_process::CredentialProcessLease>> {
        self.0
            .process_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Box::new(ProcessLease(self.0.clone())))
    }
}
#[derive(Clone, Debug)]
pub(super) struct NativeDns(pub(super) Arc<Resources>);
struct Worker(Arc<Resources>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.dns_busy.store(false, Ordering::Release);
    }
}
impl NativeDns {
    pub(super) async fn addresses(
        &self,
        name: &str,
    ) -> Result<Vec<SocketAddr>, KeyProviderFailure> {
        if name.is_empty() || name.len() > 253 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        self.0
            .dns_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| KeyProviderFailure::LimitExceeded)?;
        let worker = Arc::new(Worker(self.0.clone()));
        resolver::addresses(name, worker).await
    }
}
pub(super) fn collect_addresses(
    addresses: impl Iterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, KeyProviderFailure> {
    let mut result = Vec::with_capacity(16);
    for address in addresses.take(17) {
        if result.len() == 16 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        result.push(address);
    }
    if result.is_empty() {
        return Err(KeyProviderFailure::Unavailable);
    }
    Ok(result)
}
impl reqwest::dns::Resolve for NativeDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        if name.as_str().len() > 253 {
            return Box::pin(async {
                Err(Box::new(KeyProviderFailure::LimitExceeded)
                    as Box<dyn std::error::Error + Send + Sync>)
            });
        }
        let dns = self.clone();
        let name = name.as_str().to_owned();
        Box::pin(async move {
            dns.addresses(&name)
                .await
                .map(|addresses| Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
                .map_err(|failure| Box::new(failure) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

impl aws_smithy_runtime_api::client::dns::ResolveDns for NativeDns {
    fn resolve_dns<'a>(
        &'a self,
        name: &'a str,
    ) -> aws_smithy_runtime_api::client::dns::DnsFuture<'a> {
        aws_smithy_runtime_api::client::dns::DnsFuture::new(async move {
            self.addresses(name)
                .await
                .map(|addresses| {
                    addresses
                        .into_iter()
                        .map(|address| address.ip())
                        .collect::<Vec<IpAddr>>()
                })
                .map_err(aws_smithy_runtime_api::client::dns::ResolveDnsError::new)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_protection::tests::providers::provider_governor;
    #[test]
    fn canceled_native_process_retains_admission_until_confirmed_reap()
    -> Result<(), Box<dyn std::error::Error>> {
        use aws_credential_types::provider::ProvideCredentials;
        let kernel = provider_governor(200_000_000)?;
        let governor = kernel.governor();
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            AwsKmsKeyProvider::required_resources(),
        )?)?;
        let owner = Arc::new(ProcessAdmission(Resources::new(grant.transfer())));
        let root = crate::data_protection::local_key::test_support::SecurityRoot::create()?;
        let path = root.path.join("owned-native-child-pid");
        let command = format!(
            "printf '%s' \"$$\" > '{}'; exec sleep 60",
            path.to_string_lossy().replace('\'', "'\"'\"'")
        );
        let provider = aws_config::credential_process::CredentialProcessProvider::new(command)
            .with_admission(owner);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut refresh = Box::pin(provider.provide_credentials());
        let pid = runtime.block_on(async {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if let Ok(pid) = std::fs::read_to_string(&path)
                    .and_then(|value| value.parse::<i32>().map_err(std::io::Error::other))
                {
                    break Ok::<_, Box<dyn std::error::Error>>(pid);
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "owned native process did not start"
                );
                assert!(
                    tokio::time::timeout(Duration::from_millis(10), refresh.as_mut())
                        .await
                        .is_err()
                );
            }
        })?;
        let pid = rustix::process::Pid::from_raw(pid).ok_or("invalid child PID")?;
        drop(refresh);
        // Cleanup has been scheduled but its owner has not been polled yet.
        assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
        let replacement = {
            let mut replacement = std::pin::pin!(provider.provide_credentials());
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            match std::future::Future::poll(replacement.as_mut(), &mut context) {
                std::task::Poll::Ready(result) => {
                    result.err().ok_or("replacement process admitted")?
                },
                std::task::Poll::Pending => {
                    return Err("replacement process deferred instead of refusing".into());
                },
            }
        };
        assert_eq!(
            credential_failure(replacement),
            KeyProviderFailure::LimitExceeded
        );
        drop(provider);
        assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
        runtime.block_on(async {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while rustix::process::test_kill_process(pid).is_ok() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "owned native child survived cancellation"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
        Ok(())
    }
}
