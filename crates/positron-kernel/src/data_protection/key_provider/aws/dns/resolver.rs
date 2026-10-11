//! Bounded system DNS inputs and Hickory's reviewed wire parser.
use super::*;
use hickory_resolver::{
    Resolver,
    config::{LookupIpStrategy, ResolveHosts},
    net::runtime::{RuntimeProvider, Spawn, TokioRuntimeProvider},
};
use std::{future::Future, io, pin::Pin, sync::atomic::AtomicUsize};

#[derive(Clone)]
struct Runtime {
    native: TokioRuntimeProvider,
    owner: Arc<Worker>,
    tasks: Arc<AtomicUsize>,
}
impl Spawn for Runtime {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        if self
            .tasks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 4).then_some(count + 1)
            })
            .is_err()
        {
            return;
        }
        let owner = self.owner.clone();
        let tasks = self.tasks.clone();
        // The same admitted owner follows every background transport task.
        drop(tokio::spawn(
            async move {
                let _owner = owner;
                let _ = tokio::time::timeout(Duration::from_secs(2), future).await;
                tasks.fetch_sub(1, Ordering::AcqRel);
            }
            .with_subscriber(tracing::subscriber::NoSubscriber::default()),
        ));
    }
}
impl RuntimeProvider for Runtime {
    type Handle = Self;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Self {
        self.clone()
    }
    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tcp>> + Send>> {
        self.native.connect_tcp(server, bind, timeout)
    }
    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Udp>> + Send>> {
        self.native.bind_udp(local, server)
    }
}

pub(super) async fn addresses(
    name: &str,
    owner: Arc<Worker>,
) -> Result<Vec<SocketAddr>, KeyProviderFailure> {
    let fs = aws_types::os_shim_internal::Fs::real();
    let config_bytes = fs
        .read_to_end("/etc/resolv.conf")
        .await
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    let hosts_bytes = fs
        .read_to_end("/etc/hosts")
        .await
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    from_inputs(name, &config_bytes, &hosts_bytes, owner).await
}

async fn from_inputs(
    name: &str,
    config_bytes: &[u8],
    hosts_bytes: &[u8],
    owner: Arc<Worker>,
) -> Result<Vec<SocketAddr>, KeyProviderFailure> {
    if config_bytes.len() > 65_536 || hosts_bytes.len() > 65_536 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let hosts_text =
        std::str::from_utf8(hosts_bytes).map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    let mut aliases = 0_usize;
    for line in hosts_text.lines() {
        if line.len() > 1024 {
            return Err(KeyProviderFailure::LimitExceeded);
        }
        let line = line.split_once('#').map_or(line, |(before, _)| before);
        for name in line.split_whitespace().skip(1) {
            aliases += 1;
            if aliases > 512 || name.len() > 253 {
                return Err(KeyProviderFailure::LimitExceeded);
            }
        }
    }
    let parsed = resolv_conf::Config::parse(config_bytes)
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    if parsed.nameservers.len() > 4 || parsed.get_last_search_or_domain().count() > 6 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    if parsed.nameservers.is_empty() {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    let servers = parsed
        .nameservers
        .iter()
        .map(|ip| hickory_resolver::config::NameServerConfig::udp_and_tcp(ip.into()))
        .collect();
    let search = parsed
        .get_last_search_or_domain()
        .map(|name| {
            hickory_resolver::proto::rr::Name::from_str_relaxed(name)
                .map_err(|_| KeyProviderFailure::InvalidConfiguration)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let config = hickory_resolver::config::ResolverConfig::from_parts(None, search, servers);
    let mut options = hickory_resolver::config::ResolverOpts::default();
    options.ndots = (parsed.ndots as usize).min(15);
    options.timeout = Duration::from_secs(2);
    options.attempts = 1;
    options.cache_size = 0;
    options.use_hosts_file = ResolveHosts::Never;
    options.num_concurrent_reqs = 1;
    options.max_active_requests = 1;
    options.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
    options.preserve_intermediates = false;
    options.edns0 = false;
    let runtime = Runtime {
        native: TokioRuntimeProvider::default(),
        owner,
        tasks: Arc::new(AtomicUsize::new(0)),
    };
    let tasks = runtime.tasks.clone();
    let mut resolver = Resolver::builder_with_config(config, runtime)
        .with_options(options)
        .build()
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    let mut hosts = hickory_resolver::Hosts::default();
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        hosts.read_hosts_conf(hosts_bytes)
    })
    .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    resolver.set_hosts(Arc::new(hosts));
    let result = tokio::time::timeout(Duration::from_secs(2), resolver.lookup_ip(name))
        .with_subscriber(tracing::subscriber::NoSubscriber::default())
        .await
        .map_err(|_| KeyProviderFailure::Unavailable)?
        .map_err(|_| KeyProviderFailure::Unavailable)?;
    let addresses = collect_addresses(result.iter().map(|ip| SocketAddr::new(ip, 0)));
    drop(resolver);
    // A completed lookup closes its transport before another native identity
    // step can acquire the same slot. Canceled callers leave ownership in tasks.
    tokio::time::timeout(Duration::from_secs(2), async {
        while tasks.load(Ordering::Acquire) != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| KeyProviderFailure::Unavailable)?;
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_protection::tests::providers::provider_governor;
    fn owner(
        kernel: &crate::resource_governor::tests::resource_governor_test_support::TestKernel,
    ) -> Result<Arc<Worker>, Box<dyn std::error::Error>> {
        let grant = kernel.reserve(crate::WorkClaim::system_maintenance(
            AwsKmsKeyProvider::required_resources(),
        )?)?;
        let resources = Resources::new(grant.transfer());
        resources.dns_busy.store(true, Ordering::Release);
        Ok(Arc::new(Worker(resources)))
    }
    #[test]
    fn local_aliases_use_bounded_host_inputs_without_dns_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let kernel = provider_governor(200_000_000)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let addresses = runtime.block_on(from_inputs(
            "native-alias",
            b"nameserver 127.0.0.1\n",
            b"127.0.0.2 native-alias localhost\n",
            owner(&kernel)?,
        ))?;
        assert_eq!(addresses, vec!["127.0.0.2:0".parse::<SocketAddr>()?]);
        assert_eq!(kernel.governor().inspect()?.outstanding_reservations(), 0);
        let oversized = vec![b'x'; 65_537];
        assert_eq!(
            runtime
                .block_on(from_inputs(
                    "native-alias",
                    &oversized,
                    b"",
                    owner(&kernel)?
                ))
                .err(),
            Some(KeyProviderFailure::LimitExceeded)
        );
        assert_eq!(
            runtime
                .block_on(from_inputs(
                    "native-alias",
                    b"nameserver 127.0.0.1\n",
                    &[b'x'; 1025],
                    owner(&kernel)?
                ))
                .err(),
            Some(KeyProviderFailure::LimitExceeded)
        );
        assert_eq!(
            runtime
                .block_on(from_inputs(
                    "native-alias",
                    b"nameserver 127.0.0.1\nsearch a b c d e f g\n",
                    b"",
                    owner(&kernel)?
                ))
                .err(),
            Some(KeyProviderFailure::LimitExceeded)
        );
        assert_eq!(kernel.governor().inspect()?.outstanding_reservations(), 0);
        Ok(())
    }
    #[test]
    fn canceled_resolver_keeps_original_grant_until_actual_transport_task_finishes()
    -> Result<(), Box<dyn std::error::Error>> {
        let kernel = provider_governor(200_000_000)?;
        let governor = kernel.governor();
        let worker = owner(&kernel)?;
        let dns = NativeDns(worker.0.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let (started, start) = tokio::sync::oneshot::channel();
        runtime.block_on(async {
            let mut native = Runtime {
                native: TokioRuntimeProvider::default(),
                owner: worker,
                tasks: Arc::new(AtomicUsize::new(0)),
            };
            native.spawn_bg(async move {
                let _ = started.send(());
                let _ = released.await;
            });
            tokio::time::timeout(Duration::from_secs(1), start).await??;
            drop(native);
            assert_eq!(
                dns.addresses("localhost").await.err(),
                Some(KeyProviderFailure::LimitExceeded)
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        drop(dns);
        assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
        release
            .send(())
            .map_err(|_| "resolver task ended before release")?;
        runtime.block_on(async {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while governor.inspect()?.outstanding_reservations() != 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "resolver owner failed to reconcile"
                );
                tokio::task::yield_now().await;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        drop(runtime);
        Ok(())
    }
}
