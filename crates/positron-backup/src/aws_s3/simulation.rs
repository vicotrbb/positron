//! Optional loopback simulation transport; never a native qualification path.
use super::*;
impl AwsS3Repository {
    /// Uses literal dummy credentials and only a loopback socket, without reading
    /// native credentials/configuration or changing the canonical target identity.
    pub fn from_local_simulator(
        target: AwsS3Target,
        identity: RepositoryIdentity,
        resources: Arc<NativeAwsResources>,
        address: std::net::SocketAddr,
    ) -> Result<Self, RepositoryFailure> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(RepositoryFailure::InvalidInput);
        }
        if identity.provider_kind() != "awsS3"
            || identity.prefix_commitment() != target.commitment()
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        if ResourceDimension::ALL.iter().any(|dimension| {
            resources.granted().get(*dimension) < Self::required_resources().get(*dimension)
        }) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if !resources.authorizes_repository_transport() {
            return Err(RepositoryFailure::PermissionDenied);
        }
        let endpoint = format!("http://{address}");
        let http = aws_smithy_http_client::Builder::new()
            .pool_max_idle_per_host(1)
            .pool_idle_timeout(Duration::from_secs(5))
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_with_resolver(NativeAwsDns::new(resources.clone()));
        let http = http::BoundedClient::new(http, resources.clone(), &target)
            .with_simulation_endpoint(&target, &endpoint);
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_config::BehaviorVersion::v2026_01_12())
            .region(aws_sdk_s3::config::Region::new(target.region().to_owned()))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .disable_multi_region_access_points(true)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "local-simulation",
            ))
            .http_client(http)
            .retry_config(aws_smithy_types::retry::RetryConfig::standard().with_max_attempts(1))
            .timeout_config(
                aws_smithy_types::timeout::TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(2))
                    .read_timeout(Duration::from_secs(5))
                    .operation_attempt_timeout(Duration::from_secs(15))
                    .operation_timeout(Duration::from_secs(15))
                    .build(),
            )
            .build();
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(config),
            target,
            identity,
            resources,
            active: AtomicBool::new(false),
            listing: std::sync::Mutex::new(listing::State::new()?),
            faults: Default::default(),
        })
    }
}
