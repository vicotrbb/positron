use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use zeroize::Zeroizing;

pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

use crate::api_keys::{ApiKeyTransport, read_bounded_trust_file};

pub(crate) struct HttpClient {
    endpoint: String,
    client: reqwest::blocking::Client,
}

impl HttpClient {
    pub(crate) fn new(transport: ApiKeyTransport) -> Result<Self, ()> {
        let (endpoint, builder) = match transport {
            ApiKeyTransport::PlaintextOptOut { endpoint } => (
                format!("http://{endpoint}"),
                reqwest::blocking::Client::builder(),
            ),
            ApiKeyTransport::Tls {
                endpoint,
                server_name,
                trust_file,
            } => {
                let identity = server_name.parse::<IpAddr>();
                if server_name.is_empty()
                    || server_name.len() > 253
                    || identity.as_ref().is_ok_and(|ip| *ip != endpoint.ip())
                {
                    return Err(());
                }
                let authority = match identity {
                    Ok(IpAddr::V6(_)) => format!("[{server_name}]"),
                    _ => server_name.clone(),
                };
                let trust = read_bounded_trust_file(&trust_file)?;
                let certificate = reqwest::Certificate::from_pem(&trust).map_err(|_| ())?;
                (
                    format!("https://{authority}:{}", endpoint.port()),
                    reqwest::blocking::Client::builder()
                        .add_root_certificate(certificate)
                        .resolve(&server_name, endpoint),
                )
            },
        };
        let client = builder
            .connect_timeout(DEFAULT_REQUEST_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .no_proxy()
            .build()
            .map_err(|_| ())?;
        Ok(Self { endpoint, client })
    }

    /// Reads at most one byte beyond the operation's canonical response bound.
    /// Secret-bearing API-key responses retain zeroizing storage throughout.
    pub(crate) fn post(
        &self,
        bearer: &str,
        path: &str,
        body: Vec<u8>,
        response_limit: usize,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), ()> {
        self.post_with_timeout(bearer, path, body, response_limit, DEFAULT_REQUEST_TIMEOUT)
    }

    pub(crate) fn post_with_timeout(
        &self,
        bearer: &str,
        path: &str,
        body: Vec<u8>,
        response_limit: usize,
        timeout: Duration,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), ()> {
        if timeout.is_zero() {
            return Err(());
        }
        let query_probe = path == crate::log_query::HTTP_PATH
            && std::env::var_os("POSITRON_117_QUERY_PROBE").as_deref()
                == Some(std::ffi::OsStr::new("1"));
        let response = self
            .client
            .post(format!("{}{path}", self.endpoint))
            .bearer_auth(bearer)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(timeout.min(DEFAULT_REQUEST_TIMEOUT))
            .send()
            .inspect_err(|error| {
                if query_probe {
                    eprintln!(
                        "positron-query-probe stage=send timeout={}",
                        error.is_timeout()
                    );
                }
            })
            .map_err(|_| ())?;
        let status = response.status().as_u16();
        let limit = response_limit
            .checked_add(1)
            .and_then(|limit| u64::try_from(limit).ok())
            .ok_or(())?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(response_limit));
        response
            .take(limit)
            .read_to_end(&mut bytes)
            .inspect_err(|error| {
                if query_probe {
                    let timeout = error
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<reqwest::Error>())
                        .map_or("unknown", |source| {
                            if source.is_timeout() { "true" } else { "false" }
                        });
                    eprintln!("positron-query-probe stage=read timeout={timeout}");
                }
            })
            .map_err(|_| ())?;
        if bytes.len() > response_limit {
            return Err(());
        }
        Ok((status, bytes))
    }
}
