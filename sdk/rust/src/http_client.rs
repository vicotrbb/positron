use std::io::{Read, Write};
use std::net::IpAddr;
use std::time::Duration;

use zeroize::Zeroizing;

pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const DEFAULT_LISTENER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
                if !server_name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
                }) || server_name.is_empty()
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
        self.post_bounded(
            bearer,
            path,
            body,
            response_limit,
            timeout.min(DEFAULT_REQUEST_TIMEOUT),
        )
    }

    pub(crate) fn post_with_default_listener_timeout(
        &self,
        bearer: &str,
        path: &str,
        body: Vec<u8>,
        response_limit: usize,
        timeout: Duration,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), ()> {
        self.post_bounded(
            bearer,
            path,
            body,
            response_limit,
            timeout.min(DEFAULT_LISTENER_REQUEST_TIMEOUT),
        )
    }

    pub(crate) fn post_query(
        &self,
        bearer: &str,
        path: &str,
        body: Vec<u8>,
        response_limit: usize,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), ()> {
        self.post_bounded(
            bearer,
            path,
            body,
            response_limit,
            DEFAULT_LISTENER_REQUEST_TIMEOUT,
        )
    }

    fn post_bounded(
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
        let response = match self
            .client
            .post(format!("{}{path}", self.endpoint))
            .bearer_auth(bearer)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(timeout)
            .send()
        {
            Ok(response) => response,
            Err(error) => {
                let phase = if error.is_timeout() {
                    "send_timeout"
                } else {
                    "send_other"
                };
                execute_failure_probe(path, phase, None)?;
                return Err(());
            },
        };
        let status = response.status().as_u16();
        let limit = response_limit
            .checked_add(1)
            .and_then(|limit| u64::try_from(limit).ok())
            .ok_or(())?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(response_limit));
        if let Err(error) = response.take(limit).read_to_end(&mut bytes) {
            let timeout = error.kind() == std::io::ErrorKind::TimedOut
                || error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout);
            execute_failure_probe(
                path,
                if timeout {
                    "read_timeout"
                } else {
                    "read_other"
                },
                None,
            )?;
            return Err(());
        }
        if bytes.len() > response_limit {
            execute_failure_probe(path, "response_bound", None)?;
            return Err(());
        }
        Ok((status, bytes))
    }
}

// TEMPORARY SDK127 Nix experiment. Remove every probe before merge.
// Only finite Execute errors reach stderr; failed writes retain that same failure.
pub(crate) fn execute_failure_probe(
    path: &str,
    phase: &'static str,
    response: Option<(u16, usize)>,
) -> Result<(), ()> {
    if path != crate::log_query::HTTP_PATH {
        return Ok(());
    }
    let line = match response {
        Some((status, bytes)) => {
            format!("POSITRON_SDK127_PROBE {phase} status={status} bytes={bytes}\n")
        },
        None => format!("POSITRON_SDK127_PROBE {phase}\n"),
    };
    std::io::stderr()
        .lock()
        .write_all(line.as_bytes())
        .map_err(|_| ())
}
