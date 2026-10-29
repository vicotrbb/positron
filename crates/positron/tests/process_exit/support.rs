use super::*;
#[cfg(unix)]
use std::time::Instant;

#[cfg(unix)]
pub(crate) struct ChildRoots {
    pub(crate) data: std::path::PathBuf,
    pub(crate) secrets: std::path::PathBuf,
}

#[cfg(unix)]
impl ChildRoots {
    pub(crate) fn new(root: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let data = root.join("data");
        let secrets = root.join("secrets");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&secrets)?;
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
        Ok(Self { data, secrets })
    }
}

#[cfg(unix)]
pub(crate) struct BlockedHost;

#[cfg(unix)]
impl positron_runtime::ListenerFactory for BlockedHost {
    fn bind(
        &self,
        request: positron_runtime::ListenerRequest,
    ) -> Result<Box<dyn positron_runtime::BoundListener>, positron_runtime::ListenerFailure> {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        let endpoint = if request.role() == positron_runtime::ListenerRole::Control {
            positron_runtime::BoundEndpoint::control(std::path::PathBuf::from(
                "/tmp/positron-blocked-child.sock",
            ))?
        } else {
            positron_runtime::BoundEndpoint::tcp(
                request.role(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_498)),
            )?
        };
        Ok(Box::new(ChildListener(endpoint)))
    }
}

#[cfg(unix)]
struct ChildListener(positron_runtime::BoundEndpoint);

#[cfg(unix)]
impl positron_runtime::BoundListener for ChildListener {
    fn endpoint(&self) -> &positron_runtime::BoundEndpoint {
        &self.0
    }
}

#[cfg(unix)]
impl positron_runtime::TaskRegistrar for BlockedHost {
    fn register(
        &self,
        _role: positron_runtime::TaskRole,
    ) -> Result<Box<dyn positron_runtime::RegisteredTask>, positron_runtime::TaskFailure> {
        Ok(Box::new(BlockedTask))
    }
}

#[cfg(unix)]
struct BlockedTask;

#[cfg(unix)]
impl positron_runtime::RegisteredTask for BlockedTask {
    fn spawn(
        self: Box<Self>,
        cancellation: positron_runtime::TaskCancellation,
        _health: positron_runtime::HealthState,
        _services: Option<positron_runtime::ServiceHandle>,
    ) -> Result<Box<dyn positron_runtime::RunningTask>, positron_runtime::TaskFailure> {
        Ok(Box::new(BlockedTaskHandle(cancellation)))
    }
}

#[cfg(unix)]
struct BlockedTaskHandle(positron_runtime::TaskCancellation);

#[cfg(unix)]
impl positron_runtime::RunningTask for BlockedTaskHandle {
    fn poll_join(
        &mut self,
    ) -> Result<Option<positron_runtime::TaskJoinOutcome>, positron_runtime::TaskFailure> {
        assert!(self.0.is_cancelled());
        Ok(None)
    }

    fn join_within(
        &mut self,
        remaining: std::time::Duration,
    ) -> Result<positron_runtime::TaskJoinOutcome, positron_runtime::TaskFailure> {
        assert!(
            remaining <= std::time::Duration::from_millis(10),
            "blocked child join must remain interruptible"
        );
        std::thread::sleep(remaining);
        Ok(positron_runtime::TaskJoinOutcome::DeadlineExpired)
    }

    fn abort(&mut self) -> Result<(), positron_runtime::TaskFailure> {
        assert!(self.0.is_cancelled());
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn wait_for_ready(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_readiness(port, "HTTP/1.1 200 ")
}

// The existing 100 × 25ms polling allowance is one absolute window. Callers
// composing readiness and status share this deadline instead of resetting it.
#[cfg(unix)]
pub(crate) const STARTUP_PROBE_BUDGET: Duration = Duration::from_millis(2500);
#[cfg(unix)]
const PROBE_INTERVAL: Duration = Duration::from_millis(25);
#[cfg(unix)]
const PROBE_IO_LIMIT: Duration = Duration::from_millis(100);

#[cfg(unix)]
pub(crate) fn wait_for_configuration_status(
    port: u16,
    authorization: &str,
    expected_fragments: &[&str],
    deadline: Instant,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut last_observation = None;
    for _ in 0..100 {
        if Instant::now() >= deadline {
            break;
        }
        let response =
            configuration_status_until(port, authorization, deadline).map_err(|error| {
                format!("configuration status request failed: {error}; last={last_observation:?}")
            })?;
        let expected = response.starts_with("HTTP/1.1 200 ");
        if expected
            && expected_fragments
                .iter()
                .all(|fragment| response.contains(fragment))
        {
            return Ok(response);
        }
        let observation = bounded_redacted_observation(&response, authorization);
        if !expected && !response.starts_with("HTTP/1.1 503 ") {
            return Err(format!(
                "configuration status refused an unexpected response: {observation}"
            )
            .into());
        }
        last_observation = Some(observation);
        std::thread::sleep(PROBE_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    Err(format!(
        "configuration status deadline expired before expected state: {}",
        last_observation.unwrap_or_else(|| "no request admitted within shared deadline".to_owned())
    )
    .into())
}

#[cfg(unix)]
pub(crate) fn configuration_status(
    port: u16,
    authorization: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    configuration_status_until(port, authorization, Instant::now() + PROBE_IO_LIMIT * 3)
}

#[cfg(unix)]
fn configuration_status_until(
    port: u16,
    authorization: &str,
    deadline: Instant,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = format!(
        "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nContent-Length: 0\r\n\r\n"
    );
    probe_response(port, request.as_bytes(), deadline)
}

#[cfg(unix)]
fn probe_timeout(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .map(|remaining| remaining.min(PROBE_IO_LIMIT))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "shared probe deadline expired",
            )
        })
}

#[cfg(unix)]
fn probe_response(
    port: u16,
    mut request: &[u8],
    deadline: Instant,
) -> Result<String, Box<dyn std::error::Error>> {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, probe_timeout(deadline)?)?;
    while !request.is_empty() {
        stream.set_write_timeout(Some(probe_timeout(deadline)?))?;
        let written = match stream.write(request) {
            Ok(written) => written,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            },
            Err(error) => return Err(error.into()),
        };
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "incomplete probe request",
            )
            .into());
        }
        request = request.get(written..).ok_or("invalid probe write length")?;
    }
    let mut response = Vec::new();
    loop {
        stream.set_read_timeout(Some(probe_timeout(deadline)?))?;
        let mut buffer = [0; 4096];
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            },
            Err(error) => return Err(error.into()),
        };
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "shared probe deadline expired",
            )
            .into());
        }
        if read == 0 {
            break;
        }
        if response.len() + read > 64 * 1024 {
            return Err("probe response exceeded its 64 KiB bound".into());
        }
        response.extend_from_slice(buffer.get(..read).ok_or("invalid probe read length")?);
    }
    Ok(String::from_utf8(response)?)
}

#[cfg(unix)]
pub(crate) fn bounded_redacted_observation(observation: &str, authorization: &str) -> String {
    const MAX_STATUS_OBSERVATION_CHARS: usize = 512;

    let redacted = if authorization.is_empty() {
        observation.to_owned()
    } else {
        observation.replace(authorization, "<redacted>")
    };
    let redacted = match authorization
        .strip_prefix("Bearer ")
        .filter(|secret| !secret.is_empty())
    {
        Some(secret) => redacted.replace(secret, "<redacted>"),
        None => redacted,
    };
    let mut bounded = redacted
        .chars()
        .take(MAX_STATUS_OBSERVATION_CHARS)
        .collect::<String>();
    if redacted.chars().nth(MAX_STATUS_OBSERVATION_CHARS).is_some() {
        bounded.push_str("…<truncated>");
    }
    bounded
}

#[cfg(unix)]
pub(crate) fn wait_for_readiness(
    port: u16,
    expected_status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_readiness_until(port, expected_status, Instant::now() + STARTUP_PROBE_BUDGET)
}

#[cfg(unix)]
pub(crate) fn wait_for_readiness_until(
    port: u16,
    expected_status: &str,
    deadline: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_observation = None;
    while Instant::now() < deadline {
        if Instant::now() >= deadline {
            break;
        }
        match probe_response(
            port,
            b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            deadline,
        ) {
            Ok(response) if response.starts_with(expected_status) => return Ok(()),
            Ok(response) => last_observation = Some(bounded_redacted_observation(&response, "")),
            Err(error) => last_observation = Some(format!("request={error}")),
        }
        std::thread::sleep(PROBE_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    Err(format!(
        "readiness deadline expired before expected response: {}",
        last_observation.unwrap_or_else(|| "no request admitted within shared deadline".to_owned())
    )
    .into())
}
#[cfg(unix)]
pub(crate) fn wait_for_fenced_startup(
    operations_port: u16,
    control_path: &std::path::Path,
    deadline: Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_readiness_until(operations_port, "HTTP/1.1 503 ", deadline)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            loop {
                probe_timeout(deadline)?;
                let stream = match tokio::net::UnixStream::connect(control_path).await {
                    Ok(stream) => stream,
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {
                        tokio::time::sleep(PROBE_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))).await;
                        continue;
                    },
                    Err(error) => return Err(error.into()),
                };
                let mut request = b"GET /control/fenced/inspection HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice();
                while !request.is_empty() {
                    probe_timeout(deadline)?;
                    stream.writable().await?;
                    match stream.try_write(request) {
                        Ok(0) => return Err("Fenced probe request was not delivered".into()),
                        Ok(written) => request = request.get(written..).ok_or("invalid Fenced probe write")?,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut response = Vec::new();
                let mut buffer = [0; 1024];
                let fenced = loop {
                    probe_timeout(deadline)?;
                    stream.readable().await?;
                    let read = match stream.try_read(&mut buffer) {
                        Ok(0) => return Err("truncated Fenced probe response".into()),
                        Ok(read) => read,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Err(error.into()),
                    };
                    if read > 4096_usize.saturating_sub(response.len()) {
                        return Err("Fenced probe response exceeded its bound".into());
                    }
                    response.extend_from_slice(buffer.get(..read).ok_or("invalid Fenced probe read")?);
                    if let Some(fenced) = fenced_probe_response(&response)? {
                        break fenced;
                    }
                };
                probe_timeout(deadline)?;
                if fenced { return Ok(()); }
                tokio::time::sleep(PROBE_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))).await;
            }
        }).await.map_err(|_| "Fenced startup deadline expired")?
    })
}

// Missing authorization returns 401 only in Fenced; no inspection is executed.
// Recovering returns 404. A complete native frame is required before either
// status can be used, and protected response contents are never collected.
#[cfg(unix)]
fn fenced_probe_response(response: &[u8]) -> Result<Option<bool>, Box<dyn std::error::Error>> {
    let Some(offset) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(
        response
            .get(..offset)
            .ok_or("invalid Fenced probe headers")?,
    )?;
    let body = response
        .get(offset + 4..)
        .ok_or("invalid Fenced probe body")?;
    let mut lengths = headers
        .lines()
        .filter_map(|line| line.strip_prefix("Content-Length: "));
    let length = lengths
        .next()
        .ok_or("missing Fenced probe length")?
        .parse::<usize>()?;
    if lengths.next().is_some()
        || length > 4096
        || headers.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("Transfer-Encoding"))
        })
    {
        return Err("ambiguous Fenced probe framing".into());
    }
    if body.len() < length {
        return Ok(None);
    }
    if body.len() != length {
        return Err("invalid Fenced probe response length".into());
    }
    if headers.starts_with("HTTP/1.1 401 ") {
        Ok(Some(true))
    } else if headers.starts_with("HTTP/1.1 404 ") {
        Ok(Some(false))
    } else {
        Err("unexpected Fenced probe response status".into())
    }
}

#[cfg(unix)]
pub(crate) fn wait_for_file(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if path.is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("child process did not reach expected phase".into())
}

#[cfg(unix)]
pub(crate) fn wait_for_child(
    child: &mut std::process::Child,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    let _status = child.wait()?;
    Err("child process did not exit".into())
}

#[cfg(unix)]
pub(crate) fn available_ports() -> Result<[u16; 5], Box<dyn std::error::Error>> {
    let mut probes = Vec::with_capacity(5);
    for _ in 0..5 {
        probes.push(
            std::net::TcpListener::bind(("127.0.0.1", 0))
                .map_err(|error| format!("bind port probe: {error}"))?,
        );
    }
    let mut ports = [0; 5];
    for (port, probe) in ports.iter_mut().zip(&probes) {
        *port = probe
            .local_addr()
            .map_err(|error| format!("inspect port probe: {error}"))?
            .port();
    }
    Ok(ports)
}

#[cfg(unix)]
pub(crate) fn process_control_path(root: &std::path::Path) -> std::path::PathBuf {
    std::path::Path::new("/tmp")
        .join(root.file_name().unwrap_or_default())
        .with_extension("sock")
}

#[cfg(unix)]
pub(crate) fn process_configuration(
    root: &std::path::Path,
    data: &std::path::Path,
    secrets: &std::path::Path,
    ports: [u16; 5],
) -> String {
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = ports;
    let crate_directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let runtime_directory = crate_directory
        .parent()
        .unwrap_or(crate_directory)
        .join("positron-runtime/tests/native_transport/fixtures");
    let certificate = runtime_directory.join("api-test-cert.pem");
    let private_key = runtime_directory.join("api-test-key.pem");
    format!(
        "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 2\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:{operations_port}\"\noperations_transport = \"plaintext\"\napi_bind_address = \"127.0.0.1:{api_port}\"\napi_transport = \"tls\"\napi_tls_certificate_file = \"{}\"\napi_tls_private_key_file = \"{}\"\notlp_grpc_bind_address = \"127.0.0.1:{otlp_grpc_port}\"\notlp_grpc_tls_certificate_file = \"{}\"\notlp_grpc_tls_private_key_file = \"{}\"\notlp_http_bind_address = \"127.0.0.1:{otlp_http_port}\"\notlp_http_tls_certificate_file = \"{}\"\notlp_http_tls_private_key_file = \"{}\"\nloki_push_bind_address = \"127.0.0.1:{loki_push_port}\"\nloki_push_tls_certificate_file = \"{}\"\nloki_push_tls_private_key_file = \"{}\"\n[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n",
        process_control_path(root).display(),
        certificate.display(),
        private_key.display(),
        certificate.display(),
        private_key.display(),
        certificate.display(),
        private_key.display(),
        certificate.display(),
        private_key.display(),
        data.display(),
        secrets.display(),
        secrets.join("local-root-key.v1").display()
    )
}
