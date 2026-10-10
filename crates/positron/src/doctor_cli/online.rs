use super::report::render_status;
use super::*;

const MAX_TRUST_FILE_BYTES: u64 = 65_536;

pub(super) fn execute(options: &Options) -> Result<(ExitCode, String), DoctorFailure> {
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err(DoctorFailure::Arguments);
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(DoctorFailure::Arguments);
    }
    online_status_request(options, bearer)
}

pub(super) fn online_status_request(
    options: &Options,
    bearer: &str,
) -> Result<(ExitCode, String), DoctorFailure> {
    let report = operations_status(options, bearer)?;
    render_status(&report)
}

fn operations_status(options: &Options, bearer: &str) -> Result<serde_json::Value, DoctorFailure> {
    if let Some(path) = options.control_path.as_deref() {
        return control_status(path, bearer);
    }
    let endpoint = options.endpoint.ok_or(DoctorFailure::Arguments)?;
    if endpoint.port() == 0 {
        return Err(DoctorFailure::Arguments);
    }
    let mut builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5));
    let target = if options.allow_plaintext {
        if options.server_name.is_some() || options.trust_file.is_some() {
            return Err(DoctorFailure::Arguments);
        }
        format!("http://{endpoint}")
    } else {
        let name = options
            .server_name
            .as_deref()
            .ok_or(DoctorFailure::Arguments)?;
        let pem = read_trust_file(
            options
                .trust_file
                .as_deref()
                .ok_or(DoctorFailure::Arguments)?,
        )?;
        builder = builder
            .add_root_certificate(
                reqwest::Certificate::from_pem(&pem).map_err(|_| DoctorFailure::Arguments)?,
            )
            .resolve(name, endpoint);
        format!("https://{name}:{}", endpoint.port())
    };
    let response = builder
        .build()
        .map_err(|_| DoctorFailure::EndpointUnavailable)?
        .get(format!("{target}/status"))
        .bearer_auth(bearer)
        .send()
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    if response.status().as_u16() == 401 {
        return Err(DoctorFailure::AuthenticationRejected);
    }
    if !response.status().is_success() {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    let mut bytes = Vec::with_capacity(8_192);
    response
        .take(8_193)
        .read_to_end(&mut bytes)
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    if bytes.len() > 8_192 {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    serde_json::from_slice(&bytes).map_err(|_| DoctorFailure::EndpointUnavailable)
}

fn read_trust_file(path: &std::path::Path) -> Result<Vec<u8>, DoctorFailure> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| DoctorFailure::TrustFileRejected)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TRUST_FILE_BYTES {
        return Err(DoctorFailure::TrustFileRejected);
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| DoctorFailure::TrustFileRejected)?;
    let file = std::fs::File::from(descriptor);
    let opened = file
        .metadata()
        .map_err(|_| DoctorFailure::TrustFileRejected)?;
    if !opened.file_type().is_file() || opened.len() > MAX_TRUST_FILE_BYTES {
        return Err(DoctorFailure::TrustFileRejected);
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| DoctorFailure::TrustFileRejected)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_TRUST_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DoctorFailure::TrustFileRejected)?;
    if bytes.len() > MAX_TRUST_FILE_BYTES as usize {
        return Err(DoctorFailure::TrustFileRejected);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn control_status(path: &Path, bearer: &str) -> Result<serde_json::Value, DoctorFailure> {
    let deadline = std::time::Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or(DoctorFailure::EndpointUnavailable)?;
    let stream = crate::control_socket::connect_owner_control(path, Duration::from_secs(5))
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    stream
        .set_nonblocking(true)
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    let request = format!(
        "GET /control/doctor HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let response = runtime
        .block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                let stream = tokio::net::UnixStream::from_std(stream)?;
                let mut pending = request.as_bytes();
                while !pending.is_empty() {
                    stream.writable().await?;
                    match stream.try_write(pending) {
                        Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
                        Ok(written) => {
                            pending = pending.get(written..).ok_or_else(|| {
                                std::io::Error::from(std::io::ErrorKind::InvalidData)
                            })?;
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(error) => return Err(error),
                    }
                }
                let mut response = Vec::with_capacity(8_192);
                let mut buffer = [0_u8; 1024];
                loop {
                    stream.readable().await?;
                    match stream.try_read(&mut buffer) {
                        Ok(0) => return Ok(response),
                        Ok(read) => {
                            response.extend_from_slice(buffer.get(..read).ok_or_else(|| {
                                std::io::Error::from(std::io::ErrorKind::InvalidData)
                            })?);
                            if response.len() > 8_192 {
                                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                            }
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(error) => return Err(error),
                    }
                }
            })
            .await
        })
        .map_err(|_| DoctorFailure::EndpointUnavailable)?
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(DoctorFailure::EndpointUnavailable)?;
    let (head, body) = response.split_at(separator + 4);
    if head.starts_with(b"HTTP/1.1 401 ") {
        return Err(DoctorFailure::AuthenticationRejected);
    }
    if !head.starts_with(b"HTTP/1.1 200 ") {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    serde_json::from_slice(body).map_err(|_| DoctorFailure::EndpointUnavailable)
}

#[cfg(not(unix))]
fn control_status(_path: &Path, _bearer: &str) -> Result<serde_json::Value, DoctorFailure> {
    Err(DoctorFailure::EndpointUnavailable)
}
