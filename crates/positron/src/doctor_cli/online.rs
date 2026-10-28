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
    let (builder, target) = operations_client(options)?;
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

// Both public consumers use one TLS/trust policy; readiness requires no bearer.
fn operations_client(
    options: &Options,
) -> Result<(reqwest::blocking::ClientBuilder, String), DoctorFailure> {
    let endpoint = options.endpoint.ok_or(DoctorFailure::Arguments)?;
    if endpoint.port() == 0 {
        return Err(DoctorFailure::Arguments);
    }
    let mut builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
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
        for certificate in trust_certificates(&pem)? {
            builder = builder.add_root_certificate(certificate);
        }
        builder = builder.resolve(name, endpoint);
        format!("https://{name}:{}", endpoint.port())
    };
    Ok((builder, target))
}

pub(super) fn health(options: &Options) -> Result<(ExitCode, String), DoctorFailure> {
    let state = if matches!(options.mode, Mode::Live) {
        "live"
    } else {
        "ready"
    };
    let (builder, target) = operations_client(options)?;
    let response = builder
        .build()
        .map_err(|_| DoctorFailure::EndpointUnavailable)?
        .get(format!("{target}/health/{state}"))
        .send()
        .map_err(|_| DoctorFailure::EndpointUnavailable)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(DoctorFailure::EndpointUnavailable);
    }
    Ok((ExitCode::SUCCESS, format!("status={state}\n")))
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
    let request = format!(
        "GET /control/doctor HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let response =
        crate::control_socket::owner_control_request(path, request.as_bytes(), 8192, |_| false)
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

fn trust_certificates(pem: &[u8]) -> Result<Vec<reqwest::Certificate>, DoctorFailure> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if pem.len() > MAX_TRUST_FILE_BYTES as usize {
        return Err(DoctorFailure::Arguments);
    }
    let mut remaining = std::str::from_utf8(pem)
        .map_err(|_| DoctorFailure::Arguments)?
        .trim();
    let mut certificates = Vec::new();
    while !remaining.is_empty() {
        if certificates.len() >= 64 || !remaining.starts_with(BEGIN) {
            return Err(DoctorFailure::Arguments);
        }
        let end = remaining
            .find(END)
            .and_then(|offset| offset.checked_add(END.len()))
            .ok_or(DoctorFailure::Arguments)?;
        let certificate = remaining.get(..end).ok_or(DoctorFailure::Arguments)?;
        let parsed = reqwest::Certificate::from_pem_bundle(certificate.as_bytes())
            .map_err(|_| DoctorFailure::Arguments)?;
        if parsed.len() != 1 {
            return Err(DoctorFailure::Arguments);
        }
        certificates.extend(parsed);
        remaining = remaining.get(end..).ok_or(DoctorFailure::Arguments)?.trim();
    }
    if certificates.is_empty() {
        return Err(DoctorFailure::Arguments);
    }
    Ok(certificates)
}

#[cfg(fuzzing)]
pub(super) fn fuzz_trust_certificates(bytes: &[u8]) {
    let _parsed = trust_certificates(bytes);
}

#[cfg(test)]
mod trust_bundle_tests {
    use super::trust_certificates;
    const CERT: &[u8] = include_bytes!(
        "../../../positron-runtime/tests/native_transport/fixtures/api-test-cert.pem"
    );
    #[test]
    fn trust_bundle_preserves_every_overlap_authority_and_rejects_partial_invalid_material() {
        let overlap = [CERT, b"\n", CERT].concat();
        assert_eq!(trust_certificates(&overlap).unwrap().len(), 2);
        for invalid in [
            Vec::new(),
            [CERT, b"garbage"].concat(),
            [
                CERT,
                b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
            ]
            .concat(),
            CERT.repeat(65),
        ] {
            let accepted = trust_certificates(&invalid).is_ok_and(|certificates| {
                let mut builder = reqwest::blocking::Client::builder();
                for certificate in certificates {
                    builder = builder.add_root_certificate(certificate);
                }
                builder.build().is_ok()
            });
            assert!(!accepted);
        }
    }
}
