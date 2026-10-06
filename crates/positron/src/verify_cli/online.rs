use super::*;

pub(super) fn execute_online(options: &VerifyOptions) -> Result<(ExitCode, String), VerifyFailure> {
    let input = std::io::stdin();
    if input.is_terminal() {
        return Err(VerifyFailure::Usage);
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| VerifyFailure::Configuration)?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024
        || bearer.is_empty()
        || bearer.len() > 1024
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(VerifyFailure::Usage);
    }
    let request = OnlineVerificationRequest::new(
        options.tenant.clone().ok_or(VerifyFailure::Usage)?,
        options.signal.clone().ok_or(VerifyFailure::Usage)?,
        options.shard.ok_or(VerifyFailure::Usage)?,
        options.expected_catalog_generation,
        options.continuation.clone(),
    );
    online_request(options, bearer, &request)
}

pub(super) fn online_request(
    options: &VerifyOptions,
    bearer: &str,
    request: &OnlineVerificationRequest,
) -> Result<(ExitCode, String), VerifyFailure> {
    let transport = online_transport(options)?;
    let client =
        MaintenanceServiceClient::new(transport).map_err(|_| VerifyFailure::Configuration)?;
    let report = client.verify(bearer, request).map_err(online_failure)?;
    let exit = if report.verification_complete && report.outcome == "verified" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_INTEGRITY)
    };
    Ok((exit, super::render::render_online_report(&report)))
}

fn online_transport(options: &VerifyOptions) -> Result<MaintenanceTransport, VerifyFailure> {
    let endpoint = options.endpoint.ok_or(VerifyFailure::Usage)?;
    if endpoint.port() == 0 {
        return Err(VerifyFailure::Usage);
    }
    if options.allow_plaintext {
        if options.server_name.is_some() || options.trust_file.is_some() {
            return Err(VerifyFailure::Usage);
        }
        Ok(MaintenanceTransport::PlaintextOptOut { endpoint })
    } else {
        Ok(MaintenanceTransport::Tls {
            endpoint,
            server_name: options.server_name.clone().ok_or(VerifyFailure::Usage)?,
            trust_file: options.trust_file.clone().ok_or(VerifyFailure::Usage)?,
        })
    }
}

fn online_failure(failure: MaintenanceServiceClientFailure) -> VerifyFailure {
    match failure {
        MaintenanceServiceClientFailure::InvalidRequest
        | MaintenanceServiceClientFailure::AuthenticationRejected
        | MaintenanceServiceClientFailure::SourceUnavailable => VerifyFailure::Usage,
        MaintenanceServiceClientFailure::TaskUnavailable
        | MaintenanceServiceClientFailure::PreconditionFailed
        | MaintenanceServiceClientFailure::IdempotencyConflict
        | MaintenanceServiceClientFailure::AdministrationUnavailable
        | MaintenanceServiceClientFailure::Transport => VerifyFailure::Configuration,
    }
}
