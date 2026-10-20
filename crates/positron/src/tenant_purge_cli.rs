//! The running instance owns purge; this command is an authenticated client.
use positron_api::tenant_purge::{
    TenantPurgeRequest, TenantPurgeResponse, TenantPurgeServiceClient,
    TenantPurgeServiceClientFailure, TenantPurgeTransport,
};
use std::{
    collections::BTreeMap,
    io::Write,
    process::ExitCode,
    time::{Duration, Instant},
};
const USAGE: &str = "usage: positron tenant purge start|status|lookup|wait|cancel --endpoint ADDRESS --credential-stdin [--server-name NAME --trust-file PATH | --allow-plaintext] [--tenant-id UUID --confirmation-slug SLUG --expected-generation N --expected-lifecycle-generation N --idempotency-key UUID --operation-id ID]";

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    crate::administrative_cli::exit(execute(arguments, &mut std::io::stdout().lock()))
}
fn execute(
    arguments: impl Iterator<Item = String>,
    output: &mut impl Write,
) -> Result<(), &'static str> {
    let (transport, request, wait) = parse(arguments)?;
    let credential = crate::administrative_cli::credential()?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    let client = TenantPurgeServiceClient::new(transport).map_err(client_failure)?;
    let mut response = client.manage(bearer, &request).map_err(client_failure)?;
    if let Some(duration) = wait {
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or("invalid wait duration")?;
        while response
            .operation
            .as_ref()
            .is_some_and(|operation| matches!(operation.status.as_str(), "pending" | "running"))
        {
            if Instant::now() >= deadline {
                write_response(output, &response)?;
                return Err(
                    "operation outcome remains unknown; inspect the same operation ID before retrying",
                );
            }
            std::thread::sleep(Duration::from_millis(100));
            response = client.manage(bearer, &request).map_err(client_failure)?;
        }
    }
    write_response(output, &response)
}
fn write_response(
    output: &mut impl Write,
    response: &TenantPurgeResponse,
) -> Result<(), &'static str> {
    writeln!(
        output,
        "catalog_generation={} managed_scope={}",
        response.catalog_generation, response.managed_scope
    )
    .map_err(|_| "purge output unavailable")?;
    if let Some(operation) = &response.operation {
        writeln!(output, "operation_id={} status={} phase={} progress_percent={} cancellation={} irreversible_boundary={} retry={} lookup_expires_at_unix_seconds={:?}", operation.id, operation.status, operation.phase, operation.progress_percent, operation.cancellation, operation.irreversible_boundary, operation.retry, operation.lookup_expires_at_unix_seconds).map_err(|_| "purge output unavailable")?;
    }
    Ok(())
}
fn client_failure(failure: TenantPurgeServiceClientFailure) -> &'static str {
    use TenantPurgeServiceClientFailure as F;
    match failure {
        F::InvalidRequest => "invalid purge request",
        F::AuthenticationRejected => "system administration authentication rejected",
        F::SourceUnavailable | F::TaskUnavailable => "purge operation unavailable",
        F::StaleGeneration => "stale resource generation; inspect current state before retrying",
        F::PreconditionFailed => {
            "operation precondition failed; inspect current state before retrying"
        },
        F::IdempotencyConflict => "idempotency key conflicts with an accepted request",
        F::AdministrationUnavailable => {
            "administration unavailable; inspect or retry the same operation"
        },
        F::CapacityUnavailable => "capacity unavailable; retry the same idempotent request",
        F::Transport => {
            "transport outcome unknown; inspect the same operation or idempotency key before retrying"
        },
    }
}
fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(TenantPurgeTransport, TenantPurgeRequest, Option<Duration>), &'static str> {
    let action = arguments.next().ok_or(USAGE)?;
    if !matches!(
        action.as_str(),
        "start" | "status" | "lookup" | "wait" | "cancel"
    ) {
        return Err(USAGE);
    }
    let mut options = BTreeMap::new();
    let mut credential_stdin = false;
    let mut allow_plaintext = false;
    while let Some(option) = arguments.next() {
        match option.as_str() {
            "--credential-stdin" if !credential_stdin => credential_stdin = true,
            "--allow-plaintext" if !allow_plaintext => allow_plaintext = true,
            "--endpoint"
            | "--server-name"
            | "--trust-file"
            | "--tenant-id"
            | "--confirmation-slug"
            | "--expected-lifecycle-generation"
            | "--expected-generation"
            | "--idempotency-key"
            | "--operation-id"
            | "--wait-seconds" => {
                let value = arguments.next().ok_or("missing purge option value")?;
                if value.is_empty() || value.len() > 2048 {
                    return Err("purge option exceeds its supported bound");
                }
                if options.insert(option, value).is_some() {
                    return Err("duplicate purge option");
                }
            },
            _ => {
                return Err(
                    "unknown or duplicate purge option; credential values must use protected stdin",
                );
            },
        }
    }
    if !credential_stdin {
        return Err("--credential-stdin is required");
    }
    let transport = crate::administrative_cli::transport(
        &mut options,
        allow_plaintext,
        crate::administrative_cli::required_transport_option,
    )?;
    let wait = options
        .remove("--wait-seconds")
        .map(|value| value.parse::<u64>().map_err(|_| "invalid wait duration"))
        .transpose()?;
    let wait = if action == "wait" {
        let seconds = wait.unwrap_or(30);
        if !(1..=60).contains(&seconds) || !options.contains_key("--operation-id") {
            return Err("wait requires an operation ID and 1..60 seconds");
        }
        Some(Duration::from_secs(seconds))
    } else {
        if wait.is_some() {
            return Err("--wait-seconds applies only to wait");
        }
        None
    };
    let request = TenantPurgeRequest {
        action: match action.as_str() {
            "wait" => "status",
            _ => &action,
        }
        .into(),
        expected_catalog_generation: options
            .remove("--expected-generation")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "invalid Catalog generation")
            })
            .transpose()?,
        idempotency_key: options.remove("--idempotency-key"),
        tenant_id: options.remove("--tenant-id"),
        confirmation_slug: options.remove("--confirmation-slug"),
        expected_lifecycle_generation: options
            .remove("--expected-lifecycle-generation")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "invalid lifecycle generation")
            })
            .transpose()?,
        operation_id: options.remove("--operation-id"),
    };
    request
        .encode()
        .map_err(|_| "invalid purge request identity or tenant confirmation")?;
    if !options.is_empty() {
        return Err("unsupported purge options");
    }
    Ok((transport, request, wait))
}
