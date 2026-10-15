//! The running instance owns migration; this command is an authenticated client.
use positron_api::provider_migration::{
    ProviderMigrationRequest, ProviderMigrationResponse, ProviderMigrationServiceClient,
    ProviderMigrationServiceClientFailure, ProviderMigrationTransport,
};
use std::{
    collections::BTreeMap,
    io::Write,
    process::ExitCode,
    time::{Duration, Instant},
};
const USAGE: &str = "usage: positron keys migrate status|prepare|activate|cancel|resume|verify|retire|lookup|wait|cancel-operation --endpoint ADDRESS --credential-stdin [--server-name NAME --trust-file PATH | --allow-plaintext] [--target-config SERVER_PATH --expected-generation N --idempotency-key UUID --operation-id ID]";

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
    let client = ProviderMigrationServiceClient::new(transport).map_err(client_failure)?;
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
    response: &ProviderMigrationResponse,
) -> Result<(), &'static str> {
    writeln!(output, "catalog_generation={} phase={} active_epoch={} successor_epoch={:?} predecessor_epoch={:?}", response.catalog_generation, response.root_phase, response.active_epoch, response.successor_epoch, response.predecessor_epoch).map_err(|_| "migration output unavailable")?;
    for (route, identity) in [
        ("source", Some(&response.source_provider)),
        ("active", Some(&response.active_provider)),
        ("target", response.target_provider.as_ref()),
    ] {
        if let Some(identity) = identity {
            writeln!(output, "{route}_provider_family={} {route}_provider_locator={} {route}_provider_version={}", identity.family, identity.locator, identity.version).map_err(|_| "migration output unavailable")?;
        }
    }
    if let Some(operation) = &response.operation {
        writeln!(output, "operation_id={} status={} phase={} progress_percent={} cancellation={} irreversible_boundary={} retry={} lookup_expires_at_unix_seconds={:?}", operation.id, operation.status, operation.phase, operation.progress_percent, operation.cancellation, operation.irreversible_boundary, operation.retry, operation.lookup_expires_at_unix_seconds).map_err(|_| "migration output unavailable")?;
    }
    Ok(())
}
fn client_failure(failure: ProviderMigrationServiceClientFailure) -> &'static str {
    use ProviderMigrationServiceClientFailure as F;
    match failure {
        F::InvalidRequest => "invalid migration request",
        F::AuthenticationRejected => "system administration authentication rejected",
        F::SourceUnavailable | F::TaskUnavailable => "migration operation unavailable",
        F::PreconditionFailed => "stale Catalog generation; inspect current state before retrying",
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
) -> Result<
    (
        ProviderMigrationTransport,
        ProviderMigrationRequest,
        Option<Duration>,
    ),
    &'static str,
> {
    let action = arguments.next().ok_or(USAGE)?;
    if !matches!(
        action.as_str(),
        "status"
            | "prepare"
            | "activate"
            | "cancel"
            | "resume"
            | "verify"
            | "retire"
            | "lookup"
            | "wait"
            | "cancel-operation"
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
            | "--target-config"
            | "--expected-generation"
            | "--idempotency-key"
            | "--operation-id"
            | "--wait-seconds" => {
                let value = arguments.next().ok_or("missing migration option value")?;
                if value.is_empty() || value.len() > 2048 {
                    return Err("migration option exceeds its supported bound");
                }
                if options.insert(option, value).is_some() {
                    return Err("duplicate migration option");
                }
            },
            _ => {
                return Err(
                    "unknown or duplicate migration option; credential values must use protected stdin",
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
    let request = ProviderMigrationRequest {
        action: match action.as_str() {
            "wait" => "status",
            "cancel-operation" => "cancel_operation",
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
        configuration_reference: options.remove("--target-config"),
        operation_id: options.remove("--operation-id"),
    };
    request
        .encode()
        .map_err(|_| "invalid migration request identity or server configuration reference")?;
    if !options.is_empty() {
        return Err("unsupported migration options");
    }
    Ok((transport, request, wait))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn online_preparation_keeps_the_server_reference_and_stable_mutation_identity() {
        let arguments = [
            "prepare",
            "--endpoint",
            "127.0.0.1:8765",
            "--allow-plaintext",
            "--credential-stdin",
            "--target-config",
            "/protected/target.toml",
            "--expected-generation",
            "7",
            "--idempotency-key",
            "11111111-1111-4111-8111-111111111111",
        ];
        let (_, request, wait) =
            parse(arguments.into_iter().map(str::to_owned)).expect("online preparation");
        assert_eq!(
            request.configuration_reference.as_deref(),
            Some("/protected/target.toml")
        );
        assert_eq!(request.expected_catalog_generation, Some(7));
        assert_eq!(wait, None);
    }
    #[test]
    fn unsupported_missing_duplicate_or_secret_options_refuse_before_storage() {
        for arguments in [
            vec!["unknown".to_owned()],
            vec!["status".to_owned()],
            vec![
                "status".to_owned(),
                "--token".to_owned(),
                "private".to_owned(),
            ],
            vec!["status".to_owned(), "--config".to_owned(), "x".repeat(4097)],
            vec![
                "status".to_owned(),
                "--config".to_owned(),
                "a".to_owned(),
                "--config".to_owned(),
                "b".to_owned(),
            ],
        ] {
            assert!(execute(arguments.into_iter(), &mut Vec::new()).is_err());
        }
    }
}
