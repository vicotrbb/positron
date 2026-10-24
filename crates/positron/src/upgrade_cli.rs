//! The running instance owns upgrade; this command is an authenticated client.
use positron_api::upgrade::{
    UpgradeRequest, UpgradeResponse, UpgradeServiceClient, UpgradeServiceClientFailure,
    UpgradeTransport,
};
use std::{
    collections::BTreeMap,
    io::Write,
    process::ExitCode,
    time::{Duration, Instant},
};
const USAGE: &str = "usage: positron upgrade start|status|lookup|wait|cancel --endpoint ADDRESS --credential-stdin [--server-name NAME --trust-file PATH | --allow-plaintext] [--candidate-manifest DIGEST --repository-id UUID --retention-seconds N --expected-generation N --idempotency-key UUID --operation-id ID]";

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    let mut arguments = arguments.peekable();
    if arguments
        .peek()
        .is_some_and(|argument| argument == "offline")
    {
        arguments.next();
        return crate::upgrade_offline_cli::run(arguments);
    }
    crate::administrative_cli::exit(execute(arguments, &mut std::io::stdout().lock()))
}
fn execute(
    arguments: impl Iterator<Item = String>,
    output: &mut impl Write,
) -> Result<(), &'static str> {
    let (transport, request, wait) = parse(arguments)?;
    let credential = crate::administrative_cli::credential()?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    let deadline = wait
        .map(|duration| {
            Instant::now()
                .checked_add(duration)
                .ok_or("invalid wait duration")
        })
        .transpose()?;
    let remaining = || {
        deadline.map_or(Duration::from_secs(30), |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(30))
        })
    };
    let client = UpgradeServiceClient::new(transport).map_err(client_failure)?;
    let mut response = client
        .manage_with_default_listener_timeout(bearer, &request, remaining())
        .map_err(client_failure)?;
    if let Some(deadline) = deadline {
        loop {
            if Instant::now() >= deadline {
                write_response(output, &response)?;
                return Err(
                    "operation outcome remains unknown; inspect the same operation ID before retrying",
                );
            }
            if !response
                .operation
                .as_ref()
                .is_some_and(|operation| matches!(operation.status.as_str(), "pending" | "running"))
            {
                break;
            }
            std::thread::sleep(
                Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
            );
            response = client
                .manage_with_default_listener_timeout(bearer, &request, remaining())
                .map_err(client_failure)?;
        }
    }
    write_response(output, &response)
}
fn write_response(output: &mut impl Write, response: &UpgradeResponse) -> Result<(), &'static str> {
    writeln!(output, "catalog_generation={}", response.catalog_generation)
        .map_err(|_| "upgrade output unavailable")?;
    if let Some(operation) = &response.operation {
        writeln!(output, "operation_id={} status={} phase={} progress_percent={} cancellation={} irreversible_boundary={} retry={} lookup_expires_at_unix_seconds={:?}", operation.id, operation.status, operation.phase, operation.progress_percent, operation.cancellation, operation.irreversible_boundary, operation.retry, operation.lookup_expires_at_unix_seconds).map_err(|_| "upgrade output unavailable")?;
    }
    if let Some(details) = &response.details {
        writeln!(output,"source_version={} target_version={} source_manifest={} target_manifest={} source_artifact={} target_artifact={} format_epoch={} configuration={} repository_id={} snapshot_manifest={:?} rollback_available={}",details.source_version,details.target_version,details.source_manifest,details.target_manifest,details.source_artifact,details.target_artifact,details.format_epoch,details.configuration,details.repository_id,details.snapshot_manifest,details.rollback_available).map_err(|_|"upgrade output unavailable")?;
    }
    Ok(())
}
fn client_failure(failure: UpgradeServiceClientFailure) -> &'static str {
    use UpgradeServiceClientFailure as F;
    match failure {
        F::InvalidRequest => "invalid upgrade request",
        F::AuthenticationRejected => "system administration authentication rejected",
        F::SourceUnavailable | F::TaskUnavailable => "upgrade operation unavailable",
        F::StaleGeneration => "stale resource generation; inspect current state before retrying",
        F::PreconditionFailed => {
            "upgrade precondition failed; inspect current state before retrying"
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
) -> Result<(UpgradeTransport, UpgradeRequest, Option<Duration>), &'static str> {
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
            | "--candidate-manifest"
            | "--repository-id"
            | "--retention-seconds"
            | "--expected-generation"
            | "--idempotency-key"
            | "--operation-id"
            | "--wait-seconds" => {
                let value = arguments.next().ok_or("missing upgrade option value")?;
                if value.is_empty() || value.len() > 2048 {
                    return Err("upgrade option exceeds its supported bound");
                }
                if options.insert(option, value).is_some() {
                    return Err("duplicate upgrade option");
                }
            },
            _ => {
                return Err(
                    "unknown or duplicate upgrade option; credential values must use protected stdin",
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
    let request = UpgradeRequest {
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
        candidate_manifest: options.remove("--candidate-manifest"),
        repository_id: options.remove("--repository-id"),
        retention_seconds: options
            .remove("--retention-seconds")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "invalid retention seconds")
            })
            .transpose()?,
        operation_id: options.remove("--operation-id"),
    };
    request
        .encode()
        .map_err(|_| "invalid upgrade request identity or configured candidate")?;
    if !options.is_empty() {
        return Err("unsupported upgrade options");
    }
    Ok((transport, request, wait))
}

#[cfg(test)]
mod tests {
    #[test]
    fn precondition_failure_does_not_claim_a_generation_race() {
        assert_eq!(
            super::client_failure(super::UpgradeServiceClientFailure::PreconditionFailed),
            "upgrade precondition failed; inspect current state before retrying"
        );
    }

    #[test]
    fn online_upgrade_requires_candidate_identity_and_protected_credential_transport() {
        let base = [
            "start",
            "--endpoint",
            "127.0.0.1:1234",
            "--allow-plaintext",
            "--credential-stdin",
            "--candidate-manifest",
            &"ab".repeat(32),
            "--repository-id",
            "11111111-1111-1111-1111-111111111111",
            "--retention-seconds",
            "3600",
            "--expected-generation",
            "4",
            "--idempotency-key",
            "22222222-2222-2222-2222-222222222222",
        ];
        assert!(super::parse(base.iter().map(|s| (*s).to_owned())).is_ok());
        assert!(
            super::parse(
                base.iter()
                    .filter(|s| **s != "--credential-stdin")
                    .map(|s| (*s).to_owned())
            )
            .is_err()
        );
    }
}
