//! The running instance owns repository; this command is an authenticated client.
use positron_api::repository::{
    RepositoryAwsS3Target, RepositoryAzureBlobTarget, RepositoryGoogleCloudStorageTarget,
    RepositoryRequest, RepositoryResponse, RepositoryServiceClient, RepositoryServiceClientFailure,
    RepositoryTransport,
};
use std::{
    collections::BTreeMap,
    io::Write,
    process::ExitCode,
    time::{Duration, Instant},
};
const USAGE: &str = "usage: positron repository init|verify|doctor|status|lookup|wait|cancel --endpoint ADDRESS --credential-stdin [--server-name NAME --trust-file PATH | --allow-plaintext] [--locator SERVER_PATH | --aws-bucket BUCKET --aws-region REGION --aws-endpoint HTTPS_ENDPOINT --aws-expected-owner ACCOUNT --aws-prefix PREFIX | --gcs-bucket BUCKET --gcs-project-number PROJECT --gcs-location LOCATION --gcs-prefix PREFIX | --azure-account ACCOUNT --azure-container CONTAINER --azure-prefix PREFIX] [--repository-id UUID --expected-generation N --idempotency-key UUID --operation-id ID]";

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
    let client = RepositoryServiceClient::new(transport).map_err(client_failure)?;
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
    response: &RepositoryResponse,
) -> Result<(), &'static str> {
    writeln!(output, "catalog_generation={}", response.catalog_generation)
        .map_err(|_| "repository output unavailable")?;
    if let Some(identity) = &response.identity {
        writeln!(output, "repository_id={} instance_id={} provider_kind={} format_epoch={} integrity_fingerprint={} prefix_commitment={}", identity.repository_id, identity.instance_id, identity.provider_kind, identity.format_epoch, identity.integrity_fingerprint, identity.prefix_commitment).map_err(|_| "repository output unavailable")?;
    }
    if let Some(doctor) = &response.doctor {
        writeln!(
            output,
            "provider_behavior_verified={} owned_probes_deleted={} external_retention={}",
            doctor.verified, doctor.probes_deleted, doctor.external_retention
        )
        .map_err(|_| "repository output unavailable")?;
    }
    if let Some(policy) = &response.policy {
        writeln!(
            output,
            "policy_observed_at_unix_seconds={}",
            policy.observed_at_unix_seconds
        )
        .map_err(|_| "repository output unavailable")?;
        let mut observations = vec![
            ("versioning", &policy.versioning),
            ("object_lock", &policy.object_lock),
            ("lifecycle", &policy.lifecycle),
        ];
        if let Some(value) = &policy.soft_delete {
            observations.push(("soft_delete_retention_seconds", value));
        }
        if let Some(probe) = &policy.doctor_probe {
            observations.extend([
                ("doctor_probe_retention", &probe.retention),
                ("doctor_probe_legal_hold", &probe.legal_hold),
                ("doctor_probe_event_hold", &probe.event_hold),
            ]);
        }
        for (name, observation) in observations {
            writeln!(output, "{name}_state={} {name}_value={:?} {name}_failure={:?} {name}_retry_after_millis={:?}",
                observation.state, observation.value, observation.failure, observation.retry_after_millis)
                .map_err(|_| "repository output unavailable")?;
            if let Some(retention) = &observation.object_retention {
                writeln!(
                    output,
                    "object_retention_mode={} retain_until_unix_seconds={}",
                    retention.mode, retention.retain_until_unix_seconds
                )
                .map_err(|_| "repository output unavailable")?;
            }
            if let Some(hold) = &observation.event_hold {
                writeln!(
                    output,
                    "event_hold_enabled={} event_hold_period_unit={:?} event_hold_period={:?}",
                    hold.enabled, hold.period_unit, hold.period
                )
                .map_err(|_| "repository output unavailable")?;
            }
            if let Some(retention) = &observation.default_retention {
                writeln!(output, "default_retention_mode={} default_retention_period_unit={} default_retention_period={}",
                    retention.mode, retention.period_unit, retention.period)
                    .map_err(|_| "repository output unavailable")?;
            }
            if let Some(lifecycle) = &observation.lifecycle {
                writeln!(output, "current_expiration={} noncurrent_expiration={} transition={} abandoned_upload_expiration={}",
                    lifecycle.current_expiration, lifecycle.noncurrent_expiration, lifecycle.transition, lifecycle.abandoned_upload_expiration)
                    .map_err(|_| "repository output unavailable")?;
            }
        }
    }
    if let Some(operation) = &response.operation {
        writeln!(output, "operation_id={} status={} phase={} progress_percent={} cancellation={} irreversible_boundary={} retry={} lookup_expires_at_unix_seconds={:?}", operation.id, operation.status, operation.phase, operation.progress_percent, operation.cancellation, operation.irreversible_boundary, operation.retry, operation.lookup_expires_at_unix_seconds).map_err(|_| "repository output unavailable")?;
    }
    Ok(())
}
fn client_failure(failure: RepositoryServiceClientFailure) -> &'static str {
    use RepositoryServiceClientFailure as F;
    match failure {
        F::InvalidRequest => "invalid repository request",
        F::AuthenticationRejected => "system administration authentication rejected",
        F::SourceUnavailable | F::TaskUnavailable => "repository operation unavailable",
        F::PreconditionFailed => "stale Catalog generation; inspect current state before retrying",
        F::IdempotencyConflict => "idempotency key conflicts with an accepted request",
        F::AdministrationUnavailable => {
            "administration unavailable; inspect or retry the same operation"
        },
        F::Transport => {
            "transport outcome unknown; inspect the same operation or idempotency key before retrying"
        },
    }
}
fn parse(
    mut arguments: impl Iterator<Item = String>,
) -> Result<(RepositoryTransport, RepositoryRequest, Option<Duration>), &'static str> {
    let action = arguments.next().ok_or(USAGE)?;
    if !matches!(
        action.as_str(),
        "init" | "verify" | "doctor" | "status" | "lookup" | "wait" | "cancel"
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
            | "--locator"
            | "--aws-bucket"
            | "--aws-region"
            | "--aws-endpoint"
            | "--aws-expected-owner"
            | "--aws-prefix"
            | "--gcs-bucket"
            | "--gcs-project-number"
            | "--gcs-location"
            | "--gcs-prefix"
            | "--azure-account"
            | "--azure-container"
            | "--azure-prefix"
            | "--repository-id"
            | "--expected-generation"
            | "--idempotency-key"
            | "--operation-id"
            | "--wait-seconds" => {
                let value = arguments.next().ok_or("missing repository option value")?;
                if value.is_empty() || value.len() > 2048 {
                    return Err("repository option exceeds its supported bound");
                }
                if options.insert(option, value).is_some() {
                    return Err("duplicate repository option");
                }
            },
            _ => {
                return Err(
                    "unknown or duplicate repository option; credential values must use protected stdin",
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
    let native = [
        "--aws-bucket",
        "--aws-region",
        "--aws-endpoint",
        "--aws-expected-owner",
        "--aws-prefix",
    ];
    let aws_s3 = if native.iter().any(|option| options.contains_key(*option)) {
        let mut required = |option| {
            options
                .remove(option)
                .ok_or("AWS target requires bucket, region, endpoint, expected owner and prefix")
        };
        Some(RepositoryAwsS3Target {
            bucket: required("--aws-bucket")?,
            region: required("--aws-region")?,
            endpoint: required("--aws-endpoint")?,
            expected_owner: required("--aws-expected-owner")?,
            prefix: required("--aws-prefix")?,
        })
    } else {
        None
    };
    let native_google = [
        "--gcs-bucket",
        "--gcs-project-number",
        "--gcs-location",
        "--gcs-prefix",
    ];
    let google_cloud_storage = if native_google
        .iter()
        .any(|option| options.contains_key(*option))
    {
        let mut required = |option| {
            options
                .remove(option)
                .ok_or("Google target requires bucket, project number, location and prefix")
        };
        Some(RepositoryGoogleCloudStorageTarget {
            bucket: required("--gcs-bucket")?,
            project_number: required("--gcs-project-number")?,
            location: required("--gcs-location")?,
            prefix: required("--gcs-prefix")?,
        })
    } else {
        None
    };
    let azure_blob = if ["--azure-account", "--azure-container", "--azure-prefix"]
        .iter()
        .any(|option| options.contains_key(*option))
    {
        let mut required = |option| {
            options
                .remove(option)
                .ok_or("Azure target requires account, container and prefix")
        };
        Some(RepositoryAzureBlobTarget {
            account: required("--azure-account")?,
            container: required("--azure-container")?,
            prefix: required("--azure-prefix")?,
        })
    } else {
        None
    };
    let request = RepositoryRequest {
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
        aws_s3,
        google_cloud_storage,
        azure_blob,
        locator: options.remove("--locator"),
        repository_id: options.remove("--repository-id"),
        operation_id: options.remove("--operation-id"),
    };
    request
        .encode()
        .map_err(|_| "invalid repository request identity or server configuration reference")?;
    if !options.is_empty() {
        return Err("unsupported repository options");
    }
    Ok((transport, request, wait))
}

#[cfg(test)]
#[test]
fn azure_cli_requires_one_complete_native_target() {
    let arguments = |extra: &[&str]| {
        [
            "doctor",
            "--endpoint",
            "127.0.0.1:4318",
            "--allow-plaintext",
            "--credential-stdin",
            "--repository-id",
            "11111111-1111-4111-8111-111111111111",
            "--expected-generation",
            "1",
            "--idempotency-key",
            "22222222-2222-4222-8222-222222222222",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .into_iter()
    };
    let complete = [
        "--azure-account",
        "positronbackup",
        "--azure-container",
        "backups",
        "--azure-prefix",
        "owned/",
    ];
    let (_, request, _) = parse(arguments(&complete)).expect("azure request");
    assert_eq!(request.azure_blob.expect("target").container, "backups");
    assert!(parse(arguments(&complete[..4])).is_err());
    let mut mixed = complete.to_vec();
    mixed.extend(["--locator", "/local"]);
    assert!(parse(arguments(&mixed)).is_err());
}
