//! The running instance owns backup; this command is an authenticated client.
use positron_api::backup::{
    BackupRequest, BackupResponse, BackupServiceClient, BackupServiceClientFailure,
    BackupTransport, RepositoryAwsS3Target, RepositoryAzureBlobTarget,
    RepositoryGoogleCloudStorageTarget,
};
use std::{
    collections::BTreeMap,
    io::Write,
    process::ExitCode,
    time::{Duration, Instant},
};
mod list;
const USAGE: &str = "usage: positron backup create|expire|status|lookup|wait|cancel|list --endpoint ADDRESS --credential-stdin [--server-name NAME --trust-file PATH | --allow-plaintext] [--locator SERVER_PATH | --aws-bucket BUCKET --aws-region REGION --aws-endpoint HTTPS_ENDPOINT --aws-expected-owner ACCOUNT --aws-prefix PREFIX | --gcs-bucket BUCKET --gcs-project-number PROJECT --gcs-location LOCATION --gcs-prefix PREFIX | --azure-account ACCOUNT --azure-container CONTAINER --azure-prefix PREFIX] [--snapshot-id HEX --expected-manifest-checksum HEX --retention-seconds N --repository-id UUID --expected-generation N --expected-operation-revision N --idempotency-key UUID --operation-id ID]";

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    let mut arguments = arguments.peekable();
    if arguments.peek().is_some_and(|action| action == "list") {
        arguments.next();
        return crate::administrative_cli::exit(list::execute(
            arguments,
            &mut std::io::stdout().lock(),
        ));
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
    let client = BackupServiceClient::new(transport).map_err(client_failure)?;
    let mut response = client.manage(bearer, &request).map_err(client_failure)?;
    if let Some(duration) = wait {
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or("invalid wait duration")?;
        while matches!(response.operation.status.as_str(), "pending" | "running") {
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
fn write_response(output: &mut impl Write, response: &BackupResponse) -> Result<(), &'static str> {
    writeln!(
        output,
        "kind={} cleanup_pending={} operation_revision={}",
        response.kind, response.cleanup_pending, response.operation_revision
    )
    .map_err(|_| "backup output unavailable")?;
    if let Some(code) = &response.terminal_error_code {
        writeln!(output, "terminal_error_code={code}").map_err(|_| "backup output unavailable")?;
    }
    let operation = &response.operation;
    writeln!(output, "operation_id={} status={} phase={} progress_percent={} cancellation={} irreversible_boundary={} retry={} lookup_expires_at_unix_seconds={:?}", operation.id, operation.status, operation.phase, operation.progress_percent, operation.cancellation, operation.irreversible_boundary, operation.retry, operation.lookup_expires_at_unix_seconds).map_err(|_| "backup output unavailable")?;
    if let Some(identity) = &response.repository {
        writeln!(output,"repository_id={} instance_id={} provider_kind={} format_epoch={} integrity_fingerprint={} prefix_commitment={}",identity.repository_id,identity.instance_id,identity.provider_kind,identity.format_epoch,identity.integrity_fingerprint,identity.prefix_commitment).map_err(|_| "backup output unavailable")?;
    }
    if let Some(receipt) = &response.retention_receipt {
        writeln!(output,"snapshot_id={} manifest_checksum={} registry_generation_checksum={} deleted_objects={} already_absent_objects={} retained_shared_objects={}",receipt.snapshot_id,receipt.manifest_checksum,receipt.registry_generation_checksum,receipt.deleted_objects,receipt.already_absent_objects,receipt.retained_shared_objects).map_err(|_|"backup output unavailable")?;
    }
    if let Some(receipt) = &response.receipt {
        writeln!(output,"manifest_checksum={} catalog_generation={} catalog_identity={} uploaded_bytes={} reused_bytes={} retain_until_unix_seconds={} registry_generation_checksum={}",receipt.manifest_checksum,receipt.catalog_generation,receipt.catalog_identity,receipt.uploaded_bytes,receipt.reused_bytes,receipt.retain_until_unix_seconds,receipt.registry_generation_checksum).map_err(|_| "backup output unavailable")?;
    }
    Ok(())
}
fn client_failure(failure: BackupServiceClientFailure) -> &'static str {
    use BackupServiceClientFailure as F;
    match failure {
        F::InvalidRequest => "invalid backup request",
        F::AuthenticationRejected => "system administration authentication rejected",
        F::SourceUnavailable | F::TaskUnavailable => "backup operation unavailable",
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
) -> Result<(BackupTransport, BackupRequest, Option<Duration>), &'static str> {
    let action = arguments.next().ok_or(USAGE)?;
    if !matches!(
        action.as_str(),
        "create" | "expire" | "status" | "lookup" | "wait" | "cancel"
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
            | "--expected-operation-revision"
            | "--expected-generation"
            | "--idempotency-key"
            | "--snapshot-id"
            | "--expected-manifest-checksum"
            | "--operation-id"
            | "--retention-seconds"
            | "--wait-seconds" => {
                let value = arguments.next().ok_or("missing backup option value")?;
                if value.is_empty() || value.len() > 2048 {
                    return Err("backup option exceeds its supported bound");
                }
                if options.insert(option, value).is_some() {
                    return Err("duplicate backup option");
                }
            },
            _ => {
                return Err(
                    "unknown or duplicate backup option; credential values must use protected stdin",
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
    let request = BackupRequest {
        expected_operation_revision: options
            .remove("--expected-operation-revision")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "invalid operation revision")
            })
            .transpose()?,
        snapshot_id: options.remove("--snapshot-id"),
        expected_manifest_checksum: options.remove("--expected-manifest-checksum"),
        action: match action.as_str() {
            "wait" => "status",
            _ => &action,
        }
        .into(),
        retention_seconds: options
            .remove("--retention-seconds")
            .map(|value| value.parse::<u64>().map_err(|_| "invalid backup retention"))
            .transpose()?,
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
        .map_err(|_| "invalid backup request identity or server configuration reference")?;
    if !options.is_empty() {
        return Err("unsupported backup options");
    }
    Ok((transport, request, wait))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> impl Iterator<Item = String> {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }
    #[test]
    fn create_has_retention_and_exact_repository_selector() {
        let base = [
            "create",
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
            "--locator",
            "/backup",
            "--retention-seconds",
            "60",
        ];
        let (_, request, wait) = parse(args(&base)).expect("create request");
        assert_eq!(
            request.repository_id.as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(request.retention_seconds, Some(60));
        assert!(wait.is_none());
        assert!(parse(args(&base[..14])).is_err());
    }
    #[test]
    fn wait_polls_same_operation_and_has_bounded_timeout() {
        let base = [
            "wait",
            "--endpoint",
            "127.0.0.1:4318",
            "--allow-plaintext",
            "--credential-stdin",
            "--operation-id",
            "11111111111111111111111111111111",
        ];
        let (_, request, wait) = parse(args(&base)).expect("wait request");
        assert_eq!(request.action, "status");
        assert_eq!(wait, Some(Duration::from_secs(30)));
        let mut invalid = base.to_vec();
        invalid.extend(["--wait-seconds", "61"]);
        assert!(parse(args(&invalid)).is_err());
        assert!(parse(args(&base[..5])).is_err());
    }
    #[test]
    fn explicit_capacity_refusal_guides_same_request_retry() {
        assert_eq!(
            client_failure(BackupServiceClientFailure::CapacityUnavailable),
            "capacity unavailable; retry the same idempotent request"
        );
        assert!(client_failure(BackupServiceClientFailure::Transport).contains("outcome unknown"));
    }
}
