use super::*;
use crate::recovery_cli::{decode, pinned_identity};
use positron_backup::{BackupRepositoryRegistration, RepositoryIdentity};
use positron_governance::{
    BackupVerificationParameters, RepositoryAction, RepositoryOperationParameters,
};

pub(super) fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Options, &'static str> {
    let action = match arguments.next().as_deref() {
        Some("start") => Action::Start,
        Some("status") => Action::Status,
        Some("wait") => Action::Wait,
        Some("cancel") => Action::Cancel,
        _ => return Err(USAGE),
    };
    let mut values = std::collections::BTreeMap::new();
    let mut passphrase = false;
    let mut total = 0usize;
    while let Some(name) = arguments.next() {
        if name == "--passphrase" && !passphrase {
            passphrase = true;
            continue;
        }
        if !matches!(
            name.as_str(),
            "--config"
                | "--output"
                | "--locator"
                | "--repository-id"
                | "--snapshot-id"
                | "--expected-manifest-checksum"
                | "--idempotency-key"
                | "--instance"
                | "--root-key-id"
                | "--root-created-at"
                | "--root-fingerprint"
                | "--integrity-public-key"
                | "--integrity-fingerprint"
                | "--bundle"
                | "--identity-file"
                | "--source-root-key-id"
                | "--source-root-fingerprint"
                | "--source-root-created-at"
                | "--provider-epoch"
                | "--expected-operation-revision"
                | "--cancellation-key"
                | "--wait-seconds"
                | "--operation-id"
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
        ) {
            return Err("unknown restore option; secret arguments are never accepted");
        }
        let value = arguments.next().ok_or("missing restore option value")?;
        total = total
            .checked_add(name.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or("restore input exceeds supported bound")?;
        if value.len() > 4096 || total > 32 * 1024 || values.len() >= 48 {
            return Err("restore input exceeds supported bound");
        }
        if values.insert(name, value).is_some() {
            return Err("duplicate restore option");
        }
    }
    let json = match values.remove("--output").as_deref() {
        None | Some("text") => false,
        Some("json") => true,
        _ => return Err("restore output must be text or json"),
    };
    let config = PathBuf::from(take(&mut values, "--config")?);
    let configuration = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&config),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|_| "invalid restore configuration")?,
    )
    .map_err(|_| "invalid restore configuration")?;
    let paths = BootstrapPaths::new(
        Path::new(configuration.data_directory()),
        Path::new(configuration.secrets_directory()),
        positron_kernel::MountQualification::LocalHost,
    )
    .map_err(|_| "invalid restore target roots")?;
    let pin = pinned_identity(&mut values)?;
    let repository_id = identifier(&take(&mut values, "--repository-id")?)?;
    let source_repository = repository(&mut values, repository_id, pin)?;
    let snapshot = identifier(&take(&mut values, "--snapshot-id")?)?;
    let checksum = decode(&take(&mut values, "--expected-manifest-checksum")?)?;
    let registration = BackupRepositoryRegistration::new(source_repository.0, &source_repository.1)
        .map_err(|_| "invalid restore repository")?;
    let source = BackupVerificationParameters::new(
        source_repository.2,
        registration
            .binding_identity()
            .map_err(|_| "invalid restore registration")?,
        snapshot,
        checksum,
    )
    .map_err(|_| "invalid restore source identity")?;
    let idempotency =
        AdministrativeIdempotencyKey::new(identifier(&take(&mut values, "--idempotency-key")?)?)
            .map_err(|_| "invalid restore idempotency key")?;
    let (request, recovery) = if configuration.provider_access().is_some() {
        if passphrase || values.contains_key("--bundle") || values.contains_key("--identity-file") {
            return Err("choose the configured native provider or a local recovery bundle");
        }
        let anchor = positron_kernel::BootstrapKeyIdentity::from_parts(
            decode(&take(&mut values, "--source-root-key-id")?)?,
            decode(&take(&mut values, "--source-root-fingerprint")?)?,
            number(&take(&mut values, "--source-root-created-at")?)?,
        )
        .map_err(|_| "invalid source root anchor")?;
        let epoch = number(&take(&mut values, "--provider-epoch")?)?;
        (
            BackupRestoreRequest::provider(source, pin, anchor, epoch, idempotency)
                .map_err(|_| "invalid restore provider binding")?,
            Unlock::Provider,
        )
    } else {
        let bundle = PathBuf::from(take(&mut values, "--bundle")?);
        let identity = values.remove("--identity-file").map(PathBuf::from);
        if passphrase == identity.is_some() {
            return Err("choose --identity-file or interactive --passphrase");
        }
        (
            BackupRestoreRequest::new(source, pin, bundle, idempotency)
                .map_err(|_| "invalid restore bundle binding")?,
            Unlock::Bundle(identity),
        )
    };
    let wait_seconds = values
        .remove("--wait-seconds")
        .map(|value| number(&value))
        .transpose()?;
    if wait_seconds.is_some_and(|seconds| seconds == 0 || seconds > 86400)
        || wait_seconds.is_some() && matches!(action, Action::Status | Action::Cancel)
    {
        return Err("invalid restore wait duration");
    }
    let operation = values
        .remove("--operation-id")
        .map(|value| identifier(&value))
        .transpose()?;
    let cancellation = match action {
        Action::Cancel => Some((
            AdministrativeIdempotencyKey::new(identifier(&take(
                &mut values,
                "--cancellation-key",
            )?)?)
            .map_err(|_| "invalid cancellation key")?,
            number(&take(&mut values, "--expected-operation-revision")?)?,
        )),
        _ => None,
    };
    if !values.is_empty() {
        return Err("option does not apply to this restore command");
    }
    Ok(Options {
        json,
        action,
        paths,
        configuration,
        request,
        recovery,
        cancellation,
        operation,
        wait: wait_seconds
            .map(Duration::from_secs)
            .or_else(|| (action == Action::Wait).then_some(Duration::from_secs(60))),
    })
}
fn repository(
    values: &mut std::collections::BTreeMap<String, String>,
    id: [u8; 16],
    pin: positron_kernel::RecoveryIdentity,
) -> Result<(RepositoryIdentity, String, RepositoryOperationParameters), &'static str> {
    let fingerprint = pin.integrity().fingerprint();
    let instance = pin.instance().to_bytes();
    let (identity, locator, parameters) = if values.contains_key("--locator") {
        let locator = take(values, "--locator")?;
        let identity = RepositoryIdentity::local(id, instance, fingerprint, Path::new(&locator))
            .map_err(|_| "invalid local repository")?;
        let parameters = RepositoryOperationParameters::local(
            RepositoryAction::Verify,
            &locator,
            id,
            fingerprint,
            identity.prefix_commitment(),
        )
        .map_err(|_| "invalid local repository")?;
        (identity, locator, parameters)
    } else if values.contains_key("--aws-bucket") {
        let target = positron_backup::AwsS3Target::new(
            &take(values, "--aws-bucket")?,
            &take(values, "--aws-region")?,
            &take(values, "--aws-endpoint")?,
            &take(values, "--aws-expected-owner")?,
            &take(values, "--aws-prefix")?,
        )
        .map_err(|_| "invalid AWS repository")?;
        let identity = RepositoryIdentity::aws_s3(id, instance, fingerprint, &target)
            .map_err(|_| "invalid AWS repository")?;
        let locator = target.encode_locator();
        let parameters = RepositoryOperationParameters::aws_s3(
            RepositoryAction::Verify,
            &locator,
            id,
            fingerprint,
            identity.prefix_commitment(),
        )
        .map_err(|_| "invalid AWS repository")?;
        (identity, locator, parameters)
    } else if values.contains_key("--gcs-bucket") {
        let target = positron_backup::GoogleCloudStorageTarget::new(
            &take(values, "--gcs-bucket")?,
            &take(values, "--gcs-project-number")?,
            &take(values, "--gcs-location")?,
            &take(values, "--gcs-prefix")?,
        )
        .map_err(|_| "invalid GCS repository")?;
        let identity = RepositoryIdentity::google_cloud_storage(id, instance, fingerprint, &target)
            .map_err(|_| "invalid GCS repository")?;
        let locator = target.encode_locator();
        let parameters = RepositoryOperationParameters::google_cloud_storage(
            RepositoryAction::Verify,
            &locator,
            id,
            fingerprint,
            identity.prefix_commitment(),
        )
        .map_err(|_| "invalid GCS repository")?;
        (identity, locator, parameters)
    } else {
        let target = positron_backup::AzureBlobTarget::new(
            &take(values, "--azure-account")?,
            &take(values, "--azure-container")?,
            &take(values, "--azure-prefix")?,
        )
        .map_err(|_| "invalid Azure repository")?;
        let identity = RepositoryIdentity::azure_blob(id, instance, fingerprint, &target)
            .map_err(|_| "invalid Azure repository")?;
        let locator = target.encode_locator();
        let parameters = RepositoryOperationParameters::azure_blob(
            RepositoryAction::Verify,
            &locator,
            id,
            fingerprint,
            identity.prefix_commitment(),
        )
        .map_err(|_| "invalid Azure repository")?;
        (identity, locator, parameters)
    };
    Ok((identity, locator, parameters))
}
fn take(
    values: &mut std::collections::BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, &'static str> {
    values.remove(name).ok_or(name)
}
fn number(value: &str) -> Result<u64, &'static str> {
    value.parse().map_err(|_| "invalid unsigned restore number")
}
fn identifier(value: &str) -> Result<[u8; 16], &'static str> {
    if value.len() == 32 {
        return decode(value);
    }
    if value.len() != 36
        || !value.is_ascii()
        || [8, 13, 18, 23]
            .into_iter()
            .any(|offset| value.as_bytes().get(offset) != Some(&b'-'))
    {
        return Err("invalid restore identifier");
    }
    decode(&value.replace('-', ""))
}
