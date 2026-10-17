//! Explicit offline continuation holds the existing exclusive volume owner.
use positron_governance::{AdministrativeIdempotencyKey, OperationId};
use positron_runtime::{BootstrapPaths, OfflineUpgradeSession};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};
const USAGE: &str = "usage: positron upgrade offline status|advance|publish|cancel|fail|rollback|restore-reference --config PATH --operation-id HEX [--seconds 1..60] [--idempotency-key HEX --expected-operation-revision N]";
struct Options {
    action: String,
    config: PathBuf,
    id: OperationId,
    seconds: u64,
    key: Option<AdministrativeIdempotencyKey>,
    revision: Option<u64>,
}
pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    crate::administrative_cli::exit(execute(arguments, &mut std::io::stdout().lock()))
}
fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Options, &'static str> {
    let action = arguments.next().ok_or(USAGE)?;
    if !matches!(
        action.as_str(),
        "status" | "advance" | "publish" | "cancel" | "fail" | "rollback" | "restore-reference"
    ) {
        return Err(USAGE);
    }
    let mut values = BTreeMap::new();
    while let Some(name) = arguments.next() {
        if !matches!(
            name.as_str(),
            "--config"
                | "--operation-id"
                | "--seconds"
                | "--idempotency-key"
                | "--expected-operation-revision"
        ) {
            return Err(USAGE);
        }
        let value = arguments.next().ok_or(USAGE)?;
        if value.is_empty() || value.len() > 2048 || values.insert(name, value).is_some() {
            return Err("invalid or duplicate offline upgrade option");
        }
    }
    let config = PathBuf::from(values.remove("--config").ok_or(USAGE)?);
    if !config.is_absolute() {
        return Err("offline configuration path must be absolute");
    }
    let id = OperationId::from_bytes(crate::recovery_cli::decode(
        &values.remove("--operation-id").ok_or(USAGE)?,
    )?)
    .map_err(|_| "invalid operation ID")?;
    let seconds = values
        .remove("--seconds")
        .map(|s| s.parse::<u64>().map_err(|_| USAGE))
        .transpose()?;
    if seconds.is_some() && action != "advance" {
        return Err(USAGE);
    }
    let seconds = seconds.unwrap_or(30);
    if !(1..=60).contains(&seconds) {
        return Err(USAGE);
    }
    let key = values
        .remove("--idempotency-key")
        .map(|s| {
            crate::recovery_cli::decode(&s).and_then(|b| {
                AdministrativeIdempotencyKey::new(b).map_err(|_| "invalid idempotency key")
            })
        })
        .transpose()?;
    let revision = values
        .remove("--expected-operation-revision")
        .map(|s| s.parse::<u64>().map_err(|_| USAGE))
        .transpose()?;
    if matches!(action.as_str(), "cancel" | "rollback") {
        if key.is_none() || revision.is_none() {
            return Err(USAGE);
        }
    } else if key.is_some() || revision.is_some() {
        return Err(USAGE);
    }
    Ok(Options {
        action,
        config,
        id,
        seconds,
        key,
        revision,
    })
}
fn execute(
    arguments: impl Iterator<Item = String>,
    output: &mut impl std::io::Write,
) -> Result<(), &'static str> {
    let options = parse(arguments)?;
    let configuration = positron_config::resolve(
        positron_config::ConfigurationInputs::try_from_sources(
            Some(&options.config),
            [] as [(&str, &str); 0],
            [] as [(&str, &str); 0],
        )
        .map_err(|_| "invalid upgrade configuration")?,
    )
    .map_err(|_| "invalid upgrade configuration")?;
    let paths = BootstrapPaths::with_local_key(
        Path::new(configuration.data_directory()),
        Path::new(configuration.secrets_directory()),
        configuration.local_key_file().as_path(),
        positron_kernel::MountQualification::LocalHost,
    )
    .map_err(|_| "invalid configured roots")?;
    if options.action == "restore-reference" {
        let reference =
            OfflineUpgradeSession::restore_reference(&paths, &configuration, options.id)
                .map_err(upgrade_failure)?;
        writeln!(
            output,
            "fresh_target_required=true snapshot_id={} manifest_checksum={}",
            hex(reference.snapshot_id()),
            hex(reference.manifest_checksum())
        )
        .map_err(|_| "upgrade output unavailable")?;
        return Ok(());
    }
    if options.action == "status" {
        let operation = OfflineUpgradeSession::inspect(&paths, &configuration, options.id)
            .map_err(upgrade_failure)?;
        writeln!(
            output,
            "operation_id={} status={:?} stage={:?} revision={} rollback_available={}",
            hex(operation.operation_id().to_bytes()),
            operation.status(),
            operation.upgrade_stage(),
            operation.revision(),
            operation.upgrade_rollback_available()
        )
        .map_err(|_| "upgrade output unavailable")?;
        return Ok(());
    }
    let mut session = match OfflineUpgradeSession::begin(&paths, &configuration, options.id) {
        Ok(session) => session,
        Err(
            positron_runtime::UpgradeFailure::DrainIncomplete
            | positron_runtime::UpgradeFailure::UnsafeState,
        ) if options.action == "cancel" => {
            let operation = OfflineUpgradeSession::cancel_intent(
                &paths,
                &configuration,
                options.id,
                options.key.ok_or(USAGE)?,
                options.revision.ok_or(USAGE)?,
            )
            .map_err(upgrade_failure)?;
            writeln!(
                output,
                "operation_id={} status={:?} revision={}",
                hex(operation.operation_id().to_bytes()),
                operation.status(),
                operation.revision()
            )
            .map_err(|_| "upgrade output unavailable")?;
            return Ok(());
        },
        Err(failure) => return Err(upgrade_failure(failure)),
    };
    let operation = match options.action.as_str() {
        "status" => session.status(),
        "advance" => session.advance(
            Instant::now()
                .checked_add(Duration::from_secs(options.seconds))
                .ok_or(USAGE)?,
        ),
        "publish" => session.publish_installed(&configuration),
        "cancel" => session.cancel(options.key.ok_or(USAGE)?, options.revision.ok_or(USAGE)?),
        "fail" => session.fail(),
        "rollback" => session.rollback_installed(
            &configuration,
            options.key.ok_or(USAGE)?,
            options.revision.ok_or(USAGE)?,
        ),
        _ => return Err(USAGE),
    }
    .map_err(upgrade_failure)?;
    writeln!(
        output,
        "operation_id={} status={:?} stage={:?} revision={} rollback_available={}",
        hex(operation.operation_id().to_bytes()),
        operation.status(),
        operation.upgrade_stage(),
        operation.revision(),
        operation.upgrade_rollback_available()
    )
    .map_err(|_| "upgrade output unavailable")?;
    Ok(())
}
fn hex<const N: usize>(bytes: [u8; N]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn upgrade_failure(failure: positron_runtime::UpgradeFailure) -> &'static str {
    use positron_runtime::UpgradeFailure as F;
    match failure {
        F::SnapshotUnavailable | F::CapacityUnavailable => {
            "upgrade remains resumable; inspect and retry after trusted time or capacity recovers"
        },
        F::DrainIncomplete => {
            "authenticated completed Drain is required; resume the source process control path"
        },
        F::ArtifactMismatch | F::ArtifactUnavailable => {
            "installed artifact does not match the accepted signed release"
        },
        F::AuthenticationFailed => "installed release or operation authority rejected",
        F::UnsupportedTransition => "unsupported release or format transition",
        F::StaleGeneration | F::IdempotencyConflict => {
            "upgrade precondition changed; inspect the accepted operation"
        },
        F::InvalidRequest => "offline request does not match the accepted upgrade",
        F::UnsafeState => "upgrade recovery state or exclusive volume ownership unavailable",
        F::PersistenceUnavailable => {
            "upgrade outcome unknown; inspect the same operation before retrying"
        },
        F::VerificationFailed => {
            "upgrade verification failed; use the explicit rollback or fresh-target restore boundary"
        },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn offline_upgrade_has_explicit_bounded_actions_and_no_remote_trust_options() {
        assert!(
            super::parse(
                [
                    "advance",
                    "--config",
                    "/tmp/positron.toml",
                    "--operation-id",
                    &"ab".repeat(16),
                    "--seconds",
                    "1"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_ok()
        );
        assert!(
            super::parse(
                ["install", "--config", "/tmp/positron.toml"]
                    .into_iter()
                    .map(str::to_owned)
            )
            .is_err()
        );
        assert!(
            super::parse(
                [
                    "advance",
                    "--config",
                    "/tmp/positron.toml",
                    "--operation-id",
                    &"ab".repeat(16),
                    "--seconds",
                    "0"
                ]
                .into_iter()
                .map(str::to_owned)
            )
            .is_err()
        );
    }
}
