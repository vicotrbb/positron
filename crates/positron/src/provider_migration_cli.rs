//! Exclusive-owner commands use canonical configuration and durable migration owners.
use positron_config::{ConfigurationInputs, EffectiveConfiguration, Setting, resolve};
use positron_kernel::MountQualification;
use positron_runtime::{
    BootstrapPaths, InstanceBootstrap, LocalKeyRotationFailure, native_root_configuration,
};
use std::{collections::BTreeMap, io::Write, path::Path, process::ExitCode};
const USAGE: &str = "usage: positron keys migrate status|prepare|activate|cancel|resume|verify|retire --config PATH [--target-config PATH]";

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    crate::administrative_cli::exit(execute(arguments, &mut std::io::stdout().lock()))
}
fn execute(
    mut arguments: impl Iterator<Item = String>,
    output: &mut impl Write,
) -> Result<(), &'static str> {
    let action = arguments.next().ok_or(USAGE)?;
    if !matches!(
        action.as_str(),
        "status" | "prepare" | "activate" | "cancel" | "resume" | "verify" | "retire"
    ) {
        return Err(USAGE);
    }
    let mut options = BTreeMap::new();
    while let Some(option) = arguments.next() {
        if !matches!(option.as_str(), "--config" | "--target-config") {
            return Err("unknown migration option; credential values are never arguments");
        }
        let value = arguments.next().ok_or("missing migration option value")?;
        if value.is_empty() || value.len() > 4096 {
            return Err("migration configuration path exceeds the supported bound");
        }
        if options.insert(option, value).is_some() {
            return Err("duplicate migration option");
        }
    }
    let source = configuration(
        options
            .remove("--config")
            .ok_or("--config is required")?
            .as_ref(),
    )?;
    let target = options
        .remove("--target-config")
        .map(|path| configuration(Path::new(&path)))
        .transpose()?;
    if matches!(action.as_str(), "prepare" | "activate") != target.is_some() {
        return Err("only prepare and activate require --target-config");
    }
    if let Some(target) = &target
        && source
            .semantic_diff(target)
            .changes()
            .iter()
            .any(|change| change.setting() != Setting::SecurityProviderAccess)
    {
        return Err("target configuration may change only provider access");
    }
    let paths = BootstrapPaths::with_local_key(
        Path::new(source.data_directory()),
        Path::new(source.secrets_directory()),
        source.local_key_file().as_path(),
        MountQualification::LocalHost,
    )
    .map_err(|_| "invalid canonical migration roots")?;
    let instance = InstanceBootstrap::reopen_configured(&paths, &source).map_err(
        |_| "exclusive initialized instance and authenticated active provider access are required",
    )?;
    match action.as_str() {
        "prepare" | "activate" => {
            let target = target.as_ref().ok_or("target configuration unavailable")?;
            match target.provider_access() {
                Some(access) => {
                    let provider = native_root_configuration(access)
                        .map_err(|_| "invalid pinned target provider access")?;
                    if action == "prepare" {
                        instance
                            .begin_key_provider_migration(provider)
                            .map_err(failure)?;
                    } else {
                        instance
                            .activate_key_provider_migration(provider)
                            .map_err(failure)?;
                    }
                },
                None => {
                    if action == "prepare" {
                        instance.begin_local_key_rotation().map_err(failure)?;
                    } else {
                        instance.activate_local_key_rotation().map_err(failure)?;
                    }
                },
            }
        },
        "cancel" => {
            instance.cancel_key_provider_migration().map_err(failure)?;
        },
        "resume" => {
            instance.resume_key_provider_migration().map_err(failure)?;
        },
        "verify" | "retire" => match source.provider_access() {
            Some(access) => {
                let provider = native_root_configuration(access)
                    .map_err(|_| "invalid pinned active provider access")?;
                if action == "verify" {
                    instance
                        .verify_key_provider_migration(provider)
                        .map_err(failure)?;
                } else {
                    instance
                        .retire_key_provider_predecessor(provider)
                        .map_err(failure)?;
                }
            },
            None => {
                if action == "verify" {
                    instance.verify_local_key_rotation().map_err(failure)?;
                } else {
                    instance.retire_local_key_predecessor().map_err(failure)?;
                }
            },
        },
        "status" => {},
        _ => return Err(USAGE),
    }
    let status = instance.key_provider_migration_status().map_err(failure)?;
    let target = status
        .target_provider()
        .map(|identity| format!("{}@{}", identity.locator(), identity.version()))
        .unwrap_or_else(|| "none".to_owned());
    writeln!(output, "action={} phase={:?} active_epoch={} successor_epoch={:?} predecessor_epoch={:?} active={}@{} source={}@{} target={}", action, status.rotation().phase(), status.rotation().active_epoch(), status.rotation().successor_epoch(), status.rotation().predecessor_epoch(), status.active_provider().locator(), status.active_provider().version(), status.source_provider().locator(), status.source_provider().version(), target).map_err(|_| "migration output unavailable")
}
fn configuration(path: &Path) -> Result<EffectiveConfiguration, &'static str> {
    let inputs = ConfigurationInputs::try_from_sources(
        Some(path),
        [] as [(&str, &str); 0],
        [] as [(&str, &str); 0],
    )
    .map_err(|_| "protected canonical configuration unavailable")?;
    resolve(inputs).map_err(|_| "invalid canonical migration configuration")
}
fn failure(value: LocalKeyRotationFailure) -> &'static str {
    match value {
        LocalKeyRotationFailure::Custody => {
            "active custody or independently verified successor recovery unavailable"
        },
        LocalKeyRotationFailure::Authentication => {
            "provider context or migration authority authentication failed"
        },
        LocalKeyRotationFailure::LimitExceeded => "migration resource admission unavailable",
        LocalKeyRotationFailure::Storage => {
            "migration publication unavailable; inspect durable state before retrying"
        },
        LocalKeyRotationFailure::Busy => {
            "managed references or migration phase prevent this transition"
        },
        LocalKeyRotationFailure::InvalidInput => "invalid migration transition",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
