//! Exclusive filesystem-owner adapter for the existing local root lifecycle.
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InstanceBootstrap, LocalKeyRotationFailure};
use std::{collections::BTreeMap, io::Write, process::ExitCode};

const USAGE: &str =
    "usage: positron keys local status|prepare|activate|retire --data-dir PATH --secrets-dir PATH";

pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    crate::administrative_cli::exit(execute(arguments))
}

fn execute(mut arguments: impl Iterator<Item = String>) -> Result<(), &'static str> {
    let action = arguments.next().ok_or(USAGE)?;
    if !matches!(
        action.as_str(),
        "status" | "prepare" | "activate" | "retire"
    ) {
        return Err(USAGE);
    }
    let mut options = BTreeMap::new();
    while let Some(option) = arguments.next() {
        if !matches!(option.as_str(), "--data-dir" | "--secrets-dir") {
            return Err("unknown local-key option; secret values are never accepted as arguments");
        }
        let value = arguments.next().ok_or("missing local-key option value")?;
        if value.is_empty() || value.len() > 4096 {
            return Err("local-key path exceeds the supported bound");
        }
        if options.insert(option, value).is_some() {
            return Err("duplicate local-key option");
        }
    }
    let data = options
        .remove("--data-dir")
        .ok_or("--data-dir is required")?;
    let secrets = options
        .remove("--secrets-dir")
        .ok_or("--secrets-dir is required")?;
    let paths = BootstrapPaths::new(
        std::path::Path::new(&data),
        std::path::Path::new(&secrets),
        MountQualification::LocalHost,
    )
    .map_err(|_| "invalid local-key paths")?;
    let instance = InstanceBootstrap::reopen(&paths)
        .map_err(|_| "exclusive initialized instance and valid local custody are required")?;
    let status = match action.as_str() {
        "prepare" => instance.begin_local_key_rotation(),
        "activate" => instance.activate_local_key_rotation(),
        "retire" => {
            instance.retire_local_key_predecessor().map_err(failure)?;
            instance.local_key_rotation_status()
        },
        "status" => instance.local_key_rotation_status(),
        _ => return Err(USAGE),
    }
    .map_err(failure)?;
    writeln!(
        std::io::stdout().lock(),
        "action={} phase={:?} active_epoch={} successor_epoch={:?} predecessor_epoch={:?}",
        action,
        status.phase(),
        status.active_epoch(),
        status.successor_epoch(),
        status.predecessor_epoch()
    )
    .map_err(|_| "local-key output unavailable")
}

fn failure(value: LocalKeyRotationFailure) -> &'static str {
    match value {
        LocalKeyRotationFailure::Custody => {
            "local custody or independently verified successor recovery is unavailable"
        },
        LocalKeyRotationFailure::Authentication => {
            "local-key context or rotation authority authentication failed"
        },
        LocalKeyRotationFailure::LimitExceeded => "local-key resource admission unavailable",
        LocalKeyRotationFailure::Storage => {
            "local-key publication unavailable; inspect durable state before retrying"
        },
        LocalKeyRotationFailure::Busy => {
            "managed references or an active rotation prevent this transition"
        },
        LocalKeyRotationFailure::InvalidInput => "invalid local-key transition",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_or_unbounded_arguments_refuse_before_storage() {
        for arguments in [
            vec!["unknown".to_owned()],
            vec![
                "status".to_owned(),
                "--key".to_owned(),
                "private".to_owned(),
            ],
            vec![
                "status".to_owned(),
                "--data-dir".to_owned(),
                "x".repeat(4097),
            ],
            vec![
                "status".to_owned(),
                "--data-dir".to_owned(),
                "x".to_owned(),
                "--data-dir".to_owned(),
                "y".to_owned(),
            ],
        ] {
            assert!(execute(arguments.into_iter()).is_err());
        }
    }
}
