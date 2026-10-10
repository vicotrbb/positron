//! Explicit offline owner workflow; secret values never enter argv or environment handling.
use positron_kernel::{
    BootstrapIntegrityIdentity, BootstrapKeyIdentity, InstanceId, MountQualification,
    RecoveryFailure, RecoveryIdentity, RecoveryPassphrase, RecoveryRecipients, RecoveryUnlock,
};
use positron_runtime::{BootstrapPaths, InstanceBootstrap};
use std::{collections::BTreeMap, io::Write, path::PathBuf, process::ExitCode};
mod terminal;
const USAGE: &str = "usage: positron keys recovery create|verify|inspect|rotate|retire|import --data-dir PATH --secrets-dir PATH [--bundle PATH] [--recipient age1...] [--identity-file PATH | --passphrase]";
struct Options {
    command: String,
    paths: BootstrapPaths,
    bundle: Option<PathBuf>,
    recipients: Option<RecoveryRecipients>,
    identity: Option<PathBuf>,
    passphrase: bool,
    pin: Option<RecoveryIdentity>,
}
pub(super) fn run(arguments: impl Iterator<Item = String>) -> ExitCode {
    crate::administrative_cli::exit(execute(arguments))
}
fn execute(arguments: impl Iterator<Item = String>) -> Result<(), &'static str> {
    let options = parse(arguments)?;
    let mut read_unlock = || terminal::passphrase(false).map_err(|_| RecoveryFailure::InvalidInput);
    let pin = if options.command == "import" {
        let bundle = options.bundle.as_deref().ok_or("--bundle is required")?;
        let pin = options
            .pin
            .ok_or("all externally pinned identity fields are required for import")?;
        let instance = InstanceBootstrap::import_recovery_bundle(
            &options.paths,
            bundle,
            pin,
            unlock(&options, &mut read_unlock)?,
        )
        .map_err(failure)?;
        instance.recovery_identity().map_err(failure)?
    } else {
        let instance = InstanceBootstrap::reopen(&options.paths).map_err(
            |_| "exclusive initialized instance and valid local key custody are required",
        )?;
        if options.command == "retire" {
            instance.retire_recovery_predecessor().map_err(failure)?;
        } else {
            let bundle = options.bundle.as_deref().ok_or("--bundle is required")?;
            match options.command.as_str() {
                "create" | "rotate" => {
                    match (&options.recipients, options.passphrase) {
                        (Some(recipients), false) => instance
                            .create_recovery_bundle(bundle, recipients)
                            .map_err(failure)?,
                        (None, true) => instance
                            .create_interactive_recovery_bundle(bundle, || {
                                terminal::passphrase(true)
                                    .map_err(|_| RecoveryFailure::InvalidInput)
                            })
                            .map_err(failure)?,
                        _ => {
                            return Err(
                                "choose X25519 recipients or interactive passphrase protection",
                            );
                        },
                    }
                    if options.command == "rotate" {
                        instance
                            .verify_recovery_bundle(bundle, unlock(&options, &mut read_unlock)?)
                            .map_err(failure)?;
                    }
                },
                "verify" => {
                    instance
                        .verify_recovery_bundle(bundle, unlock(&options, &mut read_unlock)?)
                        .map_err(failure)?;
                },
                "inspect" => {
                    let metadata = instance
                        .inspect_recovery_bundle(bundle, unlock(&options, &mut read_unlock)?)
                        .map_err(failure)?;
                    let mut output = std::io::stdout().lock();
                    writeln!(output,"format=age-encryption.org/v1 payload_version={} created_at={} recipients={}",metadata.payload_version(),metadata.created_at_unix_seconds(),metadata.recipients().join(",")).map_err(|_|"output unavailable")?;
                },
                _ => return Err(USAGE),
            }
        }
        instance.recovery_identity().map_err(failure)?
    };
    let mut output = std::io::stdout().lock();
    writeln!(output,"completed={} instance={} root_key_id={} root_created_at={} root_fingerprint={} integrity_public_key={} integrity_fingerprint={}",options.command,hex(&pin.instance().to_bytes()),hex(&pin.root().key_id()),pin.root().created_at_unix_seconds(),hex(&pin.root().fingerprint()),hex(&pin.integrity().public_key()),hex(&pin.integrity().fingerprint())).map_err(|_|"output unavailable")
}
fn unlock<'a>(
    options: &'a Options,
    read: &'a mut dyn FnMut() -> Result<RecoveryPassphrase, RecoveryFailure>,
) -> Result<RecoveryUnlock<'a>, &'static str> {
    if options.passphrase {
        Ok(RecoveryUnlock::InteractivePassphrase(read))
    } else {
        options
            .identity
            .as_deref()
            .map(RecoveryUnlock::IdentityFile)
            .ok_or("--identity-file or --passphrase is required")
    }
}
fn failure(value: RecoveryFailure) -> &'static str {
    match value {
        RecoveryFailure::Authentication => {
            "recovery authentication failed; check the recipient, artifact and externally pinned identity"
        },
        RecoveryFailure::Admission => "recovery resource admission unavailable",
        RecoveryFailure::InvalidInput => {
            "invalid recovery request or protected terminal input; passphrases require an interactive terminal"
        },
        RecoveryFailure::AlreadyExists => {
            "destination already exists; choose a separate replacement artifact"
        },
        RecoveryFailure::Missing => "recovery artifact is missing",
        RecoveryFailure::LimitExceeded => "recovery input exceeds the supported bound",
        RecoveryFailure::Custody => {
            "local root publication failed; existing custody is never overwritten"
        },
        RecoveryFailure::Storage => {
            "recovery storage unavailable; inspect current state before retrying"
        },
    }
}
fn parse(mut arguments: impl Iterator<Item = String>) -> Result<Options, &'static str> {
    if arguments.next().as_deref() != Some("recovery") {
        return Err(USAGE);
    }
    let command = arguments.next().ok_or(USAGE)?;
    if !matches!(
        command.as_str(),
        "create" | "verify" | "inspect" | "rotate" | "retire" | "import"
    ) {
        return Err(USAGE);
    }
    let mut values = BTreeMap::new();
    let mut recipients = Vec::new();
    let mut passphrase = false;
    while let Some(name) = arguments.next() {
        if name == "--passphrase" && !passphrase {
            passphrase = true;
            continue;
        }
        if !matches!(
            name.as_str(),
            "--data-dir"
                | "--secrets-dir"
                | "--bundle"
                | "--recipient"
                | "--identity-file"
                | "--instance"
                | "--root-key-id"
                | "--root-created-at"
                | "--root-fingerprint"
                | "--integrity-public-key"
                | "--integrity-fingerprint"
        ) {
            return Err("unknown recovery option; secret values are never accepted as arguments");
        }
        let value = arguments.next().ok_or("missing recovery option value")?;
        if value.len() > 4096 {
            return Err("recovery option exceeds supported bound");
        }
        if name == "--recipient" {
            if recipients.len() == 16 {
                return Err("at most sixteen X25519 recipients are supported");
            }
            recipients.push(value);
        } else if values.insert(name, value).is_some() {
            return Err("duplicate recovery option");
        }
    }
    let data = values
        .remove("--data-dir")
        .ok_or("--data-dir is required")?;
    let secrets = values
        .remove("--secrets-dir")
        .ok_or("--secrets-dir is required")?;
    let paths = BootstrapPaths::new(
        std::path::Path::new(&data),
        std::path::Path::new(&secrets),
        MountQualification::LocalHost,
    )
    .map_err(|_| "invalid instance roots")?;
    let bundle = values.remove("--bundle").map(PathBuf::from);
    let identity = values.remove("--identity-file").map(PathBuf::from);
    let pin = if command == "import" {
        let instance = InstanceId::new(decode(
            &values
                .remove("--instance")
                .ok_or("--instance is required")?,
        )?)
        .map_err(|_| "invalid pinned instance")?;
        let key_id = decode(
            &values
                .remove("--root-key-id")
                .ok_or("--root-key-id is required")?,
        )?;
        let created = values
            .remove("--root-created-at")
            .ok_or("--root-created-at is required")?
            .parse()
            .map_err(|_| "invalid root creation time")?;
        let fingerprint = decode(
            &values
                .remove("--root-fingerprint")
                .ok_or("--root-fingerprint is required")?,
        )?;
        let root = BootstrapKeyIdentity::from_parts(key_id, fingerprint, created)
            .map_err(|_| "invalid root identity")?;
        let integrity = BootstrapIntegrityIdentity::from_pinned(
            decode(
                &values
                    .remove("--integrity-public-key")
                    .ok_or("--integrity-public-key is required")?,
            )?,
            decode(
                &values
                    .remove("--integrity-fingerprint")
                    .ok_or("--integrity-fingerprint is required")?,
            )?,
        )
        .map_err(|_| "invalid pinned integrity identity")?;
        Some(
            RecoveryIdentity::new(instance, root, integrity)
                .map_err(|_| "invalid recovery identity")?,
        )
    } else {
        None
    };
    if !values.is_empty() {
        return Err("option does not apply to this recovery command");
    }
    if passphrase && (identity.is_some() || !recipients.is_empty()) {
        return Err("interactive passphrase protection cannot be mixed with X25519");
    }
    if command == "retire" {
        if bundle.is_some() || identity.is_some() || passphrase || !recipients.is_empty() {
            return Err(
                "retire uses the exact Catalog-tracked predecessor and verified replacement",
            );
        }
    } else {
        if bundle.is_none() {
            return Err("--bundle is required");
        }
        if matches!(command.as_str(), "create" | "rotate") {
            if recipients.is_empty() && !passphrase {
                return Err("--recipient or --passphrase is required");
            }
            if command == "create" && identity.is_some() {
                return Err("identity input does not apply to creation");
            }
        } else if !recipients.is_empty() {
            return Err("recipient options apply only to create or rotate");
        }
        if matches!(command.as_str(), "inspect" | "verify" | "rotate" | "import")
            && identity.is_none()
            && !passphrase
        {
            return Err("--identity-file or --passphrase is required");
        }
    }
    let recipients = if recipients.is_empty() {
        None
    } else {
        Some(
            RecoveryRecipients::parse(&recipients)
                .map_err(|_| "invalid native X25519 recipient set")?,
        )
    };
    Ok(Options {
        command,
        paths,
        bundle,
        recipients,
        identity,
        passphrase,
        pin,
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err("invalid hexadecimal pinned identity");
    }
    let mut bytes = [0; N];
    for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let value = std::str::from_utf8(pair).map_err(|_| "invalid pinned identity")?;
        *slot = u8::from_str_radix(value, 16).map_err(|_| "invalid hexadecimal pinned identity")?;
    }
    Ok(bytes)
}
