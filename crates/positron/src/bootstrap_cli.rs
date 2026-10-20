//! Native one-time credential delivery uses the canonical bootstrap owner.
use positron_config::{ConfigurationInputs, resolve};
use positron_runtime::{BootstrapPaths, InstanceBootstrap};
use std::{io::Write, path::Path, process::ExitCode};

pub(super) fn run(
    mut arguments: impl Iterator<Item = String>,
    environment: impl IntoIterator<Item = (String, String)>,
) -> ExitCode {
    crate::administrative_cli::exit((|| {
        if arguments.next().as_deref() != Some("claim") {
            return Err("usage: positron bootstrap claim [--config FILE]");
        }
        let config = match arguments.next().as_deref() {
            Some("--config") => Some(arguments.next().ok_or("missing configuration path")?),
            None => None,
            _ => return Err("usage: positron bootstrap claim [--config FILE]"),
        };
        if arguments.next().is_some() {
            return Err("unexpected bootstrap claim argument");
        }
        let inputs = ConfigurationInputs::try_from_sources(
            config.as_deref().map(Path::new),
            environment,
            [] as [(&str, &str); 0],
        )
        .map_err(|_| "invalid bootstrap configuration")?;
        let config = resolve(inputs).map_err(|_| "invalid bootstrap configuration")?;
        let paths = BootstrapPaths::with_local_key(
            Path::new(config.data_directory()),
            Path::new(config.secrets_directory()),
            config.local_key_file().as_path(),
            positron_kernel::MountQualification::LocalHost,
        )
        .map_err(|_| "invalid bootstrap paths")?;
        let claim = InstanceBootstrap::claim(&paths)
            .map_err(|_| "bootstrap claim unavailable; already claimed or instance/key state requires recovery")?;
        let mut output = std::io::stdout().lock();
        writeln!(output, "administrator_secret={}", claim.secret())
            .map_err(|_| "claim output unavailable; credentials cannot be redisplayed")?;
        if let Some(secret) = claim.ingest_secret() {
            writeln!(output, "ingest_secret={secret}")
                .map_err(|_| "claim output unavailable; credentials cannot be redisplayed")?;
        }
        if let Some(secret) = claim.query_secret() {
            writeln!(output, "query_secret={secret}")
                .map_err(|_| "claim output unavailable; credentials cannot be redisplayed")?;
        }
        output
            .flush()
            .map_err(|_| "claim output unavailable; credentials cannot be redisplayed")
    })())
}
