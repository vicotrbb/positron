use super::*;

#[derive(Default)]
pub(super) struct VerifyOptions {
    pub(super) offline: bool,
    pub(super) online: bool,
    pub(super) config: Option<PathBuf>,
    pub(super) overrides: Vec<(String, String)>,
    pub(super) endpoint: Option<SocketAddr>,
    pub(super) server_name: Option<String>,
    pub(super) trust_file: Option<PathBuf>,
    pub(super) allow_plaintext: bool,
    pub(super) credential_stdin: bool,
    pub(super) tenant: Option<String>,
    pub(super) signal: Option<String>,
    pub(super) shard: Option<u32>,
    pub(super) expected_catalog_generation: Option<u64>,
    pub(super) continuation: Option<String>,
}

impl VerifyOptions {
    pub(super) fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, VerifyFailure> {
        let mut result = Self::default();
        let mut arguments = arguments;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--offline" if !result.offline && !result.online => result.offline = true,
                "--online" if !result.online && !result.offline => result.online = true,
                "--allow-plaintext" if !result.allow_plaintext => result.allow_plaintext = true,
                "--credential-stdin" if !result.credential_stdin => result.credential_stdin = true,
                "--config" if result.config.is_none() => {
                    result.config =
                        Some(PathBuf::from(arguments.next().ok_or(VerifyFailure::Usage)?));
                },
                "--set" => {
                    let value = arguments.next().ok_or(VerifyFailure::Usage)?;
                    let (path, value) = value.split_once('=').ok_or(VerifyFailure::Usage)?;
                    result.overrides.push((path.to_owned(), value.to_owned()));
                },
                "--endpoint" if result.endpoint.is_none() => {
                    result.endpoint = Some(
                        arguments
                            .next()
                            .ok_or(VerifyFailure::Usage)?
                            .parse()
                            .map_err(|_| VerifyFailure::Usage)?,
                    );
                },
                "--server-name" if result.server_name.is_none() => {
                    result.server_name = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                "--trust-file" if result.trust_file.is_none() => {
                    result.trust_file =
                        Some(PathBuf::from(arguments.next().ok_or(VerifyFailure::Usage)?));
                },
                "--tenant" if result.tenant.is_none() => {
                    result.tenant = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                "--signal" if result.signal.is_none() => {
                    result.signal = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                "--shard" if result.shard.is_none() => {
                    result.shard = Some(
                        arguments
                            .next()
                            .ok_or(VerifyFailure::Usage)?
                            .parse()
                            .map_err(|_| VerifyFailure::Usage)?,
                    );
                },
                "--expected-catalog-generation" if result.expected_catalog_generation.is_none() => {
                    result.expected_catalog_generation = Some(
                        arguments
                            .next()
                            .ok_or(VerifyFailure::Usage)?
                            .parse()
                            .map_err(|_| VerifyFailure::Usage)?,
                    );
                },
                "--continuation" if result.continuation.is_none() => {
                    result.continuation = Some(arguments.next().ok_or(VerifyFailure::Usage)?);
                },
                _ => return Err(VerifyFailure::Usage),
            }
        }
        if !result.offline && !result.online {
            return Err(VerifyFailure::Usage);
        }
        if result.offline
            && (result.endpoint.is_some()
                || result.server_name.is_some()
                || result.trust_file.is_some()
                || result.allow_plaintext
                || result.expected_catalog_generation.is_some())
        {
            return Err(VerifyFailure::Usage);
        }
        if result.offline
            && result.continuation.is_some()
            && (result.tenant.is_some() || result.signal.is_some() || result.shard.is_some())
        {
            return Err(VerifyFailure::Usage);
        }
        if result.offline
            && result.continuation.is_none()
            && (result.tenant.is_some() || result.signal.is_some() || result.shard.is_some())
            && (result.tenant.is_none() || result.signal.is_none() || result.shard.is_none())
        {
            return Err(VerifyFailure::Usage);
        }
        if result.online
            && (result.config.is_some()
                || !result.overrides.is_empty()
                || !result.credential_stdin
                || result.tenant.is_none()
                || result.signal.is_none()
                || result.shard.is_none()
                || result
                    .continuation
                    .as_ref()
                    .is_some_and(|_| result.expected_catalog_generation.is_none()))
        {
            return Err(VerifyFailure::Usage);
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum VerifyFailure {
    Usage,
    Configuration,
}

impl VerifyFailure {
    pub(super) const fn status(self) -> &'static str {
        match self {
            Self::Usage => "invalid_arguments",
            Self::Configuration => "configuration_rejected",
        }
    }
}
