use super::*;

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Offline,
    Online,
}
pub(super) struct Options {
    pub(super) mode: Mode,
    pub(super) config: Option<PathBuf>,
    pub(super) overrides: Vec<(String, String)>,
    pub(super) endpoint: Option<SocketAddr>,
    pub(super) control_path: Option<PathBuf>,
    pub(super) server_name: Option<String>,
    pub(super) trust_file: Option<PathBuf>,
    pub(super) allow_plaintext: bool,
}

impl Options {
    pub(super) fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, DoctorFailure> {
        let mut mode = None;
        let mut config = None;
        let mut overrides = Vec::new();
        let mut endpoint = None;
        let mut control_path = None;
        let mut server_name = None;
        let mut trust_file = None;
        let mut allow_plaintext = false;
        let mut credential_stdin = false;
        let mut arguments = arguments;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--offline" if mode.is_none() => mode = Some(Mode::Offline),
                "--online" if mode.is_none() => mode = Some(Mode::Online),
                "--config" if config.is_none() => {
                    config = Some(PathBuf::from(
                        arguments.next().ok_or(DoctorFailure::Arguments)?,
                    ))
                },
                "--set" => {
                    let value = arguments.next().ok_or(DoctorFailure::Arguments)?;
                    let (key, value) = value.split_once('=').ok_or(DoctorFailure::Arguments)?;
                    overrides.push((key.to_owned(), value.to_owned()));
                },
                "--endpoint" if endpoint.is_none() => {
                    endpoint = Some(
                        arguments
                            .next()
                            .ok_or(DoctorFailure::Arguments)?
                            .parse()
                            .map_err(|_| DoctorFailure::Arguments)?,
                    )
                },
                "--control-path" if control_path.is_none() => {
                    control_path = Some(PathBuf::from(
                        arguments.next().ok_or(DoctorFailure::Arguments)?,
                    ))
                },
                "--server-name" if server_name.is_none() => {
                    server_name = Some(arguments.next().ok_or(DoctorFailure::Arguments)?)
                },
                "--trust-file" if trust_file.is_none() => {
                    trust_file = Some(PathBuf::from(
                        arguments.next().ok_or(DoctorFailure::Arguments)?,
                    ))
                },
                "--allow-plaintext" if !allow_plaintext => allow_plaintext = true,
                "--credential-stdin" if !credential_stdin => credential_stdin = true,
                _ => return Err(DoctorFailure::Arguments),
            }
        }
        let mode = mode.ok_or(DoctorFailure::Arguments)?;
        match mode {
            Mode::Offline
                if endpoint.is_some()
                    || control_path.is_some()
                    || server_name.is_some()
                    || trust_file.is_some()
                    || allow_plaintext
                    || credential_stdin =>
            {
                Err(DoctorFailure::Arguments)
            },
            Mode::Online
                if config.is_some()
                    || !overrides.is_empty()
                    || !credential_stdin
                    || (endpoint.is_some() == control_path.is_some())
                    || (control_path.is_some()
                        && (server_name.is_some() || trust_file.is_some() || allow_plaintext)) =>
            {
                Err(DoctorFailure::Arguments)
            },
            Mode::Offline | Mode::Online => Ok(Self {
                mode,
                config,
                overrides,
                endpoint,
                control_path,
                server_name,
                trust_file,
                allow_plaintext,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum DoctorFailure {
    Arguments,
    ConfigurationInvalid,
    AuthenticationRejected,
    TrustFileRejected,
    EndpointUnavailable,
}
impl std::fmt::Display for DoctorFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.render())
    }
}
impl std::error::Error for DoctorFailure {}
impl DoctorFailure {
    pub(super) const fn exit_code(self) -> u8 {
        match self {
            Self::Arguments | Self::ConfigurationInvalid => EXIT_USAGE,
            Self::AuthenticationRejected | Self::TrustFileRejected | Self::EndpointUnavailable => {
                EXIT_DIAGNOSTIC_FAILURE
            },
        }
    }
    pub(super) const fn render(self) -> &'static str {
        match self {
            Self::Arguments => {
                "report_version=1\nmode=unknown\nstatus=invalid_arguments\nfinding_code=DOCTOR_ARGUMENTS_INVALID\nseverity=error\nsafe_command=correct_doctor_arguments\n"
            },
            Self::ConfigurationInvalid => {
                "report_version=1\nmode=offline\nstatus=configuration_invalid\nfinding_code=DOCTOR_CONFIGURATION_INVALID\nseverity=error\nevidence_scope=configuration_contract\nconfiguration_contract=invalid\nremaining_inspection=unknown\nsafe_command=positron config validate\n"
            },
            Self::AuthenticationRejected => {
                "report_version=1\nmode=online\nstatus=authentication_rejected\nfinding_code=DOCTOR_AUTHENTICATION_REJECTED\nseverity=error\nevidence_scope=none\nsafe_command=use_system_administrator_credential\n"
            },
            Self::TrustFileRejected => {
                "report_version=1\nmode=online\nstatus=trust_file_rejected\nfinding_code=DOCTOR_TRUST_FILE_REJECTED\nseverity=error\nevidence_scope=none\nsafe_command=provide_a_regular_bounded_trust_file\n"
            },
            Self::EndpointUnavailable => {
                "report_version=1\nmode=online\nstatus=inspection_unavailable\nfinding_code=DOCTOR_ONLINE_INSPECTION_UNAVAILABLE\nseverity=error\nevidence_scope=none\nsafe_command=inspect_runtime_connectivity\n"
            },
        }
    }
}
