use std::{
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use positron_governance::PresentedCredential;
use positron_runtime::{
    ControlDiagnosticsFailure, ControlDiagnosticsHandler, ControlDiagnosticsResponse,
    DoctorRuntimeFacts, FencedDiagnosticsFailure, HealthState, ProcessPhase,
    ServingDiagnosticsFailure,
};
use zeroize::Zeroizing;

use super::{
    AgeRecipients, BundleFailure, BundleLimits, BundleMember, BundleOptions, Class,
    DEFAULT_ELAPSED_LIMIT, DEFAULT_LOG_WINDOW, DEFAULT_OUTPUT_LIMIT, DEFAULT_SOURCE_FILES,
    ManifestAuthentication, SupportBundle, canonical_members, diagnostics_claim,
};

/// Binary-owned serving collector. It receives only an opaque bearer and a
/// bounded recipient request from the Control listener; all authority is
/// re-attributed against the current serving instance immediately before the
/// archive is assembled.
pub(crate) struct LiveSupportBundleCollector;

impl ControlDiagnosticsHandler for LiveSupportBundleCollector {
    fn collect(
        &self,
        bearer: &str,
        request: &[u8],
        health: &HealthState,
    ) -> Result<ControlDiagnosticsResponse, ControlDiagnosticsFailure> {
        let request = LiveBundleRequest::parse(request)
            .map_err(|_| ControlDiagnosticsFailure::Unavailable)?;
        let started = Instant::now();
        match health.phase() {
            ProcessPhase::Serving => health
                .with_authenticated_serving_diagnostics(bearer, |instance, actor, runtime| {
                let observed = runtime.observed().map_err(|_| ())?;
                let effective = observed.effective();
                let reservation = instance
                    .resource_governor()
                    .reserve(diagnostics_claim(DEFAULT_OUTPUT_LIMIT).map_err(|_| ())?)
                    .map_err(|_| ())?;
                let facts = instance.doctor_runtime_facts(actor).map_err(|_| ())?;
                let signer = instance.support_bundle_manifest_signer(actor).map_err(|_| ())?;
                let report = live_doctor_report(&facts);
                let options = BundleOptions {
                    config: PathBuf::new(),
                    output: PathBuf::new(),
                    recipients: request.recipients,
                    plaintext_warning: false,
                    offline_key_unavailable: false,
                    output_limit: DEFAULT_OUTPUT_LIMIT,
                    elapsed_limit: DEFAULT_ELAPSED_LIMIT,
                    log_window: DEFAULT_LOG_WINDOW,
                    source_file_limit: DEFAULT_SOURCE_FILES,
                    control_path: None,
                };
                let operational = format!(
                    "inspection_mode=online\nprocess_phase=serving\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nbackup_repository={}\n",
                    if facts.key_custody_verified() { "verified" } else { "unavailable" },
                    if facts.catalog_bootstrap_verified() { "verified" } else { "unavailable" },
                    facts.catalog_generation(),
                    facts.backup_repository().label(),
                );
                let members =
                    live_canonical_members(effective, &report, &operational, &options, started)
                        .map_err(|_| ())?;
                let limits = BundleLimits::new(14, DEFAULT_OUTPUT_LIMIT)
                    .map_err(|_| ())?
                    .with_elapsed_limit(DEFAULT_ELAPSED_LIMIT);
                let bundle = SupportBundle::build_authenticated(
                    members,
                    limits,
                    ManifestAuthentication::Signed(&signer),
                )
                .map_err(|_| ())?;
                let recipients = AgeRecipients::parse(options.recipients).map_err(|_| ())?;
                let ciphertext = recipients
                    .encrypt_bounded(bundle.archive(), DEFAULT_OUTPUT_LIMIT)
                    .map_err(|_| ())?;
                Ok(ControlDiagnosticsResponse::new(ciphertext, reservation.transfer()))
            })
            .map_err(|failure| match failure {
                ServingDiagnosticsFailure::AuthenticationRejected => {
                    ControlDiagnosticsFailure::AuthenticationRejected
                },
                ServingDiagnosticsFailure::Unavailable => ControlDiagnosticsFailure::Unavailable,
            }),
            ProcessPhase::Fenced => health
                .with_authenticated_fenced_diagnostics(bearer, |instance, actor, facts| {
                    let reservation = instance
                        .resource_governor()
                        .reserve(diagnostics_claim(DEFAULT_OUTPUT_LIMIT).map_err(|_| ())?)
                        .map_err(|_| ())?;
                    let signer = instance.support_bundle_manifest_signer(actor).map_err(|_| ())?;
                    let report = fenced_doctor_report(&facts);
                    let members = fenced_canonical_members(&facts, &report, started)?;
                    let limits = BundleLimits::new(14, DEFAULT_OUTPUT_LIMIT)
                        .map_err(|_| ())?
                        .with_elapsed_limit(DEFAULT_ELAPSED_LIMIT);
                    let bundle = SupportBundle::build_authenticated(
                        members,
                        limits,
                        ManifestAuthentication::Signed(&signer),
                    )
                    .map_err(|_| ())?;
                    let recipients = AgeRecipients::parse(request.recipients).map_err(|_| ())?;
                    let ciphertext = recipients
                        .encrypt_bounded(bundle.archive(), DEFAULT_OUTPUT_LIMIT)
                        .map_err(|_| ())?;
                    Ok(ControlDiagnosticsResponse::new(ciphertext, reservation.transfer()))
                })
                .map_err(|failure| match failure {
                    FencedDiagnosticsFailure::AuthenticationRejected => {
                        ControlDiagnosticsFailure::AuthenticationRejected
                    },
                    FencedDiagnosticsFailure::Unavailable => ControlDiagnosticsFailure::Unavailable,
                }),
            _ => Err(ControlDiagnosticsFailure::Unavailable),
        }
    }
}

fn live_doctor_report(facts: &DoctorRuntimeFacts) -> String {
    format!(
        "report_version=1\nmode=online\nstatus=healthy\nfinding_code=DOCTOR_SERVING_OWNER_VERIFIED\nseverity=info\nevidence_scope=authenticated_serving_instance\nprocess_phase=serving\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nbackup_repository={}\nsafe_command=none\n",
        if facts.key_custody_verified() {
            "verified"
        } else {
            "unavailable"
        },
        if facts.catalog_bootstrap_verified() {
            "verified"
        } else {
            "unavailable"
        },
        facts.catalog_generation(),
        facts.backup_repository().label(),
    )
}

fn fenced_doctor_report(facts: &DoctorRuntimeFacts) -> String {
    format!(
        "report_version=1\nmode=online_fenced\nstatus=fenced\nfinding_code=DOCTOR_FENCED_OWNER_VERIFIED\nseverity=error\nevidence_scope=authenticated_fenced_instance\nprocess_phase=fenced\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nbackup_repository={}\nsafe_command=inspect_storage_without_mutation\nfinding_code=DOCTOR_CONFIGURATION_RUNTIME_UNAVAILABLE_FENCED\nseverity=info\nevidence_scope=retired_runtime_configuration\nconfiguration_runtime=unavailable_retired_after_fence\nsafe_command=inspect_effective_configuration_after_recovery\n",
        if facts.key_custody_verified() {
            "verified"
        } else {
            "unavailable"
        },
        if facts.catalog_bootstrap_verified() {
            "verified"
        } else {
            "unavailable"
        },
        facts.catalog_generation(),
        facts.backup_repository().label(),
    )
}

/// A Fenced process deliberately retires its RuntimeConfiguration, services,
/// and data listeners. This closed member list records current authenticated
/// catalog/key facts and typed unavailable runtime families rather than
/// reusing Serving claims or reconstructing configuration from a stale owner.
fn fenced_canonical_members(
    facts: &DoctorRuntimeFacts,
    doctor: &str,
    started: Instant,
) -> Result<Vec<BundleMember>, ()> {
    if started.elapsed() > DEFAULT_ELAPSED_LIMIT {
        return Err(());
    }
    let compatibility = super::command::compatibility_manifest_evidence()?;
    let product = super::command::product_identity_evidence()?;
    let current = format!(
        "key_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nbackup_repository={}\n",
        if facts.key_custody_verified() {
            "verified"
        } else {
            "unavailable"
        },
        if facts.catalog_bootstrap_verified() {
            "verified"
        } else {
            "unavailable"
        },
        facts.catalog_generation(),
        facts.backup_repository().label(),
    );
    Ok(vec![
        BundleMember::effective_configuration(
            b"inspection_owner=configuration_runtime\navailability=unavailable\nreason=retired_after_fence\n",
        ),
        BundleMember::compatibility_manifest(compatibility.as_bytes()),
        BundleMember::product_identity(product.as_bytes()),
        BundleMember::health_state(
            b"inspection_owner=health_state\nprocess_phase=fenced\nreadiness=not_ready\nliveness=live\n",
        ),
        BundleMember::operational_telemetry(
            b"inspection_owner=operational_telemetry_runtime\navailability=unavailable\nreason=retired_after_fence\n",
        ),
        BundleMember::operational_logs_with_omission(
            b"inspection_owner=operational_log_runtime\navailability=unavailable\nreason=not_persisted\n",
            "operational_log_owner_unavailable",
        ),
        BundleMember::catalog_summary(
            format!("inspection_owner=authenticated_fenced_catalog\n{current}").as_bytes(),
        ),
        BundleMember::resource_status(
            b"inspection_owner=resource_governor\ndiagnostics_reservation=held\nresource_snapshot=unavailable\nreason=runtime_retired_after_fence\n",
        ),
        BundleMember::maintenance_status(
            b"inspection_owner=maintenance_runtime\navailability=unavailable\nreason=retired_after_fence\n",
        ),
        BundleMember::listener_status(
            b"inspection_owner=process_lifecycle\ncontrol_diagnostics=active\ndata_listeners=retired\n",
        ),
        BundleMember::backup_repository_status(
            format!("inspection_owner=authenticated_catalog_backup_binding\n{current}").as_bytes(),
        ),
        BundleMember::environment(
            format!(
                "os={}\narch={}\nenvironment_configuration=unavailable_retired_after_fence\n",
                std::env::consts::OS,
                std::env::consts::ARCH,
            )
            .as_bytes(),
        ),
        BundleMember::doctor_report(doctor.as_bytes()),
        BundleMember::sanitized_crash_records_with_omissions(
            b"inspection_owner=crash_record_store\navailability=unavailable\nreason=retired_configuration_path\n",
            &["crash_record_store_unavailable_after_fence"],
        ),
    ])
}

fn live_canonical_members(
    effective: &positron_config::EffectiveConfiguration,
    doctor: &str,
    operational: &str,
    options: &BundleOptions,
    started: Instant,
) -> Result<Vec<BundleMember>, ()> {
    let mut members =
        canonical_members(effective, doctor, operational, options, started).map_err(|_| ())?;
    for member in &mut members {
        match member.class {
            Some(Class::HealthState) => {
                member.bytes = b"inspection_owner=serving_health_state\nprocess_phase=serving\ninspection_mode=online\n".to_vec();
            },
            Some(Class::CatalogSummary) => {
                member.bytes = format!("inspection_owner=authenticated_serving_catalog\n{doctor}")
                    .into_bytes();
            },
            Some(Class::ResourceStatus) => {
                member.bytes =
                    format!("inspection_owner=serving_resource_governor\n{doctor}").into_bytes();
            },
            Some(Class::MaintenanceStatus) => {
                member.bytes = b"inspection_owner=maintenance_runtime\ninspection_mode=online\nstatus=not_exported_by_current_diagnostics_contract\n".to_vec();
            },
            Some(Class::ListenerStatus) => {
                member.bytes = b"inspection_owner=listener_runtime\ninspection_mode=online\ncontrol_listener=active\n".to_vec();
            },
            Some(_) | None => {},
        }
    }
    Ok(members)
}

pub(super) struct LiveBundleRequest {
    pub(super) recipients: Vec<String>,
}

impl LiveBundleRequest {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, ()> {
        let text = std::str::from_utf8(bytes).map_err(|_| ())?;
        let mut lines = text.lines();
        if lines.next() != Some("version=1") {
            return Err(());
        }
        let mut recipients = Vec::new();
        for line in lines {
            let recipient = line.strip_prefix("recipient=").ok_or(())?;
            if recipient.is_empty() || recipient.len() > 128 || recipients.len() == 16 {
                return Err(());
            }
            recipients.push(recipient.to_owned());
        }
        AgeRecipients::parse(&recipients)?;
        (!recipients.is_empty())
            .then_some(Self { recipients })
            .ok_or(())
    }

    pub(super) fn encode(recipients: &[String]) -> Result<Vec<u8>, BundleFailure> {
        AgeRecipients::parse(recipients).map_err(|_| BundleFailure::Arguments)?;
        let mut body = String::from("version=1\n");
        for recipient in recipients {
            if recipient.len() > 128 {
                return Err(BundleFailure::Arguments);
            }
            body.push_str("recipient=");
            body.push_str(recipient);
            body.push('\n');
        }
        (body.len() <= 8_192)
            .then_some(body.into_bytes())
            .ok_or(BundleFailure::Arguments)
    }
}

pub(super) fn request_live_bundle(
    path: &Path,
    options: &BundleOptions,
) -> Result<Vec<u8>, BundleFailure> {
    let body = LiveBundleRequest::encode(&options.recipients)?;
    let bearer = read_credential()?;
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let mut stream =
            UnixStream::connect(path).map_err(|_| BundleFailure::InspectionUnavailable)?;
        stream
            .set_read_timeout(Some(options.elapsed_limit))
            .map_err(|_| BundleFailure::InspectionUnavailable)?;
        stream
            .set_write_timeout(Some(options.elapsed_limit))
            .map_err(|_| BundleFailure::InspectionUnavailable)?;
        let request = format!(
            "POST /control/support-bundle HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bearer.as_str(),
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|_| BundleFailure::InspectionUnavailable)?;
        stream
            .write_all(&body)
            .map_err(|_| BundleFailure::InspectionUnavailable)?;
        let mut response = Vec::with_capacity(options.output_limit.saturating_add(512));
        stream
            .take(
                u64::try_from(options.output_limit.saturating_add(8_193))
                    .map_err(|_| BundleFailure::InspectionUnavailable)?,
            )
            .read_to_end(&mut response)
            .map_err(|_| BundleFailure::InspectionUnavailable)?;
        parse_live_response(&response, options.output_limit)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, body, bearer);
        Err(BundleFailure::InspectionUnavailable)
    }
}

fn read_credential() -> Result<Zeroizing<String>, BundleFailure> {
    let input = io::stdin();
    if input.is_terminal() {
        return Err(BundleFailure::Arguments);
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| BundleFailure::AuthenticationRejected)?;
    let trimmed = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024 || trimmed.is_empty() || PresentedCredential::parse(trimmed).is_err()
    {
        return Err(BundleFailure::AuthenticationRejected);
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
}

fn parse_live_response(response: &[u8], limit: usize) -> Result<Vec<u8>, BundleFailure> {
    let separator = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or(BundleFailure::InspectionUnavailable)?;
    let (head, body) = response.split_at(separator + 4);
    if head.starts_with(b"HTTP/1.1 401 ") {
        return Err(BundleFailure::AuthenticationRejected);
    }
    if !head.starts_with(b"HTTP/1.1 200 ") {
        return Err(BundleFailure::InspectionUnavailable);
    }
    let length = std::str::from_utf8(head)
        .map_err(|_| BundleFailure::InspectionUnavailable)?
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .ok_or(BundleFailure::InspectionUnavailable)?
        .parse::<usize>()
        .map_err(|_| BundleFailure::InspectionUnavailable)?;
    if length != body.len() || length > limit {
        return Err(BundleFailure::InspectionUnavailable);
    }
    Ok(body.to_vec())
}
