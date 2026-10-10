use super::*;

pub(super) fn execute_offline(
    options: &Options,
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<(ExitCode, String), DoctorFailure> {
    let inputs = ConfigurationInputs::try_from_sources(
        options.config.as_deref().map(Path::new),
        environment,
        options.overrides.clone(),
    )
    .map_err(|_| DoctorFailure::ConfigurationInvalid)?;
    let effective = resolve(inputs).map_err(|_| DoctorFailure::ConfigurationInvalid)?;
    let paths = BootstrapPaths::with_local_key(
        Path::new(effective.data_directory()),
        Path::new(effective.secrets_directory()),
        effective.local_key_file().as_path(),
        MountQualification::LocalHost,
    )
    .map_err(|_| DoctorFailure::ConfigurationInvalid)?;
    match verify_offline_integrity(&paths, effective.max_registered_tenants()) {
        Ok(report) => {
            let verified = report.is_verified();
            Ok((
                if verified {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(EXIT_DIAGNOSTIC_FAILURE)
                },
                offline_success_report(
                    verified,
                    &report,
                    &effective,
                    options.config.as_deref(),
                    &options.overrides,
                ),
            ))
        },
        Err(failure) => Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            offline_failure_report(failure),
        )),
    }
}

/// Renders only facts established by the exclusive offline inspection path.
/// Storage ownership proves no Positron process currently owns this volume;
/// runtime-only families are therefore explicitly unavailable, never inferred
/// from stale files or placeholder values.
pub(super) fn offline_success_report(
    verified: bool,
    inspection: &OfflineIntegrityVerification,
    effective: &positron_config::EffectiveConfiguration,
    configuration: Option<&Path>,
    overrides: &[(String, String)],
) -> String {
    let facts = inspection.facts();
    let pressure = match facts.disk_pressure() {
        OfflineDiskPressure::Healthy => "healthy",
        OfflineDiskPressure::Soft => "soft",
        OfflineDiskPressure::Hard => "hard",
    };
    let outcome = inspection.aggregate_outcome();
    let (status, finding, severity) = offline_outcome_fields(outcome);
    let continuation = inspection.continuation().map(|value| hex(value.encoded()));
    let safe_command = continuation.as_ref().map_or_else(
        || {
            if verified {
                "none".to_owned()
            } else {
                "positron verify --offline".to_owned()
            }
        },
        |value| offline_verify_command(Some(value), configuration, overrides),
    );
    let mut report = format!(
        "report_version=1\nmode=offline\nstatus={}\naggregate_integrity_outcome={}\nfinding_code=DOCTOR_INTEGRITY_{}\nseverity={}\nevidence_scope=offline_integrity_reports\nsafe_command={}\nreport_count={}\nverified_scope_count={}\nquarantined_scope_count={}\nfenced_scope_count={}\nincomplete_scope_count={}\n",
        status,
        offline_outcome_label(outcome),
        finding,
        severity,
        safe_command,
        inspection.reports().len(),
        facts.verified_scope_count(),
        inspection
            .aggregate_evidence()
            .iter()
            .filter(|evidence| {
                evidence.outcome() == positron_kernel::IntegrityVerificationOutcome::Quarantined
            })
            .count(),
        facts.fenced_scope_count(),
        facts.incomplete_scope_count(),
    );
    if let Some(continuation) = continuation {
        report.push_str(&format!("aggregate_continuation={continuation}\n"));
    }
    report.push_str(
        "finding_code=DOCTOR_CONFIGURATION_RESOLVED\nseverity=info\nevidence_scope=effective_configuration\nconfiguration_contract=valid\nconfiguration_effective_redacted_begin=true\n",
    );
    report.push_str(&effective.redacted_effective());
    report.push_str("\nconfiguration_effective_redacted_end=true\nsafe_command=none\n");
    report.push_str("storage_ownership=exclusive\nstorage_capabilities=not_probed_read_only\n");
    report.push_str(&format!(
        "finding_code=DOCTOR_STORAGE_CAPACITY_OBSERVED\nseverity=info\nevidence_scope=primary_data_volume\nusable_disk_bytes={}\ndisk_pressure={pressure}\nsafe_command=none\n",
        facts.usable_disk_bytes(),
    ));
    report.push_str(&format!(
        "finding_code=DOCTOR_KEY_ENVELOPES_VERIFIED\nseverity={}\nevidence_scope=authenticated_tenant_envelopes\nverified_envelope_count={}\nsafe_command={}\n",
        if verified { "info" } else { "error" },
        facts.verified_envelope_count(),
        if verified { "none" } else { "positron verify --offline" },
    ));
    report.push_str(&format!(
        "finding_code=DOCTOR_CATALOG_FRONTIERS_VERIFIED\nseverity={}\nevidence_scope=authenticated_catalog_snapshot\ncatalog_generation={}\nregistered_tenant_count={}\nreachable_scope_count={}\nquarantine_finding_count={}\nsafe_command={}\n",
        if verified { "info" } else { "error" },
        facts.catalog_generation(),
        facts.registered_tenant_count(),
        facts.reachable_scope_count(),
        facts.quarantine_finding_count(),
        if verified { "none" } else { "positron verify --offline" },
    ));
    let backup = facts.backup_repository().label();
    report.push_str(&format!(
        "finding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED\nseverity=warning\nevidence_scope=authenticated_catalog_backup_binding\nbackup_repository={backup}\nsafe_command=configure_backup_repository\n"
    ));
    report.push_str(
        "finding_code=DOCTOR_GOVERNOR_RUNTIME_UNAVAILABLE_OFFLINE\nseverity=info\nevidence_scope=runtime_resource_governor\nruntime_state=not_observable_offline\nsafe_command=start_positron_for_live_governor_status\n",
    );
    for (code, command) in [
        (
            "DOCTOR_MAINTENANCE_RUNTIME_UNAVAILABLE_OFFLINE",
            "start_positron_for_maintenance_status",
        ),
        (
            "DOCTOR_OPERATIONS_LEASES_UNAVAILABLE_OFFLINE",
            "start_positron_for_operations_status",
        ),
        (
            "DOCTOR_LISTENERS_UNAVAILABLE_OFFLINE",
            "start_positron_for_listener_status",
        ),
        (
            "DOCTOR_HEALTH_UNAVAILABLE_OFFLINE",
            "start_positron_for_process_health",
        ),
    ] {
        report.push_str(&format!(
            "finding_code={code}\nseverity=info\nevidence_scope=exclusive_primary_data_volume_ownership\nruntime_state=not_observable_offline\nsafe_command={command}\n"
        ));
    }
    report
}

pub(super) const fn offline_outcome_label(
    outcome: OfflineIntegrityAggregateOutcome,
) -> &'static str {
    match outcome {
        OfflineIntegrityAggregateOutcome::Verified => "verified",
        OfflineIntegrityAggregateOutcome::Incomplete => "incomplete",
        OfflineIntegrityAggregateOutcome::Quarantined => "quarantined",
        OfflineIntegrityAggregateOutcome::Fenced => "fenced",
    }
}

pub(super) const fn offline_outcome_fields(
    outcome: OfflineIntegrityAggregateOutcome,
) -> (&'static str, &'static str, &'static str) {
    match outcome {
        OfflineIntegrityAggregateOutcome::Verified => ("healthy", "VERIFIED", "info"),
        OfflineIntegrityAggregateOutcome::Incomplete => ("incomplete", "INCOMPLETE", "warning"),
        OfflineIntegrityAggregateOutcome::Quarantined => ("degraded", "QUARANTINED", "warning"),
        OfflineIntegrityAggregateOutcome::Fenced => ("fenced", "FENCED", "error"),
    }
}

pub(super) fn offline_verify_command(
    continuation: Option<&str>,
    configuration: Option<&Path>,
    overrides: &[(String, String)],
) -> String {
    let Some(continuation) = continuation else {
        return "positron verify --offline".to_owned();
    };
    let mut command = String::from("positron verify --offline");
    if let Some(configuration) = configuration {
        let Some(configuration) = configuration.to_str().and_then(shell_quote) else {
            return "inspect_effective_configuration_before_resuming".to_owned();
        };
        command.push_str(" --config ");
        command.push_str(&configuration);
    }
    for (key, value) in overrides {
        let Some(override_value) = shell_quote(&format!("{key}={value}")) else {
            return "inspect_effective_configuration_before_resuming".to_owned();
        };
        command.push_str(" --set ");
        command.push_str(&override_value);
    }
    let Some(continuation) = shell_quote(continuation) else {
        return "inspect_effective_configuration_before_resuming".to_owned();
    };
    command.push_str(" --continuation ");
    command.push_str(&continuation);
    command
}

fn shell_quote(value: &str) -> Option<String> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    Some(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn offline_failure_report(failure: OfflineIntegrityFailure) -> String {
    format!(
        "report_version=1\nmode=offline\nstatus={}\nfinding_code={}\nseverity=error\nevidence_scope=primary_data_volume\nsafe_command={}\nreport_count=0\n",
        status(failure),
        code(failure),
        safe_command(failure)
    )
}

fn status(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
        OfflineIntegrityFailure::OwnershipLocked => "storage_locked",
        OfflineIntegrityFailure::BootstrapUnavailable => "bootstrap_unavailable",
        OfflineIntegrityFailure::KeyUnavailable => "key_unavailable",
        OfflineIntegrityFailure::CatalogUnavailable => "catalog_busy",
        OfflineIntegrityFailure::CorruptState => "fenced",
        OfflineIntegrityFailure::CapacityUnavailable => "capacity_unavailable",
        OfflineIntegrityFailure::StorageUnavailable => "storage_unavailable",
    }
}
fn code(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
        OfflineIntegrityFailure::OwnershipLocked => "DOCTOR_STORAGE_LOCKED",
        OfflineIntegrityFailure::BootstrapUnavailable => "DOCTOR_BOOTSTRAP_UNAVAILABLE",
        OfflineIntegrityFailure::KeyUnavailable => "DOCTOR_KEY_UNAVAILABLE",
        OfflineIntegrityFailure::CatalogUnavailable => "DOCTOR_CATALOG_BUSY",
        OfflineIntegrityFailure::CorruptState => "DOCTOR_INTEGRITY_FENCED",
        OfflineIntegrityFailure::CapacityUnavailable => "DOCTOR_CAPACITY_UNAVAILABLE",
        OfflineIntegrityFailure::StorageUnavailable => "DOCTOR_STORAGE_UNAVAILABLE",
    }
}
const fn safe_command(failure: OfflineIntegrityFailure) -> &'static str {
    match failure {
        OfflineIntegrityFailure::OwnershipLocked => "stop_positron_before_offline_doctor",
        _ => "inspect_storage_without_mutation",
    }
}
