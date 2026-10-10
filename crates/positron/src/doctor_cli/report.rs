//! Closed, bounded Doctor report rendering from authenticated inspection facts.
use super::*;

pub(super) fn render_status(
    report: &serde_json::Value,
) -> Result<(ExitCode, String), DoctorFailure> {
    let report = report
        .as_object()
        .ok_or(DoctorFailure::EndpointUnavailable)?;
    let phase = required_string(report, "phase")?;
    if phase == "fenced" {
        return fenced_control_report(report);
    }
    let degraded = required_bool(report, "integrity_degraded")?;
    let effective_configuration_digest = required_string(report, "effective_digest")?;
    let desired_configuration_digest = required_string(report, "desired_digest")?;
    let configuration_drift_disposition = required_string(report, "drift_disposition")?;
    let configuration_pending_restart = required_bool(report, "pending_restart")?;
    let maintenance = required_object(report, "maintenance")?;
    let queued = required_u64(maintenance, "queued")?;
    let reservations = required_u64(maintenance, "outstanding_reservations")?;
    let clock_uncertain = required_bool(maintenance, "clock_uncertain")?;
    let stalled = required_u64(maintenance, "running_no_durable_progress_slo_breaches")?;
    let progress_unknown = required_u64(maintenance, "running_no_durable_progress_slo_unknown")?;
    let checkpointed_tasks = required_u64(maintenance, "checkpointed_tasks")?;
    let paused_tasks = required_u64(maintenance, "paused_tasks")?;
    let conflicted_tasks = required_u64(maintenance, "conflicted_tasks")?;
    let doctor = required_object(report, "doctor")?;
    let key_custody = required_string(doctor, "key_custody")?;
    let catalog_bootstrap = required_string(doctor, "catalog_bootstrap")?;
    let catalog_generation = required_u64(doctor, "catalog_generation")?;
    let backup_repository = required_string(doctor, "backup_repository")?;
    let durable_operations = required_u64(doctor, "durable_operations")?;
    let active_durable_operations = required_u64(doctor, "active_durable_operations")?;
    let snapshot_leases = required_u64(doctor, "snapshot_leases")?;
    let listeners = required_object(doctor, "listener_topology")?;
    let required_families = doctor
        .get("required_families")
        .and_then(serde_json::Value::as_object);
    let storage = family(required_families, "storage");
    let catalog = family(required_families, "catalog_integrity");
    let governor = family(required_families, "resource_governor");
    let listener_security = family(required_families, "listener_security");
    let backup = family(required_families, "backup_verification");
    let health_state = family(required_families, "health_state");
    let configuration = family(required_families, "configuration");
    let required_family_complete = [
        (
            storage,
            &[
                "ownership",
                "capabilities",
                "usable_disk_bytes",
                "disk_pressure",
            ][..],
        ),
        (
            catalog,
            &[
                "audit_chain",
                "frontier",
                "manifest_objects",
                "quarantine_findings",
                "scrub",
            ][..],
        ),
        (governor, &["queues", "fairness", "recovery_reserve"][..]),
        (
            listener_security,
            &["profiles", "certificates", "proxy_trust", "drain"][..],
        ),
        (
            backup,
            &["manifest_verification", "purge_compatibility"][..],
        ),
        (health_state, &["derivation"][..]),
        (
            configuration,
            &["contract", "effective_sources", "key_custody"][..],
        ),
    ]
    .into_iter()
    .all(|(family, fields)| {
        family_disposition(family) == "observed"
            && fields.iter().all(|key| {
                !matches!(
                    family_value(family, key).as_str(),
                    "missing" | "unavailable" | "not_shipped" | "unknown"
                )
            })
    });
    let family_degraded = [
        (storage, "disk_pressure"),
        (catalog, "audit_chain"),
        (governor, "fairness"),
        (listener_security, "profiles"),
        (listener_security, "certificates"),
        (listener_security, "drain"),
        (backup, "manifest_verification"),
        (backup, "purge_compatibility"),
        (configuration, "contract"),
    ]
    .into_iter()
    .any(|(family, key)| {
        matches!(
            family_value(family, key).as_str(),
            "soft"
                | "hard"
                | "degraded"
                | "breached"
                | "incomplete"
                | "not_loaded"
                | "draining"
                | "not_serving"
                | "incompatible"
                | "invalid"
        )
    });
    let topology_active = [
        "control",
        "operations",
        "api",
        "otlp_grpc",
        "otlp_http",
        "loki_push",
    ]
    .into_iter()
    .try_fold(true, |active, role| {
        required_bool(listeners, role).map(|bound| active && bound)
    })?;
    let evidence = format!(
        "evidence_scope=authenticated_operations_status\nprocess_phase={phase}\nintegrity_degraded={degraded}\neffective_configuration_digest={effective_configuration_digest}\ndesired_configuration_digest={desired_configuration_digest}\nconfiguration_drift_disposition={configuration_drift_disposition}\nconfiguration_pending_restart={configuration_pending_restart}\nmaintenance_queued={queued}\nmaintenance_clock_uncertain={clock_uncertain}\nmaintenance_running_no_durable_progress_slo_breaches={stalled}\nmaintenance_running_no_durable_progress_slo_unknown={progress_unknown}\nmaintenance_checkpointed_tasks={checkpointed_tasks}\nmaintenance_paused_tasks={paused_tasks}\nmaintenance_conflicted_tasks={conflicted_tasks}\ndurable_operations={durable_operations}\nactive_durable_operations={active_durable_operations}\nsnapshot_leases={snapshot_leases}\noutstanding_reservations={reservations}\nkey_custody={key_custody}\ncatalog_bootstrap={catalog_bootstrap}\ncatalog_generation={catalog_generation}\nlistener_topology={}\nbackup_repository={backup_repository}\ncatalog_integrity_disposition={}\ncatalog_audit_chain={}\ncatalog_frontier={}\ncatalog_manifest_objects={}\ncatalog_reachable_ledger_scopes={}\ncatalog_quarantine_findings={}\ncatalog_scrub={}\ncatalog_scrub_tasks={}\ncatalog_scrub_checkpoints={}\nresource_governor_disposition={}\nresource_governor_queues={}\nresource_governor_fairness={}\nresource_governor_recovery_reserve={}\nlistener_security_disposition={}\nlistener_profiles={}\nlistener_certificates={}\nlistener_proxy_trust={}\nlistener_drain={}\nbackup_verification_disposition={}\nbackup_manifest_verification={}\nbackup_purge_compatibility={}\nhealth_state_disposition={}\nhealth_derivation={}\nconfiguration_disposition={}\nconfiguration_contract={}\nconfiguration_effective_sources={}\nconfiguration_key_custody={}\nrequired_diagnostic_families_complete={required_family_complete}\n",
        if topology_active {
            "active"
        } else {
            "incomplete"
        },
        family_disposition(catalog),
        family_value(catalog, "audit_chain"),
        family_value(catalog, "frontier"),
        family_value(catalog, "manifest_objects"),
        family_value(catalog, "reachable_ledger_scopes"),
        family_value(catalog, "quarantine_findings"),
        family_value(catalog, "scrub"),
        family_value(catalog, "scrub_tasks"),
        family_value(catalog, "scrub_checkpoints"),
        family_disposition(governor),
        family_value(governor, "queues"),
        family_value(governor, "fairness"),
        family_value(governor, "recovery_reserve"),
        family_disposition(listener_security),
        family_value(listener_security, "profiles"),
        family_value(listener_security, "certificates"),
        family_value(listener_security, "proxy_trust"),
        family_value(listener_security, "drain"),
        family_disposition(backup),
        family_value(backup, "manifest_verification"),
        family_value(backup, "purge_compatibility"),
        family_disposition(health_state),
        family_value(health_state, "derivation"),
        family_disposition(configuration),
        family_value(configuration, "contract"),
        family_value(configuration, "effective_sources"),
        family_value(configuration, "key_custody"),
    );
    let evidence = format!(
        "{evidence}storage_disposition={}\nstorage_ownership={}\nstorage_capabilities={}\nstorage_usable_disk_bytes={}\nstorage_disk_pressure={}\nresource_governor_recovery_reserve_memory_bytes={}\n",
        family_disposition(storage),
        family_value(storage, "ownership"),
        family_value(storage, "capabilities"),
        family_value(storage, "usable_disk_bytes"),
        family_value(storage, "disk_pressure"),
        family_value(governor, "recovery_reserve_memory_bytes")
    );
    if key_custody != "verified"
        || catalog_bootstrap != "verified"
        || !topology_active
        || !required_family_complete
    {
        return Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            format!(
                "report_version=1\nmode=online\nstatus=inspection_incomplete\nfinding_code=DOCTOR_RUNTIME_FACTS_INCOMPLETE\nseverity=warning\n{evidence}safe_command=inspect_runtime_state\n"
            ),
        ));
    }
    if effective_configuration_digest != desired_configuration_digest
        || configuration_drift_disposition != "none"
        || configuration_pending_restart
    {
        return Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            format!(
                "report_version=1\nmode=online\nstatus=degraded\nfinding_code=DOCTOR_CONFIGURATION_DEGRADED\nseverity=warning\n{evidence}safe_command=inspect_configuration_status\n"
            ),
        ));
    }
    if backup_repository == "not_configured" {
        return Ok((
            ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
            format!(
                "report_version=1\nmode=online\nstatus=degraded\nfinding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED\nseverity=warning\n{evidence}safe_command=configure_backup_repository\n"
            ),
        ));
    }
    if phase == "serving"
        && !degraded
        && !family_degraded
        && backup_repository == "configured"
        && !clock_uncertain
        && stalled == 0
        && progress_unknown == 0
    {
        return Ok((
            ExitCode::SUCCESS,
            format!(
                "report_version=1\nmode=online\nstatus=healthy\nfinding_code=DOCTOR_RUNTIME_VERIFIED\nseverity=info\n{evidence}safe_command=none\n"
            ),
        ));
    }
    Ok((
        ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
        format!(
            "report_version=1\nmode=online\nstatus=degraded\nfinding_code=DOCTOR_RUNTIME_DEGRADED\nseverity=error\n{evidence}safe_command=inspect_runtime_state\n"
        ),
    ))
}

fn family<'a>(
    families: Option<&'a serde_json::Map<String, serde_json::Value>>,
    name: &str,
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    families
        .and_then(|families| families.get(name))
        .and_then(serde_json::Value::as_object)
}

fn family_disposition(family: Option<&serde_json::Map<String, serde_json::Value>>) -> &str {
    family
        .and_then(|family| family.get("disposition"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            matches!(
                *value,
                "observed" | "partial" | "degraded" | "unavailable" | "not_shipped"
            )
        })
        .unwrap_or("missing")
}

fn family_value(family: Option<&serde_json::Map<String, serde_json::Value>>, key: &str) -> String {
    match family.and_then(|family| family.get(key)) {
        Some(serde_json::Value::String(value))
            if match key {
                "ownership" => matches!(value.as_str(), "held" | "unavailable"),
                "capabilities" => matches!(value.as_str(), "not_probed_read_only" | "unavailable"),
                "disk_pressure" => {
                    matches!(value.as_str(), "healthy" | "soft" | "hard" | "unavailable")
                },
                "audit_chain" => matches!(value.as_str(), "verified" | "degraded" | "unavailable"),
                "scrub" => matches!(
                    value.as_str(),
                    "observed" | "not_running" | "running" | "unavailable"
                ),
                "queues" => matches!(value.as_str(), "observed" | "unavailable"),
                "fairness" => matches!(value.as_str(), "within_bound" | "breached" | "unknown"),
                "recovery_reserve" => {
                    matches!(value.as_str(), "configured" | "available" | "unavailable")
                },
                "profiles" => matches!(value.as_str(), "active" | "incomplete" | "unavailable"),
                "certificates" => matches!(
                    value.as_str(),
                    "loaded" | "loaded_or_not_required" | "not_loaded" | "unavailable"
                ),
                "proxy_trust" => matches!(
                    value.as_str(),
                    "configured" | "not_configured" | "unavailable"
                ),
                "drain" => matches!(
                    value.as_str(),
                    "accepting" | "draining" | "not_serving" | "unavailable"
                ),
                "manifest_verification" => matches!(
                    value.as_str(),
                    "verified" | "incomplete" | "not_shipped" | "unavailable"
                ),
                "purge_compatibility" => matches!(
                    value.as_str(),
                    "compatible" | "incompatible" | "not_shipped" | "unavailable"
                ),
                "derivation" => matches!(
                    value.as_str(),
                    "serving_ready_live"
                        | "serving_integrity_degraded"
                        | "fenced_not_ready_live"
                        | "not_ready_live"
                        | "unavailable"
                ),
                "contract" => matches!(value.as_str(), "valid" | "invalid" | "unavailable"),
                "effective_sources" => matches!(value.as_str(), "redacted" | "unavailable"),
                "key_custody" => matches!(value.as_str(), "verified" | "unavailable"),
                _ => false,
            } =>
        {
            value.clone()
        },
        Some(serde_json::Value::Number(value))
            if value.is_u64()
                && matches!(
                    key,
                    "usable_disk_bytes"
                        | "recovery_reserve_memory_bytes"
                        | "frontier"
                        | "manifest_objects"
                        | "reachable_ledger_scopes"
                        | "quarantine_findings"
                        | "scrub_tasks"
                        | "scrub_checkpoints"
                ) =>
        {
            value.to_string()
        },
        _ => "missing".to_owned(),
    }
}

fn required_object<'a>(
    value: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_object)
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn required_string<'a>(
    value: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| match key {
            "phase" => matches!(
                *value,
                "starting" | "recovering" | "serving" | "draining" | "fenced" | "stopping"
            ),
            "effective_digest" | "desired_digest" => {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            },
            "drift_disposition" => matches!(*value, "none" | "reconcile" | "fence"),
            "key_custody" | "catalog_bootstrap" => matches!(*value, "verified" | "unavailable"),
            "backup_repository" => {
                matches!(*value, "configured" | "not_configured" | "unavailable")
            },
            "reason" => matches!(
                *value,
                "ambiguous_integrity"
                    | "unreliable_storage_ownership"
                    | "instance_identity_mismatch"
                    | "key_envelope_mismatch"
                    | "durability_frontier_ambiguity"
            ),
            _ => false,
        })
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn required_bool(
    value: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn required_u64(
    value: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, DoctorFailure> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or(DoctorFailure::EndpointUnavailable)
}

fn fenced_control_report(
    report: &serde_json::Map<String, serde_json::Value>,
) -> Result<(ExitCode, String), DoctorFailure> {
    let doctor = required_object(report, "doctor")?;
    let key_custody = required_string(doctor, "key_custody")?;
    let catalog_bootstrap = required_string(doctor, "catalog_bootstrap")?;
    let catalog_generation = required_u64(doctor, "catalog_generation")?;
    let backup_repository = required_string(doctor, "backup_repository")?;
    let listeners = required_object(doctor, "listener_topology")?;
    let control = required_bool(listeners, "control")?;
    let operations = required_bool(listeners, "operations")?;
    let data_retired = ["api", "otlp_grpc", "otlp_http", "loki_push"]
        .into_iter()
        .try_fold(true, |retired, role| {
            required_bool(listeners, role).map(|bound| retired && !bound)
        })?;
    let reason = required_string(report, "reason")?;
    Ok((
        ExitCode::from(EXIT_DIAGNOSTIC_FAILURE),
        format!(
            "report_version=1\nmode=online\nstatus=fenced\nfinding_code=DOCTOR_RUNTIME_FENCED\nseverity=error\nevidence_scope=owner_local_control\nprocess_phase=fenced\nfence_reason={reason}\nkey_custody={key_custody}\ncatalog_bootstrap={catalog_bootstrap}\ncatalog_generation={catalog_generation}\nbackup_repository={backup_repository}\ncontrol_listener_active={control}\noperations_listener_active={operations}\ndata_listeners_retired={data_retired}\nsafe_command=inspect_integrity_recovery\n"
        ),
    ))
}
