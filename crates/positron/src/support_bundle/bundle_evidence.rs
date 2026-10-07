use super::*;

pub(super) fn offline_operational_status(report: &str) -> String {
    let finding = report
        .lines()
        .find_map(|line| line.strip_prefix("finding_code="))
        .map_or("DOCTOR_OFFLINE_INSPECTION_UNAVAILABLE", |finding| finding);
    format!(
        "inspection_mode=offline\noperations_runtime_state=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nintegrity_finding={finding}\n"
    )
}

/// Renders the common bundle families from a previously opened kernel-owned
/// crash inspection capability. Serving callers must use the capability held
/// by their initialized instance; re-acquiring offline volume ownership while
/// the process is serving is intentionally rejected.
pub(crate) fn canonical_members_with_crash(
    effective: &positron_config::EffectiveConfiguration,
    doctor: &str,
    operational: &str,
    options: &BundleOptions,
    started: Instant,
    crash: positron_kernel::CrashReadout,
) -> Result<Vec<BundleMember>, BundleFailure> {
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    let pseudonyms = privacy::Pseudonymizer::new();
    let data_directory = match options.identifier_retention {
        IdentifierRetention::Ephemeral => pseudonyms
            .pseudonymize(effective.data_directory())
            .map_err(|_| BundleFailure::OutputUnavailable)?,
        IdentifierRetention::DataDirectory => effective.data_directory().to_owned(),
    };
    let configuration = effective.redacted_for_support_bundle(|class, value| match class {
        positron_config::SupportBundleIdentifierClass::DataDirectory
            if options.identifier_retention == IdentifierRetention::DataDirectory =>
        {
            Ok(value.to_owned())
        },
        _ => pseudonyms
            .pseudonymize(value)
            .map_err(|_| BundleFailure::OutputUnavailable),
    })?;
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    let metadata = std::fs::metadata(effective.data_directory()).ok();
    let data_directory_metadata_bytes = metadata.map_or(0, |value| value.len());
    let config_digest =
        hex(configuration.as_bytes()).map_err(|_| BundleFailure::OutputUnavailable)?;
    let health = format!(
        "inspection_owner=offline_doctor\nhealth_runtime_state=not_observable_offline\nlatest_finding={}\n",
        finding_code(doctor),
    );
    let catalog =
        format!("inspection_owner=offline_doctor\nconfiguration_digest={config_digest}\n{doctor}");
    let resource = format!("inspection_owner=offline_doctor\n{doctor}");
    let maintenance = "inspection_owner=maintenance_runtime\navailability=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nsafe_command=start_positron_for_maintenance_status\n";
    let listeners = "inspection_owner=listener_runtime\navailability=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nsafe_command=start_positron_for_listener_status\n";
    let backup = report_field(doctor, "backup_repository").map_or_else(
        || "inspection_owner=authenticated_catalog_backup_binding\navailability=not_observable_offline\nevidence_scope=exclusive_primary_data_volume_ownership\nsafe_command=inspect_backup_configuration_when_available\n".to_owned(),
        |value| format!("inspection_owner=authenticated_catalog_backup_binding\nbackup_repository={value}\nevidence_scope=authenticated_catalog_snapshot\nsafe_command=configure_backup_repository\n"),
    );
    Ok(vec![
        BundleMember::effective_configuration(configuration.as_bytes()),
        BundleMember::compatibility_manifest(
            compatibility_manifest_evidence()
                .map_err(|_| BundleFailure::OutputUnavailable)?
                .as_bytes(),
        ),
        BundleMember::product_identity(
            product_identity_evidence()
                .map_err(|_| BundleFailure::OutputUnavailable)?
                .as_bytes(),
        ),
        BundleMember::health_state(health.as_bytes()),
        BundleMember::operational_telemetry(operational.as_bytes()),
        BundleMember::operational_logs_with_omission(b"inspection_owner=operational_log_runtime\navailability=not_persisted\n", "operational_log_owner_unavailable"),
        BundleMember::catalog_summary(catalog.as_bytes()),
        BundleMember::resource_status(resource.as_bytes()),
        BundleMember::maintenance_status(maintenance.as_bytes()),
        BundleMember::listener_status(listeners.as_bytes()),
        BundleMember::backup_repository_status(backup.as_bytes()),
        BundleMember::environment(format!("os={}\narch={}\ndata_directory_identity={}\ndata_directory_metadata_bytes={data_directory_metadata_bytes}\n", std::env::consts::OS, std::env::consts::ARCH, data_directory).as_bytes()),
        BundleMember::doctor_report(doctor.as_bytes()),
        BundleMember::sanitized_crash_records_with_omissions(crash.render().as_bytes(), crash.omissions()),
    ])
}

const COMPATIBILITY_INPUTS_SCOPE: &str = "Cargo.lock,Cargo.toml,crates/positron/Cargo.toml,api/positron/v1/positron.proto,api/positron/v1/http.json,configuration/schema.json";
pub(crate) const COMPATIBILITY_INPUTS: [(&str, &[u8]); 6] = [
    ("Cargo.lock", include_bytes!("../../../../Cargo.lock")),
    ("Cargo.toml", include_bytes!("../../../../Cargo.toml")),
    (
        "crates/positron/Cargo.toml",
        include_bytes!("../../Cargo.toml"),
    ),
    (
        "api/positron/v1/positron.proto",
        include_bytes!("../../../../api/positron/v1/positron.proto"),
    ),
    (
        "api/positron/v1/http.json",
        include_bytes!("../../../../api/positron/v1/http.json"),
    ),
    (
        "configuration/schema.json",
        include_bytes!("../../../../configuration/schema.json"),
    ),
];

/// Locally reproducible compatibility evidence for exactly the declared six
/// inputs. It is not a complete source-tree or release-build identity.
pub(crate) fn compatibility_manifest_evidence() -> Result<String, ()> {
    let schema_digest = positron_api::generated::SchemaDigest::canonical().as_str();
    let configuration_schema_digest = hex(include_bytes!("../../../../configuration/schema.json"))?;
    let compatibility_inputs_sha256 = compatibility_inputs_sha256()?;
    Ok(format!(
        "compatibility_manifest_version=1\nproduct=positron\nproduct_version={}\napi_package=positron.v1\napi_schema_digest={schema_digest}\nconfiguration_schema_digest={configuration_schema_digest}\nstorage_catalog_readable_format_epochs={},{}\nstorage_catalog_writable_format_epochs={},{}\nquery_contract=not_shipped\nreceiver_contract=not_shipped\ncrd_contract=not_shipped\noperator_contract=not_shipped\nbackup_contract=not_shipped\nmigration_graph=not_shipped\ncompatibility_inputs_sha256={compatibility_inputs_sha256}\ncompatibility_inputs_scope={COMPATIBILITY_INPUTS_SCOPE}\nsource_build_state=not_captured\nsource_build_evidence_scope=unavailable\nsource_build_evidence_owner=release_pipeline\n",
        env!("CARGO_PKG_VERSION"),
        positron_kernel::FormatEpoch::CATALOG_V1.value(),
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
        positron_kernel::FormatEpoch::CATALOG_V1.value(),
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
    ))
}

/// Product identity states the unavailable source-build provenance owner
/// instead of inferring it from compatibility inputs.
pub(crate) fn product_identity_evidence() -> Result<String, ()> {
    let compatibility_inputs_sha256 = compatibility_inputs_sha256()?;
    Ok(format!(
        "product=positron\nproduct_version={}\nproduct_identity_source=workspace_package\napi_package=positron.v1\nschema_digest={}\ncatalog_writable_format_epochs={},{}\ncompatibility_inputs_sha256={compatibility_inputs_sha256}\ncompatibility_inputs_scope={COMPATIBILITY_INPUTS_SCOPE}\nsource_build_state=not_captured\nsource_build_evidence_scope=unavailable\nsource_build_evidence_owner=release_pipeline\n",
        env!("CARGO_PKG_VERSION"),
        positron_api::generated::SchemaDigest::canonical().as_str(),
        positron_kernel::FormatEpoch::CATALOG_V1.value(),
        positron_kernel::FormatEpoch::CATALOG_V2.value(),
    ))
}

fn compatibility_inputs_sha256() -> Result<String, ()> {
    let mut digest = Sha256::new();
    for (scope, bytes) in COMPATIBILITY_INPUTS {
        digest.update(scope.as_bytes());
        digest.update([0]);
        digest.update(u64::try_from(bytes.len()).map_err(|_| ())?.to_be_bytes());
        digest.update(bytes);
    }
    encode_bytes(&digest.finalize())
}

fn finding_code(report: &str) -> &str {
    report
        .lines()
        .find_map(|line| line.strip_prefix("finding_code="))
        .unwrap_or("DOCTOR_REPORT_UNAVAILABLE")
}

fn report_field<'a>(report: &'a str, key: &str) -> Option<&'a str> {
    report.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
    })
}

/// A signed bundle already holds the sole Storage Kernel authority through
/// `InstanceBootstrap::reopen`. Re-acquiring it for the CLI's standalone
/// offline verifier would manufacture a storage-lock failure, so this report
/// uses only the already-opened authenticated bootstrap, Catalog, and
/// governor authorities.
pub(super) fn owned_bundle_doctor_report(
    catalog_generation: u64,
    backup_repository: positron_runtime::BackupRepositoryInspection,
    resources: ResourceSnapshot,
) -> String {
    let pressure = match resources.disk_pressure() {
        DiskPressureState::Healthy => "healthy",
        DiskPressureState::SoftPressure => "soft",
        DiskPressureState::HardPressure => "hard",
    };
    let mut report = format!(
        "report_version=1\nmode=offline_owned_bundle\nstatus=inspection_partial\nfinding_code=DOCTOR_BUNDLE_OWNER_VERIFIED\nseverity={}\nevidence_scope=exclusive_primary_data_volume_ownership\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nsafe_command={}\n",
        "info", "verified", "verified", catalog_generation, "none",
    );
    report.push_str("finding_code=DOCTOR_CONFIGURATION_RESOLVED\nseverity=info\nevidence_scope=effective_configuration\nsafe_command=none\n");
    report.push_str("finding_code=DOCTOR_INTEGRITY_FRONTIERS_UNAVAILABLE_OWNED_BUNDLE\nseverity=info\nevidence_scope=offline_integrity_verifier\ninspection_state=not_run_while_bundle_ownership_is_held\nsafe_command=positron_doctor_offline_after_bundle\n");
    report.push_str(&format!("finding_code=DOCTOR_STORAGE_CAPACITY_OBSERVED\nseverity=info\nevidence_scope=temporary_offline_resource_authority\nusable_disk_bytes={}\ndisk_pressure={pressure}\nsafe_command=none\n", resources.usable_disk_bytes()));
    report.push_str("finding_code=DOCTOR_GOVERNOR_RUNTIME_UNAVAILABLE_OFFLINE\nseverity=info\nevidence_scope=runtime_resource_governor\nruntime_state=not_observable_offline\nsafe_command=start_positron_for_live_governor_status\n");
    for (code, owner, command) in [
        (
            "DOCTOR_MAINTENANCE_RUNTIME_UNAVAILABLE_OFFLINE",
            "maintenance_runtime",
            "start_positron_for_maintenance_status",
        ),
        (
            "DOCTOR_OPERATIONS_LEASES_UNAVAILABLE_OFFLINE",
            "durable_operation_runtime",
            "start_positron_for_operations_status",
        ),
        (
            "DOCTOR_LISTENERS_UNAVAILABLE_OFFLINE",
            "listener_runtime",
            "start_positron_for_listener_status",
        ),
        (
            "DOCTOR_HEALTH_UNAVAILABLE_OFFLINE",
            "process_health_runtime",
            "start_positron_for_process_health",
        ),
    ] {
        report.push_str(&format!("finding_code={code}\nseverity=info\nevidence_scope={owner}\nruntime_state=not_observable_offline\nsafe_command={command}\n"));
    }
    let backup = backup_repository.label();
    report.push_str(&format!("finding_code=DOCTOR_BACKUP_REPOSITORY_NOT_CONFIGURED\nseverity=warning\nevidence_scope=authenticated_catalog_backup_binding\nbackup_repository={backup}\nsafe_command=configure_backup_repository\n"));
    report
}

pub(super) const fn key_unavailable_doctor_report() -> &'static str {
    "report_version=1\nmode=offline\nstatus=key_unavailable\nfinding_code=DOCTOR_KEY_UNAVAILABLE\nseverity=error\nevidence_scope=primary_data_volume\n"
}

pub(crate) fn diagnostics_claim(output_limit: usize) -> Result<WorkClaim, BundleFailure> {
    let bounded_bytes = u64::try_from(output_limit)
        .ok()
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(BundleFailure::Arguments)?;
    WorkClaim::system_diagnostics(ResourceAmounts::new([
        bounded_bytes,
        0,
        1,
        0,
        0,
        0,
        0,
        1,
        1,
        1,
        0,
    ]))
    .map_err(|_| BundleFailure::Arguments)
}
