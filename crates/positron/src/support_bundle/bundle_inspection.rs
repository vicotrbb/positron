use super::*;

pub(super) fn authenticated_inspection<T>(
    paths: &BootstrapPaths,
    max_registered_tenants: u16,
    output_limit: usize,
    collect: impl FnOnce(
        positron_kernel::ExportManifestSigner,
        String,
        String,
        positron_kernel::CrashRecordStore,
    ) -> Result<T, BundleFailure>,
) -> Result<T, BundleFailure> {
    let input = io::stdin();
    if input.is_terminal() {
        return Err(BundleFailure::Arguments);
    }
    let mut credential = Zeroizing::new(String::new());
    input
        .take(1025)
        .read_to_string(&mut credential)
        .map_err(|_| BundleFailure::AuthenticationRejected)?;
    let bearer = credential.trim_end_matches(['\r', '\n']);
    if credential.len() > 1024 || bearer.is_empty() {
        return Err(BundleFailure::Arguments);
    }
    let credential =
        PresentedCredential::parse(bearer).map_err(|_| BundleFailure::AuthenticationRejected)?;
    let inspection = InstanceBootstrap::inspect_offline_support_bundle(
        paths,
        max_registered_tenants,
        credential,
        diagnostics_claim(output_limit)?,
    )
    .map_err(|failure| match failure {
        positron_runtime::OfflineSupportBundleFailure::AuthenticationRejected => {
            BundleFailure::AuthenticationRejected
        },
        positron_runtime::OfflineSupportBundleFailure::Unavailable => {
            BundleFailure::InspectionUnavailable
        },
    })?;
    let (signer, catalog_generation, backup_repository, resources, crash_records) =
        inspection.into_parts();
    let owned_report = owned_bundle_doctor_report(catalog_generation, backup_repository, resources);
    let operational = format!(
        "inspection_mode=offline\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nbackup_repository={}\n",
        "verified",
        "verified",
        catalog_generation,
        backup_repository.label(),
    );
    collect(signer, operational, owned_report, crash_records)
}
