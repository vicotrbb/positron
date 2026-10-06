use super::*;

pub(super) fn authenticated_inspection<T>(
    paths: &BootstrapPaths,
    output_limit: usize,
    collect: impl FnOnce(
        positron_kernel::ExportManifestSigner,
        String,
        String,
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
    let instance =
        InstanceBootstrap::reopen(paths).map_err(|_| BundleFailure::InspectionUnavailable)?;
    let actor = instance
        .attribute(
            credential,
            RequestedIntent::SystemAdministration,
            CompatibilityHints::none(),
        )
        .map_err(|_| BundleFailure::AuthenticationRejected)?;
    let reservation = instance
        .resource_governor()
        .reserve(diagnostics_claim(output_limit)?)
        .map_err(|_| BundleFailure::InspectionUnavailable)?;
    let facts = instance
        .doctor_runtime_facts(actor)
        .map_err(|_| BundleFailure::InspectionUnavailable)?;
    let owned_report = owned_bundle_doctor_report(
        facts,
        instance
            .resource_governor()
            .inspect()
            .map_err(|_| BundleFailure::InspectionUnavailable)?,
    );
    let signer = instance
        .support_bundle_manifest_signer(actor)
        .map_err(|_| BundleFailure::InspectionUnavailable)?;
    let operational = format!(
        "inspection_mode=offline\nkey_custody={}\ncatalog_bootstrap={}\ncatalog_generation={}\nbackup_repository={}\n",
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
    let collected = collect(signer, operational, owned_report);
    drop(reservation);
    collected
}
