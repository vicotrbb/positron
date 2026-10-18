//! Fixture manifests for the existing in-process upgrade tests.
#[path = "../support/upgrade_release.rs"]
mod shared;
pub(super) fn configuration(
    root: &std::path::Path,
    epoch: u32,
    query: &str,
) -> super::Result<(positron_config::EffectiveConfiguration, [u8; 32])> {
    let executable = std::env::current_exe()?;
    shared::configuration(
        root,
        epoch,
        query,
        &executable,
        &executable,
        "9fd68fd9eaa72ed45e070412d30656fda1277d79",
        "9fd68fd9eaa72ed45e070412d30656fda1277d79",
    )
}
