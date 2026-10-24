//! CI runs the existing public CLI flows against the extracted native archive.
//! Local runs exercise Cargo's binary unless an explicit installation is supplied.
pub fn executable() -> std::path::PathBuf {
    std::env::var_os("POSITRON_TEST_NATIVE_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_positron").into())
}

#[allow(dead_code)]
pub fn distribution() -> Result<positron_config::ExecutableDistribution, Box<dyn std::error::Error>>
{
    match std::env::var("POSITRON_TEST_EXECUTABLE_DISTRIBUTION").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("native") => {
            Ok(positron_config::ExecutableDistribution::Native)
        },
        Ok("nix") => Ok(positron_config::ExecutableDistribution::Nix),
        _ => Err("invalid installed test executable distribution".into()),
    }
}
