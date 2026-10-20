//! CI runs the existing public CLI flows against the extracted native archive.
//! Local runs exercise Cargo's binary unless an explicit installation is supplied.
pub fn executable() -> std::path::PathBuf {
    std::env::var_os("POSITRON_TEST_NATIVE_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_positron").into())
}
