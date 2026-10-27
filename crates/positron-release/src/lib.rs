//! Offline release construction and verification, using the canonical kernel manifest.
#![forbid(unsafe_code)]

mod homebrew;
pub use homebrew::homebrew_formula;
mod native_archive;
pub use native_archive::{NativeTarget, native_archive};
mod archive_scan;
pub use archive_scan::scan_release_contents;
mod files;
pub use files::{inspect_file, read_installed_trust_file, read_release_file, write_release_file};
mod native_cms;
mod native_crates;
mod native_go;
mod native_maven;
mod native_maven_package;
mod native_nix;
mod native_nuget;
mod native_packages;
mod native_rpm;
pub use native_rpm::rpm_functional_payload;
mod native_publication;
mod native_xml;
mod nuget_zip;
mod publication;
mod transparency;
pub use transparency::verify_transparency_inclusion;
mod verification;
pub use verification::*;
mod construction;
mod metadata;
mod oci;
pub use construction::*;
mod inventory;
mod trust;
pub use inventory::*;
pub use trust::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseError {
    Invalid,
    LimitExceeded,
    Authentication,
    StaleTrust,
    Revoked,
    Unsupported,
    PartialSet,
    IdentityMismatch,
    Unreproducible,
    SecretDetected,
    Unavailable,
}
impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "release refused: {self:?}")
    }
}
impl std::error::Error for ReleaseError {}

#[cfg(test)]
mod build_qualification;
