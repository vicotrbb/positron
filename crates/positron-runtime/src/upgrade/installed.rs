//! Loads the operator's installed release authority through canonical configuration.
use super::{UpgradeArtifactInput, UpgradeFailure, UpgradeRequest, UpgradeStartupVerification};
use positron_config::EffectiveConfiguration;
use positron_governance::AdministrativeIdempotencyKey;
use positron_kernel::release_manifest::{
    MAX_RELEASE_MANIFEST_BYTES, ProjectTrustRoot, SignedReleaseManifest, VerifiedReleaseManifest,
};
use rustix::fs::{Mode, OFlags};
use std::os::unix::fs::MetadataExt;
use std::{
    fs::File,
    io::Read,
    path::{Component, Path},
};

pub fn installed_upgrade_request(
    configuration: &EffectiveConfiguration,
    target_manifest_digest: [u8; 32],
    repository: [u8; 16],
    retention_seconds: u64,
    key: AdministrativeIdempotencyKey,
    expected_generation: u64,
) -> Result<UpgradeRequest, UpgradeFailure> {
    let installation = configuration
        .installed_release()
        .ok_or(UpgradeFailure::InvalidRequest)?;
    let root = trust_root(installation.project_trust_root_file().as_path())?;
    let source = manifest(installation.current_manifest_file().as_path(), &root)?;
    let target = manifest(
        installation
            .candidate_manifest_file()
            .ok_or(UpgradeFailure::InvalidRequest)?
            .as_path(),
        &root,
    )?;
    if target.digest() != target_manifest_digest {
        return Err(UpgradeFailure::ArtifactMismatch);
    }
    if target.manifest().artifacts.len() != installation.candidate_artifact_files().len() {
        return Err(UpgradeFailure::ArtifactMismatch);
    }
    let artifacts = target
        .manifest()
        .artifacts
        .iter()
        .zip(installation.candidate_artifact_files())
        .map(|(artifact, path)| UpgradeArtifactInput {
            role: artifact.role,
            platform: artifact.platform.clone(),
            path: path.as_path().to_path_buf(),
        })
        .collect();
    UpgradeRequest::new(
        (source, target),
        artifacts,
        repository,
        retention_seconds,
        expected_generation,
        key,
    )
}
pub fn installed_upgrade_startup(
    configuration: &EffectiveConfiguration,
) -> Result<Option<UpgradeStartupVerification>, UpgradeFailure> {
    let Some(installation) = configuration.installed_release() else {
        return Ok(None);
    };
    let root = trust_root(installation.project_trust_root_file().as_path())?;
    let release = manifest(installation.current_manifest_file().as_path(), &root)?;
    let credential = installation
        .query_credential_file()
        .map(|path| {
            let bytes = zeroize::Zeroizing::new(read_file(path.as_path(), 256, true)?);
            std::str::from_utf8(&bytes)
                .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
                .map_err(|_| UpgradeFailure::AuthenticationFailed)
        })
        .transpose()?;
    UpgradeStartupVerification::new(release, credential).map(Some)
}
fn trust_root(path: &Path) -> Result<ProjectTrustRoot, UpgradeFailure> {
    let bytes = read_file(path, 32, false)?;
    let key = bytes
        .as_slice()
        .try_into()
        .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
    Ok(ProjectTrustRoot::new(key))
}
fn manifest(
    path: &Path,
    root: &ProjectTrustRoot,
) -> Result<VerifiedReleaseManifest, UpgradeFailure> {
    SignedReleaseManifest::from_bytes(&read_file(path, MAX_RELEASE_MANIFEST_BYTES + 64, false)?)
        .and_then(|signed| signed.verify(root))
        .map_err(|_| UpgradeFailure::AuthenticationFailed)
}
fn read_file(path: &Path, maximum: usize, secret: bool) -> Result<Vec<u8>, UpgradeFailure> {
    // Hold each ancestor instead of following a substituted symlink; nonblocking
    // descriptor checks also prevent FIFOs or devices from becoming file inputs.
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(UpgradeFailure::InvalidRequest);
    }
    let mut directory = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
    let mut components = path
        .components()
        .filter_map(|part| {
            if let Component::Normal(name) = part {
                Some(name)
            } else {
                None
            }
        })
        .peekable();
    while let Some(name) = components.next() {
        let last = components.peek().is_none();
        let flags = OFlags::RDONLY
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | if last {
                OFlags::empty()
            } else {
                OFlags::DIRECTORY
            };
        let descriptor = rustix::fs::openat(&directory, name, flags, Mode::empty())
            .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        if !last {
            directory = descriptor;
            continue;
        }
        let file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.len() > maximum as u64
            || (metadata.uid() != rustix::process::geteuid().as_raw() && metadata.uid() != 0)
            || metadata.mode() & 0o022 != 0
            || (secret && (metadata.mode() & 0o077 != 0 || metadata.nlink() != 1))
        {
            return Err(UpgradeFailure::ArtifactUnavailable);
        }
        let mut bytes = Vec::with_capacity(maximum + 1);
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| UpgradeFailure::ArtifactUnavailable)?;
        if bytes.len() > maximum {
            return Err(UpgradeFailure::ArtifactUnavailable);
        }
        return Ok(bytes);
    }
    Err(UpgradeFailure::InvalidRequest)
}

#[cfg(test)]
#[path = "installed_tests.rs"]
mod tests;
