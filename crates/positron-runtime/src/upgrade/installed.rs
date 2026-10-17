//! Loads the operator's installed release authority through canonical configuration.
use super::{UpgradeArtifactInput, UpgradeFailure, UpgradeRequest, UpgradeStartupVerification};
use positron_config::EffectiveConfiguration;
use positron_governance::AdministrativeIdempotencyKey;
use positron_kernel::release_manifest::{
    ArtifactRole, MAX_RELEASE_MANIFEST_BYTES, VerifiedReleaseManifest,
};
use positron_release::{InstalledReleaseTrust, MAX_INSTALLED_TRUST_BYTES};
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
    clock: &positron_kernel::RetentionTimeAuthority,
) -> Result<UpgradeRequest, UpgradeFailure> {
    let installation = configuration
        .installed_release()
        .ok_or(UpgradeFailure::InvalidRequest)?;
    let now = clock
        .security_time_seconds()
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    let root = trust_root(installation.project_trust_root_file().as_path())?;
    let source = source_manifest(installation.current_manifest_file().as_path(), &root, now)?;
    verify_inventory(
        &source,
        &root,
        installation
            .current_inventory_file()
            .map(|path| path.as_path()),
        now,
    )?;
    let target = manifest(
        installation
            .candidate_manifest_file()
            .ok_or(UpgradeFailure::InvalidRequest)?
            .as_path(),
        &root,
        now,
    )?;
    root.verify(now)
        .and_then(|trust| trust.require_supported_version(target.manifest().version))
        .map_err(|_| UpgradeFailure::UnsupportedTransition)?;
    let inventory = target
        .manifest()
        .artifacts
        .iter()
        .position(|artifact| artifact.role == ArtifactRole::ReleaseInventory)
        .and_then(|index| installation.candidate_artifact_files().get(index))
        .map(|path| path.as_path());
    let bytes = read_file(
        inventory.ok_or(UpgradeFailure::AuthenticationFailed)?,
        positron_release::MAX_INVENTORY_BYTES,
        false,
    )?;
    let qualified = positron_release::verify_target_metadata(
        target.signed_bytes(),
        &bytes,
        root.release_signer,
        &root
            .verify(now)
            .map_err(|_| UpgradeFailure::AuthenticationFailed)?,
    )
    .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
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
        (source, qualified),
        artifacts,
        repository,
        retention_seconds,
        expected_generation,
        key,
    )
}
pub fn installed_upgrade_startup(
    configuration: &EffectiveConfiguration,
    clock: &positron_kernel::RetentionTimeAuthority,
) -> Result<Option<UpgradeStartupVerification>, UpgradeFailure> {
    let Some(installation) = configuration.installed_release() else {
        return Ok(None);
    };
    let now = clock
        .security_time_seconds()
        .map_err(|_| UpgradeFailure::CapacityUnavailable)?;
    let root = trust_root(installation.project_trust_root_file().as_path())?;
    let release = source_manifest(installation.current_manifest_file().as_path(), &root, now)?;
    verify_inventory(
        &release,
        &root,
        installation
            .current_inventory_file()
            .map(|path| path.as_path()),
        now,
    )?;
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
fn trust_root(path: &Path) -> Result<InstalledReleaseTrust, UpgradeFailure> {
    InstalledReleaseTrust::from_bytes(&read_file(path, MAX_INSTALLED_TRUST_BYTES, false)?)
        .map_err(|_| UpgradeFailure::AuthenticationFailed)
}
fn source_manifest(
    path: &Path,
    trust: &InstalledReleaseTrust,
    now: u64,
) -> Result<VerifiedReleaseManifest, UpgradeFailure> {
    trust
        .verify_installed_manifest(
            &read_file(path, MAX_RELEASE_MANIFEST_BYTES + 64, false)?,
            now,
        )
        .map_err(|_| UpgradeFailure::AuthenticationFailed)
}
fn manifest(
    path: &Path,
    trust: &InstalledReleaseTrust,
    now: u64,
) -> Result<VerifiedReleaseManifest, UpgradeFailure> {
    trust
        .verify_manifest(
            &read_file(path, MAX_RELEASE_MANIFEST_BYTES + 64, false)?,
            now,
        )
        .map_err(|_| UpgradeFailure::AuthenticationFailed)
}
fn verify_inventory(
    manifest: &VerifiedReleaseManifest,
    installed: &InstalledReleaseTrust,
    path: Option<&Path>,
    now: u64,
) -> Result<(), UpgradeFailure> {
    if manifest
        .manifest()
        .artifacts
        .iter()
        .any(|artifact| artifact.role == ArtifactRole::ReleaseInventory)
    {
        let bytes = read_file(
            path.ok_or(UpgradeFailure::AuthenticationFailed)?,
            positron_release::MAX_INVENTORY_BYTES,
            false,
        )?;
        positron_release::verify_manifest_inventory(
            manifest,
            &bytes,
            &installed
                .verify(now)
                .map_err(|_| UpgradeFailure::AuthenticationFailed)?,
        )
        .map_err(|_| UpgradeFailure::AuthenticationFailed)?;
    } else if path.is_some() {
        return Err(UpgradeFailure::AuthenticationFailed);
    }
    Ok(())
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
