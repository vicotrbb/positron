//! Native package contexts, metadata eligibility, and offline proof dispatch.
use crate::{files::Bundle as Files, *};
use serde_json::Value;
use sha2::{Digest, Sha256};
pub(crate) fn verify(
    proof: &Value,
    artifact: &Artifact,
    inventory: &ReleaseInventory,
    files: &Files,
    trust: &VerifiedTrust,
    policy: &NativePublisherPolicy,
) -> Result<(), ReleaseError> {
    let version = format!(
        "{}.{}.{}",
        inventory.version.major, inventory.version.minor, inventory.version.patch
    );
    let contents = files.read(&artifact.file, 64 << 20)?;
    if let NativePublisherPolicy::CratesIo { repository } = policy {
        if artifact.surface != Surface::SdkRust
            || artifact.publication.registry != "https://crates.io"
        {
            return Err(ReleaseError::Unsupported);
        }
        let name = package_subject(&artifact.publication.native_subject, "pkg:cargo/", &version)?;
        return crate::native_crates::verify(
            proof,
            &contents,
            name,
            &version,
            &inventory.source_commit,
            repository,
        );
    }
    let root = proof
        .get("trustedRoot")
        .ok_or(ReleaseError::Authentication)?;
    if let Some(expected) = policy.trusted_root_sha256() {
        let bytes = serde_json::to_vec(root).map_err(|_| ReleaseError::Invalid)?;
        if bytes.len() > 65_536 || <[u8; 32]>::from(Sha256::digest(&bytes)) != *expected {
            return Err(ReleaseError::Authentication);
        }
        trust.check_artifact(expected)?;
    }
    match policy {
        NativePublisherPolicy::NugetRepository { .. }
            if artifact.surface == Surface::SdkDotNet
                && artifact.publication.registry == "https://api.nuget.org/v3/index.json" =>
        {
            let name =
                package_subject(&artifact.publication.native_subject, "pkg:nuget/", &version)?;
            for identity in crate::native_nuget::verify(
                root,
                &contents,
                name,
                &version,
                &artifact.publication.registry,
                trust.now(),
            )? {
                trust.check_artifact(&identity)?;
            }
        },
        NativePublisherPolicy::Maven { .. }
            if artifact.surface == Surface::SdkJava
                && artifact.publication.registry == "https://repo.maven.apache.org/maven2" =>
        {
            crate::native_maven::verify(
                root,
                proof.get("signature").ok_or(ReleaseError::Authentication)?,
                &contents,
                trust.now(),
            )?;
        },
        NativePublisherPolicy::GoChecksum { .. }
            if artifact.surface == Surface::SdkGo
                && artifact.publication.registry == "https://proxy.golang.org" =>
        {
            let module = package_subject(
                &artifact.publication.native_subject,
                "pkg:golang/",
                &version,
            )?;
            crate::native_go::verify(
                root,
                proof.get("sumdb").ok_or(ReleaseError::Authentication)?,
                &contents,
                module,
                &format!("v{version}"),
            )?;
        },
        _ => return Err(ReleaseError::Unsupported),
    }
    Ok(())
}
pub(crate) fn package_subject<'a>(
    subject: &'a str,
    prefix: &str,
    version: &str,
) -> Result<&'a str, ReleaseError> {
    let name = subject
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(&format!("@{version}")))
        .ok_or(ReleaseError::IdentityMismatch)?;
    if name.is_empty() || name.len() > 512 || name.chars().any(char::is_control) {
        return Err(ReleaseError::IdentityMismatch);
    }
    Ok(name)
}

pub(crate) fn verify_registry_metadata(
    artifact: &Artifact,
    inventory: &ReleaseInventory,
) -> Result<(), ReleaseError> {
    let version = format!(
        "{}.{}.{}",
        inventory.version.major, inventory.version.minor, inventory.version.patch
    );
    let (registry, prefix) = match artifact.surface {
        Surface::SdkRust => ("https://crates.io", "pkg:cargo/"),
        Surface::SdkTypeScript => ("https://registry.npmjs.org", "pkg:npm/"),
        Surface::SdkGo => ("https://proxy.golang.org", "pkg:golang/"),
        Surface::SdkDotNet => ("https://api.nuget.org/v3/index.json", "pkg:nuget/"),
        Surface::SdkJava => {
            if artifact.publication.registry != "https://repo.maven.apache.org/maven2" {
                return Err(ReleaseError::Unsupported);
            }
            return Ok(());
        },
        Surface::SdkPython => {
            if artifact.publication.registry != "https://pypi.org" {
                return Err(ReleaseError::Unsupported);
            }
            if artifact.publication.native_subject != artifact.file
                || !(artifact.file.contains(&format!("-{version}-"))
                    && artifact.file.ends_with(".whl")
                    || artifact.file.ends_with(&format!("-{version}.tar.gz")))
            {
                return Err(ReleaseError::IdentityMismatch);
            }
            return Ok(());
        },
        Surface::Homebrew => {
            if !artifact
                .publication
                .registry
                .starts_with("https://github.com/")
                || !artifact
                    .publication
                    .registry
                    .split('/')
                    .next_back()
                    .is_some_and(|name| name.starts_with("homebrew-"))
                || artifact.publication.registry == "https://github.com/Homebrew/homebrew-core"
                || artifact.publication.native_revision.is_none()
            {
                return Err(ReleaseError::Unsupported);
            }
            return Ok(());
        },
        _ => return Ok(()),
    };
    if artifact.publication.registry != registry {
        return Err(ReleaseError::Unsupported);
    }
    package_subject(&artifact.publication.native_subject, prefix, &version)?;
    Ok(())
}
