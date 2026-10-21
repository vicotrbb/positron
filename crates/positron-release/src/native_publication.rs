//! Offline verification of standard keyless publisher attestations.
use crate::native_packages::{package_subject, verify_registry_metadata};
use crate::{
    files::Bundle as Files,
    publication::{base64, string},
    *,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sigstore_verify::{VerificationPolicy, Verifier, trust_root::TrustedRoot, types::Bundle};

pub(crate) fn verify_native(
    proof: &Value,
    artifact: &Artifact,
    inventory: &ReleaseInventory,
    files: &Files,
    trust: &VerifiedTrust,
) -> Result<(), ReleaseError> {
    verify_registry_metadata(artifact, inventory)?;
    let authorization = trust.native_publisher(&artifact.publication.registry)?;
    if artifact.surface == Surface::Nix {
        return crate::native_nix::verify(
            proof,
            artifact,
            inventory,
            files,
            trust,
            &authorization.policy,
        );
    }
    let eligible = match (artifact.surface, &authorization.policy) {
        (Surface::Rpm, NativePublisherPolicy::Rpm { .. }) => true,
        (Surface::Rpm, _) => false,
        (Surface::SdkRust, NativePublisherPolicy::CratesIo { .. }) => {
            artifact.publication.registry == "https://crates.io"
        },
        (Surface::SdkGo, NativePublisherPolicy::GoChecksum { .. }) => {
            artifact.publication.registry == "https://proxy.golang.org"
        },
        (Surface::SdkJava, NativePublisherPolicy::Maven { .. }) => {
            artifact.publication.registry == "https://repo.maven.apache.org/maven2"
        },
        (Surface::SdkDotNet, NativePublisherPolicy::NugetRepository { .. }) => {
            artifact.publication.registry == "https://api.nuget.org/v3/index.json"
        },
        (Surface::SdkTypeScript, NativePublisherPolicy::Keyless(policy)) => {
            policy.kind == NativePublicationKind::Npm
                && artifact.publication.registry == "https://registry.npmjs.org"
        },
        (Surface::SdkPython, NativePublisherPolicy::Keyless(policy)) => {
            policy.kind == NativePublicationKind::PyPi
                && artifact.publication.registry == "https://pypi.org"
        },
        (Surface::Homebrew, NativePublisherPolicy::Keyless(policy)) => {
            policy.kind == NativePublicationKind::HomebrewTap
        },
        (Surface::SdkRust | Surface::SdkGo | Surface::SdkJava | Surface::SdkDotNet, _) => false,
        (_, NativePublisherPolicy::Keyless(policy)) => {
            policy.kind == NativePublicationKind::GithubActions
        },
        _ => false,
    };
    if !eligible {
        return Err(ReleaseError::Unsupported);
    }

    let source_commit = inventory.source_commit.as_str();
    let NativePublisherPolicy::Keyless(publisher) = &authorization.policy else {
        return crate::native_packages::verify(
            proof,
            artifact,
            inventory,
            files,
            trust,
            &authorization.policy,
        );
    };
    let source_commit = if publisher.kind == NativePublicationKind::HomebrewTap {
        if artifact.surface != Surface::Homebrew
            || authorization.registry != publisher.repository
            || !publisher.repository.starts_with("https://github.com/")
            || !publisher
                .repository
                .split('/')
                .next_back()
                .is_some_and(|name| name.starts_with("homebrew-"))
            || publisher.repository == "https://github.com/Homebrew/homebrew-core"
        {
            return Err(ReleaseError::Unsupported);
        }
        artifact
            .publication
            .native_revision
            .as_deref()
            .ok_or(ReleaseError::IdentityMismatch)?
    } else {
        source_commit
    };
    let root = proof
        .get("trustedRoot")
        .ok_or(ReleaseError::Authentication)?;
    let root_bytes = serde_json::to_vec(root).map_err(|_| ReleaseError::Invalid)?;
    if root_bytes.len() > 65_536
        || <[u8; 32]>::from(Sha256::digest(&root_bytes)) != publisher.trusted_root_sha256
    {
        return Err(ReleaseError::Authentication);
    }
    trust.check_artifact(&publisher.trusted_root_sha256)?;
    let supplied = proof.get("bundle").ok_or(ReleaseError::Authentication)?;
    let normalized =
        if publisher.kind == NativePublicationKind::PyPi && supplied.get("version").is_some() {
            Some(normalize_pypi(supplied)?)
        } else {
            None
        };
    let bundle = normalized.as_ref().unwrap_or(supplied);
    let root = TrustedRoot::from_json(&root.to_string()).map_err(|_| ReleaseError::Invalid)?;
    let parsed = Bundle::from_json(&bundle.to_string()).map_err(|_| ReleaseError::Invalid)?;
    let leaf = base64(string(
        bundle,
        "/verificationMaterial/certificate/rawBytes",
    )?)?;
    trust.check_artifact(&Sha256::digest(&leaf).into())?;
    let result = Verifier::new(&root)
        .map_err(|_| ReleaseError::Authentication)?
        .verify_reader(
            files.file(&artifact.file)?,
            &parsed,
            &VerificationPolicy::new(publisher.identity.clone(), publisher.issuer.clone()),
        )
        .map_err(|_| ReleaseError::Authentication)?;
    let integrated = result
        .integrated_time()
        .ok_or(ReleaseError::Authentication)?
        .as_second();
    if integrated < 0 || integrated as u64 > trust.now() {
        return Err(ReleaseError::Authentication);
    }
    let certificate = result.certificate().ok_or(ReleaseError::Authentication)?;
    let claims = &certificate.ci_claims;
    if claims.source_repository_uri.as_deref() != Some(&publisher.repository)
        || claims.source_repository_digest.as_deref() != Some(source_commit)
        || claims.source_repository_ref.as_deref() != Some(&publisher.source_ref)
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let payload = base64(string(bundle, "/dsseEnvelope/payload")?)?;
    let statement: Value = serde_json::from_slice(&payload).map_err(|_| ReleaseError::Invalid)?;
    if string(&statement, "/_type")? != "https://in-toto.io/Statement/v1"
        || !statement
            .get("subject")
            .and_then(Value::as_array)
            .is_some_and(|subjects| {
                subjects.len() == 1
                    && subjects
                        .first()
                        .and_then(|subject| subject.get("name"))
                        .and_then(Value::as_str)
                        == Some(&artifact.publication.native_subject)
            })
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    match publisher.kind {
        NativePublicationKind::PyPi => {
            if artifact.surface != Surface::SdkPython
                || authorization.registry != "https://pypi.org"
                || artifact.publication.native_subject != artifact.file
                || string(&statement, "/predicateType")?
                    != "https://docs.pypi.org/attestations/publish/v1"
                || statement.get("predicate").is_some_and(|predicate| {
                    !predicate.is_null()
                        && predicate
                            .as_object()
                            .is_none_or(|object| !object.is_empty())
                })
            {
                return Err(ReleaseError::IdentityMismatch);
            }
        },
        NativePublicationKind::Npm
        | NativePublicationKind::GithubActions
        | NativePublicationKind::HomebrewTap => {
            if publisher.kind == NativePublicationKind::Npm {
                let version = format!(
                    "{}.{}.{}",
                    inventory.version.major, inventory.version.minor, inventory.version.patch
                );
                package_subject(&artifact.publication.native_subject, "pkg:npm/", &version)?;
            }
            if publisher.kind == NativePublicationKind::Npm
                && (artifact.surface != Surface::SdkTypeScript
                    || authorization.registry != "https://registry.npmjs.org"
                    || !artifact.publication.native_subject.starts_with("pkg:npm/")
                    || !statement
                        .pointer("/subject/0/digest/sha512")
                        .and_then(Value::as_str)
                        .is_some_and(|digest| {
                            digest.len() == 128
                                && digest.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        }))
            {
                return Err(ReleaseError::IdentityMismatch);
            }
            if string(&statement, "/predicateType")? != "https://slsa.dev/provenance/v1"
                || string(&statement, "/predicate/buildDefinition/buildType")?
                    != if publisher.kind == NativePublicationKind::Npm {
                        "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
                    } else {
                        "https://actions.github.io/buildtypes/workflow/v1"
                    }
                || string(
                    &statement,
                    "/predicate/buildDefinition/externalParameters/workflow/repository",
                )? != publisher.repository
                || string(
                    &statement,
                    "/predicate/buildDefinition/externalParameters/workflow/ref",
                )? != publisher.source_ref
            {
                return Err(ReleaseError::IdentityMismatch);
            }
            let workflow = format!(
                "{}/{}@{}",
                publisher.repository,
                string(
                    &statement,
                    "/predicate/buildDefinition/externalParameters/workflow/path"
                )?,
                publisher.source_ref
            );
            if workflow != publisher.identity
                || !statement
                    .pointer("/predicate/buildDefinition/resolvedDependencies")
                    .and_then(Value::as_array)
                    .is_some_and(|dependencies| {
                        dependencies.iter().any(|dependency| {
                            dependency.get("uri").and_then(Value::as_str)
                                == Some(
                                    format!(
                                        "git+{}@{}",
                                        publisher.repository, publisher.source_ref
                                    )
                                    .as_str(),
                                )
                                && dependency
                                    .pointer("/digest/gitCommit")
                                    .and_then(Value::as_str)
                                    == Some(source_commit)
                        })
                    })
            {
                return Err(ReleaseError::IdentityMismatch);
            }
        },
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PyPiAttestation {
    version: u32,
    envelope: PyPiEnvelope,
    verification_material: PyPiMaterial,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PyPiEnvelope {
    statement: String,
    signature: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PyPiMaterial {
    certificate: String,
    transparency_entries: Vec<Value>,
}
fn normalize_pypi(value: &Value) -> Result<Value, ReleaseError> {
    let attestation: PyPiAttestation =
        serde_json::from_value(value.clone()).map_err(|_| ReleaseError::Invalid)?;
    if attestation.version != 1 || attestation.verification_material.transparency_entries.len() != 1
    {
        return Err(ReleaseError::Unsupported);
    }
    Ok(
        serde_json::json!({"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":attestation.verification_material.certificate},"tlogEntries":attestation.verification_material.transparency_entries},"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":attestation.envelope.statement,"signatures":[{"keyid":"","sig":attestation.envelope.signature}]}}),
    )
}
