use crate::{construction::sha256, files::Bundle, inventory::hex, *};
use serde_json::Value;

pub(crate) fn verify_metadata(
    inventory: &ReleaseInventory,
    bundle: &Bundle,
) -> Result<(), ReleaseError> {
    verify_identities(inventory, bundle)?;
    verify_evidence(inventory, bundle)
}

pub(crate) fn verify_identities(
    inventory: &ReleaseInventory,
    bundle: &Bundle,
) -> Result<(), ReleaseError> {
    crate::native_maven_package::verify_set(inventory, bundle)?;
    let input_identities = inventory
        .inputs
        .iter()
        .map(|input| {
            inventory
                .file(&input.file)
                .map(|file| (input, &file.identity))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inputs = hex(&sha256(
        &serde_json::to_vec(&input_identities).map_err(|_| ReleaseError::Invalid)?,
    ));
    let compatibility = hex(&sha256(
        &serde_json::to_vec(&inventory.compatibility).map_err(|_| ReleaseError::Invalid)?,
    ));
    let version = format!(
        "{}.{}.{}",
        inventory.version.major, inventory.version.minor, inventory.version.patch
    );
    for artifact in &inventory.artifacts {
        if artifact.surface == Surface::SdkRust {
            if artifact.publication.registry != "https://crates.io"
                || artifact.publication.native_subject
                    != format!("pkg:cargo/positron-sdk@{version}")
            {
                return Err(ReleaseError::IdentityMismatch);
            }
            crate::native_crates::inspect_sdk(
                &bundle.read(&artifact.file, crate::native_crates::MAX_INPUT)?,
                &version,
                &inventory.source_commit,
                &inventory.api_version,
                &inventory.compatibility.schema,
            )?;
        }
        if artifact.surface == Surface::SdkTypeScript {
            if artifact.publication.registry != "https://registry.npmjs.org"
                || artifact.publication.native_subject
                    != format!("pkg:npm/%40positron/sdk@{version}")
            {
                return Err(ReleaseError::IdentityMismatch);
            }
            crate::native_npm::inspect_sdk(
                &bundle.read(&artifact.file, crate::native_npm::MAX_INPUT)?,
                &version,
                &inventory.source_commit,
                &inventory.api_version,
                &inventory.compatibility.schema,
            )?;
        }
        if artifact.surface == Surface::SdkGo {
            if artifact.publication.registry != "https://proxy.golang.org"
                || artifact.publication.native_subject
                    != format!("pkg:golang/{}@{version}", crate::native_go::sdk::MODULE)
            {
                return Err(ReleaseError::IdentityMismatch);
            }
            crate::native_go::sdk::inspect(
                &bundle.read(&artifact.file, 64 << 20)?,
                &version,
                &inventory.source_commit,
                &inventory.api_version,
                &inventory.compatibility.schema,
            )?;
        }
        if artifact.surface == Surface::SdkPython {
            if artifact.publication.registry != "https://pypi.org"
                || artifact.publication.native_subject
                    != format!("positron_sdk-{version}-py3-none-any.whl")
                || artifact.file != artifact.publication.native_subject
            {
                return Err(ReleaseError::IdentityMismatch);
            }
            crate::native_python::inspect_sdk(
                &bundle.read(&artifact.file, crate::native_python::MAX_INPUT)?,
                &version,
                &inventory.source_commit,
                &inventory.api_version,
                &inventory.compatibility.schema,
            )?;
        }
        let digest = hex(&inventory.file(&artifact.file)?.identity.sha256);
        let spdx = document(bundle, &artifact.spdx)?;
        let packages = spdx
            .get("packages")
            .and_then(Value::as_array)
            .ok_or(ReleaseError::IdentityMismatch)?;
        if spdx.get("spdxVersion").and_then(Value::as_str) != Some("SPDX-2.3")
            || spdx.get("SPDXID").and_then(Value::as_str) != Some("SPDXRef-DOCUMENT")
            || !packages.iter().any(|package| {
                package.get("name").and_then(Value::as_str) == Some(&artifact.file)
                    && package.get("versionInfo").and_then(Value::as_str) == Some(&version)
                    && package
                        .get("licenseConcluded")
                        .and_then(Value::as_str)
                        .is_some_and(|license| !license.is_empty() && license != "NOASSERTION")
                    && contains_hash(
                        package,
                        "checksums",
                        "algorithm",
                        "SHA256",
                        "checksumValue",
                        &digest,
                    )
            })
        {
            return Err(ReleaseError::IdentityMismatch);
        }
        let cdx = document(bundle, &artifact.cyclonedx)?;
        if cdx.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX")
            || !matches!(
                cdx.get("specVersion").and_then(Value::as_str),
                Some("1.5" | "1.6")
            )
            || !cdx
                .get("components")
                .and_then(Value::as_array)
                .is_some_and(|components| {
                    components.iter().any(|component| {
                        component.get("name").and_then(Value::as_str) == Some(&artifact.file)
                            && component.get("version").and_then(Value::as_str) == Some(&version)
                            && contains_hash(
                                component, "hashes", "alg", "SHA-256", "content", &digest,
                            )
                    })
                })
        {
            return Err(ReleaseError::IdentityMismatch);
        }
        let provenance = document(bundle, &artifact.provenance)?;
        if provenance.get("_type").and_then(Value::as_str)
            != Some("https://in-toto.io/Statement/v1")
            || provenance.get("predicateType").and_then(Value::as_str)
                != Some("https://slsa.dev/provenance/v1")
            || !provenance
                .get("subject")
                .and_then(Value::as_array)
                .is_some_and(|subjects| {
                    subjects.iter().any(|subject| {
                        subject.get("name").and_then(Value::as_str) == Some(&artifact.file)
                            && subject.pointer("/digest/sha256").and_then(Value::as_str)
                                == Some(&digest)
                    })
                })
        {
            return Err(ReleaseError::IdentityMismatch);
        }
        let parameters = provenance
            .pointer("/predicate/buildDefinition/externalParameters")
            .ok_or(ReleaseError::IdentityMismatch)?;
        for (name, value) in [
            ("source_commit", &inventory.source_commit),
            ("build_identity", &inventory.build_identity),
            ("api_version", &inventory.api_version),
            ("product_version", &version),
            ("target", &artifact.target),
            ("inputs_sha256", &inputs),
            ("schema_sha256", &hex(&inventory.compatibility.schema)),
            ("compatibility_sha256", &compatibility),
        ] {
            if parameters.get(name).and_then(Value::as_str) != Some(value) {
                return Err(ReleaseError::IdentityMismatch);
            }
        }
        if bundle
            .read(&artifact.license_notices, 1_048_576)?
            .is_empty()
        {
            return Err(ReleaseError::Invalid);
        }
    }
    Ok(())
}
// Full release construction always requires the complete validation evidence.
// Staged artifact identity qualification makes no claim that these gates passed.
pub(crate) fn verify_evidence(
    inventory: &ReleaseInventory,
    bundle: &Bundle,
) -> Result<(), ReleaseError> {
    for artifact in &inventory.artifacts {
        let digest = hex(&inventory.file(&artifact.file)?.identity.sha256);
        let provenance = document(bundle, &artifact.provenance)?;
        let builder = provenance
            .pointer("/predicate/runDetails/builder/id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .ok_or(ReleaseError::Invalid)?;
        let evidence = document(bundle, &artifact.evidence)?;
        if evidence.get("artifact_sha256").and_then(Value::as_str) != Some(&digest)
            || evidence.get("builder").and_then(Value::as_str) != Some(builder)
            || !evidence
                .get("independent_builder")
                .and_then(Value::as_str)
                .is_some_and(|other| !other.is_empty() && other != builder && other.len() <= 256)
        {
            return Err(ReleaseError::Unreproducible);
        }
        for result in [
            "unit",
            "integration",
            "fuzz",
            "conformance",
            "fault",
            "security",
            "dependency_policy",
            "secret_scan",
        ] {
            if evidence
                .get("results")
                .and_then(|results| results.get(result))
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Err(ReleaseError::Unsupported);
            }
        }
    }
    Ok(())
}

fn contains_hash(
    value: &Value,
    collection: &str,
    algorithm: &str,
    expected_algorithm: &str,
    content: &str,
    expected: &str,
) -> bool {
    value
        .get(collection)
        .and_then(Value::as_array)
        .is_some_and(|hashes| {
            hashes.iter().any(|hash| {
                hash.get(algorithm).and_then(Value::as_str) == Some(expected_algorithm)
                    && hash.get(content).and_then(Value::as_str) == Some(expected)
            })
        })
}
fn document(bundle: &Bundle, id: &str) -> Result<Value, ReleaseError> {
    serde_json::from_slice(&bundle.read(id, 1_048_576)?).map_err(|_| ReleaseError::Invalid)
}
