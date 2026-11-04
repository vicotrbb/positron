//! npm SDK package identity is checked before a signed Release Set can be made.
mod support;
use positron_release::*;
use std::io::Read;

fn rewrite(bytes: &[u8], mut change: impl FnMut(&str, Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    let mut output = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        let bytes = change(&path, bytes);
        let mut header = entry.header().clone();
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        output
            .append_data(&mut header, path, bytes.as_slice())
            .unwrap();
    }
    output.into_inner().unwrap().finish().unwrap()
}

#[test]
fn signed_inventory_refuses_npm_sdk_with_unbound_api_metadata() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkTypeScript)
        .unwrap();
    let bytes = std::fs::read(
        fixture
            .root
            .join("bundle")
            .join(&fixture.inventory.artifacts[index].file),
    )
    .unwrap();
    let invalid = rewrite(&bytes, |path, bytes| {
        if path == "package/package.json" {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value.as_object_mut().unwrap().remove("positron");
            serde_json::to_vec(&value).unwrap()
        } else {
            bytes
        }
    });
    fixture.replace_artifact(index, &invalid, &invalid);
    assert_eq!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[],
            vec![]
        )
        .err(),
        Some(ReleaseError::IdentityMismatch)
    );
}

#[test]
fn npm_identity_metadata_and_embedded_definition_fail_closed() {
    for (pointer, replacement, expected) in [
        (
            "/name",
            serde_json::json!("other"),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/version",
            serde_json::json!("9.0.0"),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/gitHead",
            serde_json::json!("0".repeat(40)),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/type",
            serde_json::json!("commonjs"),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/positron/api_version",
            serde_json::json!("positron.v2"),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/positron/schema_digest",
            serde_json::json!("0".repeat(64)),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/positron/registry",
            serde_json::json!("https://example.invalid"),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/positron/generator",
            serde_json::json!("unversioned"),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/exports/./import",
            serde_json::json!("./unbound.js"),
            ReleaseError::IdentityMismatch,
        ),
        (
            "/scripts",
            serde_json::json!({"postinstall":"untrusted"}),
            ReleaseError::Unsupported,
        ),
        (
            "/dependencies",
            serde_json::json!({"untrusted":"*"}),
            ReleaseError::Unsupported,
        ),
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == Surface::SdkTypeScript)
            .unwrap();
        let bytes = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let invalid = rewrite(&bytes, |path, bytes| {
            if path == "package/package.json" {
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                // Insert previously absent optional maps as well as changing existing identities.
                if pointer == "/scripts" || pointer == "/dependencies" {
                    value[pointer.trim_start_matches('/')] = replacement.clone();
                } else {
                    *value.pointer_mut(pointer).unwrap() = replacement.clone();
                }
                serde_json::to_vec(&value).unwrap()
            } else {
                bytes
            }
        });
        fixture.replace_artifact(index, &invalid, &invalid);
        assert_eq!(
            construct_release(
                &fixture.inventory,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                &[],
                vec![]
            )
            .err(),
            Some(expected),
            "{pointer}"
        );
    }
    for path in [
        "package/api/positron.proto",
        "package/api/schema.sha256",
        "package/dist/index.js",
        "package/dist/index.d.ts",
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == Surface::SdkTypeScript)
            .unwrap();
        let bytes = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let invalid = rewrite(
            &bytes,
            |name, bytes| if name == path { vec![] } else { bytes },
        );
        fixture.replace_artifact(index, &invalid, &invalid);
        assert_eq!(
            construct_release(
                &fixture.inventory,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                &[],
                vec![]
            )
            .err(),
            Some(ReleaseError::IdentityMismatch),
            "{path}"
        );
    }
}

#[test]
fn real_npm_archive_binds_to_signed_release_and_refuses_integrity_drift() {
    use sha2::{Digest, Sha512};
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/typescript");
    let output = std::process::Command::new("npm")
        .args(["pack", "--ignore-scripts", "--json", "--pack-destination"])
        .arg(&fixture.root)
        .current_dir(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "npm package: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let real = std::fs::read(fixture.root.join(metadata[0]["filename"].as_str().unwrap())).unwrap();
    // Keep real generated payloads and their canonical schema. Only the private
    // fixture's release/source identity differs from the unpublished candidate.
    let package = rewrite(&real, |path, bytes| {
        if path == "package/package.json" {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value["version"] = serde_json::json!("1.0.0");
            value["gitHead"] = serde_json::json!(support::keyless::SOURCE_COMMIT);
            serde_json::to_vec(&value).unwrap()
        } else {
            bytes
        }
    });
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkTypeScript)
        .unwrap();
    fixture.replace_artifact(index, &package, &package);
    let (signed, construction) = fixture.published_with_native(
        |_, _| {},
        |_, _| {},
        |artifact, statement| {
            if artifact.surface == Surface::SdkTypeScript {
                statement["subject"][0]["digest"]["sha512"] =
                    serde_json::json!(support::hex(&Sha512::digest(&package)));
                statement["predicate"]["buildDefinition"]["buildType"] = serde_json::json!(
                    "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
                );
            }
        },
    );
    let verify = |signed: &[u8]| {
        verify_release(
            signed,
            &construction.inventory_bytes,
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "linux-x86_64",
            &[],
        )
    };
    verify(&signed).unwrap();
    let mut invalid = signed.clone();
    *invalid.last_mut().unwrap() ^= 1;
    assert!(verify(&invalid).is_err());
    let payload = fixture.inventory.artifacts[index].payload.as_ref().unwrap();
    std::fs::write(
        fixture.rebuild.join(payload),
        b"independent npm payload drift",
    )
    .unwrap();
    assert_eq!(verify(&signed).err(), Some(ReleaseError::Unreproducible));
    std::fs::write(fixture.rebuild.join(payload), &package).unwrap();
    let artifact = &fixture.inventory.artifacts[index];
    let provenance = fixture.root.join("bundle").join(&artifact.provenance);
    let original = std::fs::read(&provenance).unwrap();
    std::fs::write(&provenance, b"{}").unwrap();
    assert!(verify(&signed).is_err());
    std::fs::write(provenance, original).unwrap();
    std::fs::write(
        fixture.root.join("bundle").join(&artifact.file),
        b"npm archive drift",
    )
    .unwrap();
    assert!(verify(&signed).is_err());
    std::fs::write(fixture.root.join("bundle").join(&artifact.file), &package).unwrap();
    let secret = b"explicit-private-sdk-secret-canary";
    assert_eq!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            &artifact.file,
            &[b"Generated typed client".to_vec()]
        )
        .err(),
        Some(ReleaseError::SecretDetected)
    );
    assert!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            &artifact.file,
            &[secret.to_vec()]
        )
        .is_ok()
    );
}
