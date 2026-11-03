//! Real SDK source payloads under explicitly private release-test identities.
mod support;
use positron_release::*;
use std::io::Read;

fn rewrite_package(
    bytes: &[u8],
    prefix: Option<&str>,
    mut rewrite: impl FnMut(&str, Vec<u8>) -> Vec<u8>,
) -> Vec<u8> {
    let mut source = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    let mut output = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for entry in source.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        let mut content = Vec::new();
        entry.read_to_end(&mut content).unwrap();
        let content = rewrite(&path, content);
        let mut header = entry.header().clone();
        header.set_size(content.len() as u64);
        header.set_cksum();
        let path = prefix.map_or_else(
            || path.clone(),
            |prefix| format!("{prefix}/{}", path.split_once('/').unwrap().1),
        );
        output
            .append_data(&mut header, path, content.as_slice())
            .unwrap();
    }
    output.into_inner().unwrap().finish().unwrap()
}

#[test]
fn signed_inventory_cannot_hide_missing_rust_sdk_api_metadata() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkRust)
        .unwrap();
    let bytes = std::fs::read(
        fixture
            .root
            .join("bundle")
            .join(&fixture.inventory.artifacts[index].file),
    )
    .unwrap();
    let unbound = rewrite_package(&bytes, None, |path, bytes| {
        if path.ends_with("/Cargo.toml") {
            String::from_utf8(bytes)
                .unwrap()
                .replace("[package.metadata.positron]", "[package.metadata.unbound]")
                .into_bytes()
        } else {
            bytes
        }
    });
    fixture.replace_artifact(index, &unbound, &unbound);
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

fn cargo_package(fixture: &support::Fixture) -> Vec<u8> {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let target = fixture.root.join("cargo-package");
    let output = std::process::Command::new(env!("CARGO"))
        .current_dir(repository)
        .env("CARGO_TARGET_DIR", &target)
        .args([
            "package",
            "--locked",
            "--offline",
            "--allow-dirty",
            "--no-verify",
            "-p",
            "positron-sdk",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Cargo package failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(
        target
            .join("package")
            .join(format!("positron-sdk-{}.crate", env!("CARGO_PKG_VERSION"))),
    )
    .unwrap()
}
fn bind_schema(fixture: &mut support::Fixture) {
    let schema = include_bytes!("../../../api/positron/v1/positron.proto");
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::Api)
        .unwrap();
    fixture.replace_artifact(index, schema, schema);
    fixture.inventory.compatibility.schema = FileIdentity::of(schema).sha256;
    let compatibility = support::hex(
        &FileIdentity::of(&serde_json::to_vec(&fixture.inventory.compatibility).unwrap()).sha256,
    );
    let schema = support::hex(&fixture.inventory.compatibility.schema);
    for artifact in fixture.inventory.artifacts.clone() {
        let path = fixture.root.join("bundle").join(&artifact.provenance);
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let parameters = &mut document["predicate"]["buildDefinition"]["externalParameters"];
        parameters["schema_sha256"] = serde_json::json!(schema);
        parameters["compatibility_sha256"] = serde_json::json!(compatibility);
        let bytes = serde_json::to_vec(&document).unwrap();
        std::fs::write(path, &bytes).unwrap();
        fixture
            .inventory
            .files
            .iter_mut()
            .find(|file| file.id == artifact.provenance)
            .unwrap()
            .identity = FileIdentity::of(&bytes);
    }
}
fn private_fixture_package(real: &[u8]) -> Vec<u8> {
    // Only fixture identities change. This package is never live registry or
    // project-release evidence. The actual installed package is tested separately.
    rewrite_package(real, Some("positron-sdk-1.0.0"), |path, bytes| {
        if path.ends_with("/.cargo_vcs_info.json") {
            serde_json::to_vec(&serde_json::json!({"git":{"sha1":support::keyless::SOURCE_COMMIT,"dirty":false},"path_in_vcs":"sdk/rust"})).unwrap()
        } else if path.ends_with("/Cargo.toml") || path.ends_with("/Cargo.lock") {
            String::from_utf8(bytes)
                .unwrap()
                .replace(
                    &format!("version = \"{}\"", env!("CARGO_PKG_VERSION")),
                    "version = \"1.0.0\"",
                )
                .into_bytes()
        } else {
            bytes
        }
    })
}
fn publish(fixture: &support::Fixture, digest: &str) -> (Vec<u8>, ReleaseConstruction) {
    fixture.published_with_native(
        |artifact, statement| {
            if artifact.surface == Surface::SdkRust {
                statement["predicate"]["buildDefinition"]["externalParameters"]["native"]["index"]
                    ["cksum"] = serde_json::json!(digest);
            }
        },
        |_, _| {},
        |_, _| {},
    )
}
fn verify(
    fixture: &support::Fixture,
    signed: &[u8],
    construction: &ReleaseConstruction,
) -> Result<ReleaseVerificationReport, ReleaseError> {
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
}
#[test]
fn real_rust_sdk_payload_binds_to_full_signed_release_and_refuses_mutation() {
    let mut fixture = support::Fixture::new();
    let real = cargo_package(&fixture);
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkRust)
        .unwrap();
    fixture.replace_artifact(index, &real, &real);
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
    let package = private_fixture_package(&real);
    fixture.replace_artifact(index, &package, &package);
    bind_schema(&mut fixture);
    let digest = support::hex(&FileIdentity::of(&package).sha256);
    let (signed, construction) = publish(&fixture, &digest);
    verify(&fixture, &signed, &construction).unwrap();
    let mut bad_signature = signed.clone();
    let last = bad_signature.last_mut().unwrap();
    *last ^= 1;
    assert!(verify(&fixture, &bad_signature, &construction).is_err());
    let file = fixture.inventory.artifacts[index].file.clone();
    std::fs::write(
        fixture.root.join("bundle").join(&file),
        b"changed actual SDK payload",
    )
    .unwrap();
    assert!(verify(&fixture, &signed, &construction).is_err());
    std::fs::write(fixture.root.join("bundle").join(&file), &package).unwrap();
    {
        let payload = fixture.inventory.artifacts[index]
            .payload
            .as_ref()
            .expect("Rust source payload must be reproducible");
        std::fs::write(fixture.rebuild.join(payload), b"independent build drift").unwrap();
        assert_eq!(
            verify(&fixture, &signed, &construction).err(),
            Some(ReleaseError::Unreproducible)
        );
        std::fs::write(fixture.rebuild.join(payload), &package).unwrap();
    }
    for (from, to) in [
        (
            "api_version = \"positron.v1\"",
            "api_version = \"positron.v2\"",
        ),
        (
            "registry = \"https://crates.io\"",
            "registry = \"https://example.invalid\"",
        ),
        (
            "prost=0.14.3,pbjson=0.9.0,protoc-bin-vendored=3.2.0",
            "prost=9.9.9,pbjson=0.9.0,protoc-bin-vendored=3.2.0",
        ),
    ] {
        let changed = rewrite_package(&package, None, |path, bytes| {
            if path.ends_with("/Cargo.toml") {
                String::from_utf8(bytes)
                    .unwrap()
                    .replace(from, to)
                    .into_bytes()
            } else {
                bytes
            }
        });
        fixture.replace_artifact(index, &changed, &changed);
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
    let changed = rewrite_package(&package, None, |path, bytes| {
        if path.ends_with("/api/positron/v1/schema.sha256") {
            format!("{}\n", "0".repeat(64)).into_bytes()
        } else {
            bytes
        }
    });
    fixture.replace_artifact(index, &changed, &changed);
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
    let changed = rewrite_package(&package, None, |path, bytes| {
        if path.ends_with("/api/positron/v1/positron.proto") {
            b"different canonical definition".to_vec()
        } else {
            bytes
        }
    });
    fixture.replace_artifact(index, &changed, &changed);
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
