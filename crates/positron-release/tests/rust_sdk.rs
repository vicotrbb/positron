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

fn cargo_package(fixture: &support::Fixture, repository: &std::path::Path) -> Vec<u8> {
    package(repository, &fixture.root.join("cargo-package"), true)
}

fn package(repository: &std::path::Path, target: &std::path::Path, allow_dirty: bool) -> Vec<u8> {
    let mut command = std::process::Command::new(env!("CARGO"));
    command.arg("package");
    if allow_dirty {
        command.arg("--allow-dirty");
    }
    let output = command
        .current_dir(repository)
        .env("CARGO_TARGET_DIR", target)
        .args(["--locked", "--offline", "--no-verify", "-p", "positron-sdk"])
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
fn independent_packages(fixture: &support::Fixture, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut packages = Vec::new();
    for name in ["source-one", "source-two"] {
        let root = fixture.root.join(name);
        tar::Archive::new(flate2::read::GzDecoder::new(seed))
            .unpack(&root)
            .unwrap();
        let source = root.join(format!("positron-sdk-{}", env!("CARGO_PKG_VERSION")));
        let vcs = source.join(".cargo_vcs_info.json");
        if vcs.exists() {
            std::fs::remove_file(vcs).unwrap();
        }
        // These private commits bind independently packaged source, including on
        // gitless Nix inputs. No project or global Git configuration is changed.
        for args in [
            vec!["init", "--quiet", "--initial-branch=main"],
            vec!["add", "--all"],
            vec![
                "-c",
                "user.name=SDK fixture",
                "-c",
                "user.email=sdk@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                "SDK fixture",
            ],
        ] {
            let output = std::process::Command::new("git")
                .current_dir(&source)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
                .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture Git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let bytes = package(&source, &fixture.root.join(format!("target-{name}")), false);
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
        let mut entry = archive
            .entries()
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.path().unwrap().ends_with(".cargo_vcs_info.json"))
            .expect("independent package must carry its clean source commit");
        let mut vcs = String::new();
        entry.read_to_string(&mut vcs).unwrap();
        let vcs: serde_json::Value = serde_json::from_str(&vcs).unwrap();
        assert_ne!(vcs["git"]["dirty"], true);
        packages.push(bytes);
    }
    let second = packages.pop().unwrap();
    let first = packages.pop().unwrap();
    assert_eq!(first, second, "independent clean Cargo archives differ");
    (first, second)
}
fn private_fixture_package(real: &[u8]) -> Vec<u8> {
    // Only fixture identities change. This package is never live registry or
    // project-release evidence. The actual installed package is tested separately.
    let mut has_vcs = false;
    let package = rewrite_package(real, Some("positron-sdk-1.0.0"), |path, bytes| {
        if path.ends_with("/.cargo_vcs_info.json") {
            has_vcs = true;
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
    });
    if has_vcs {
        return package;
    }
    // Nix source snapshots have no checkout metadata. Supply only this
    // explicitly private fixture identity, never production release evidence.
    let mut source = tar::Archive::new(flate2::read::GzDecoder::new(package.as_slice()));
    let mut output = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for entry in source.entries().unwrap() {
        let mut entry = entry.unwrap();
        let header = entry.header().clone();
        output.append(&header, &mut entry).unwrap();
    }
    let vcs = serde_json::to_vec(&serde_json::json!({"git":{"sha1":support::keyless::SOURCE_COMMIT,"dirty":false},"path_in_vcs":"sdk/rust"})).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_size(vcs.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    output
        .append_data(
            &mut header,
            "positron-sdk-1.0.0/.cargo_vcs_info.json",
            vcs.as_slice(),
        )
        .unwrap();
    output.into_inner().unwrap().finish().unwrap()
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
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let real = cargo_package(
        &fixture,
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")),
    );
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
    let (original, independent) = independent_packages(&fixture, &real);
    let package = private_fixture_package(&original);
    let independent = private_fixture_package(&independent);
    fixture.replace_artifact(index, &package, &independent);
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

#[test]
fn gitless_sdk_source_needs_explicit_private_fixture_vcs_identity() {
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let real = cargo_package(
        &fixture,
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")),
    );
    let source = fixture.root.join("gitless-source");
    tar::Archive::new(flate2::read::GzDecoder::new(real.as_slice()))
        .unpack(&source)
        .unwrap();
    let source = source.join(format!("positron-sdk-{}", env!("CARGO_PKG_VERSION")));
    let vcs = source.join(".cargo_vcs_info.json");
    if vcs.exists() {
        std::fs::remove_file(vcs).unwrap();
    }
    let gitless = cargo_package(&fixture, &source);
    assert!(
        tar::Archive::new(flate2::read::GzDecoder::new(gitless.as_slice()))
            .entries()
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .path()
                .unwrap()
                .ends_with(".cargo_vcs_info.json"))
    );
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkRust)
        .unwrap();
    let unbound = rewrite_package(&gitless, Some("positron-sdk-1.0.0"), |path, bytes| {
        if path.ends_with("/Cargo.toml") || path.ends_with("/Cargo.lock") {
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
        Some(ReleaseError::Invalid)
    );
    let package = private_fixture_package(&gitless);
    fixture.replace_artifact(index, &package, &package);
    let digest = support::hex(&FileIdentity::of(&package).sha256);
    let (signed, construction) = publish(&fixture, &digest);
    verify(&fixture, &signed, &construction).unwrap();
}
