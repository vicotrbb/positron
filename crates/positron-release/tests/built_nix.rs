//! Actual Nix functional outputs through the existing complete offline release verifier.
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use positron_release::*;
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires matching independently built Nix NAR outputs"]
fn built_nix_output_binds_sboms_provenance_signatures_and_independent_bytes() {
    let target = std::env::var("POSITRON_TEST_TARGET").unwrap();
    let first = std::fs::read(std::env::var("POSITRON_TEST_NIX").unwrap()).unwrap();
    let second = std::fs::read(std::env::var("POSITRON_TEST_NIX_REBUILD").unwrap()).unwrap();
    let narinfo =
        std::fs::read_to_string(std::env::var("POSITRON_TEST_NIX_NARINFO").unwrap()).unwrap();
    let public_key =
        std::fs::read_to_string(std::env::var("POSITRON_TEST_NIX_CACHE_KEY").unwrap()).unwrap();
    let (name, key) = public_key.trim().split_once(':').unwrap();
    let key: [u8; 32] = STANDARD.decode(key).unwrap().try_into().unwrap();
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend(key);
    let hint = support::hex(&Sha256::digest(spki));
    assert!(first.starts_with(b"\x0d\0\0\0\0\0\0\0nix-archive-1"));
    let mut fixture = support::Fixture::new();
    if let Some(binary) = std::env::var_os("POSITRON_TEST_NIX_BINARY") {
        let bytes = std::fs::read(binary).unwrap();
        let rebuilt =
            std::fs::read(std::env::var_os("POSITRON_TEST_NIX_BINARY_REBUILD").unwrap()).unwrap();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| {
                artifact.surface == Surface::NativeExecutable
                    && artifact.target == format!("nix-{target}")
            })
            .unwrap();
        fixture.replace_artifact(index, &bytes, &bytes);
        std::fs::write(
            fixture
                .rebuild
                .join(fixture.inventory.artifacts[index].payload.as_ref().unwrap()),
            rebuilt,
        )
        .unwrap();
    }
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::Nix && artifact.target == target)
        .unwrap();
    fixture.replace_artifact(index, &first, &first);
    fixture.inventory.artifacts[index]
        .publication
        .native_subject = narinfo
        .lines()
        .find_map(|line| line.strip_prefix("StorePath: "))
        .unwrap()
        .into();
    let selected = fixture.inventory.artifacts[index].file.clone();
    let registry = fixture.inventory.artifacts[index]
        .publication
        .registry
        .clone();
    let payload = fixture.inventory.artifacts[index]
        .payload
        .as_ref()
        .unwrap()
        .clone();
    std::fs::write(fixture.rebuild.join(&payload), &second).unwrap();
    let (signed, prepared) = fixture.published_with(
        |artifact, statement| {
            if artifact.file == selected {
                statement["predicate"]["buildDefinition"]["externalParameters"]["native"] =
                    serde_json::json!({"narinfo":narinfo});
            }
        },
        |_, _| {},
    );
    let trust = fixture.trust_with(|snapshot| {
        snapshot.identities.push(SigningIdentity {
            public_key: key,
            purpose: KeyPurpose::Publisher,
            not_before_unix: 100,
            expires_unix: support::keyless::NOW as u64 + 50,
        });
        snapshot
            .native_publishers
            .iter_mut()
            .find(|publisher| publisher.registry == registry)
            .unwrap()
            .policy = NativePublisherPolicy::NixCache {
            key_name: name.into(),
            key_hint: hint,
        };
    });
    verify_release(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &trust,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        &target,
        &[],
    )
    .unwrap();
    let mut tampered = signed;
    tampered[0] ^= 1;
    assert!(
        verify_release(
            &tampered,
            &prepared.inventory_bytes,
            fixture.key(),
            &trust,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &target,
            &[]
        )
        .is_err()
    );
}
