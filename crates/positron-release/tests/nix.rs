//! Nix outputs use the same complete-set release trust and reproducibility contract.
use positron_release::*;
#[path = "support/mod.rs"]
mod support;

#[test]
fn complete_release_requires_signed_nix_executable_identities() {
    let mut fixture = support::Fixture::new();
    fixture.inventory.artifacts.retain(|artifact| {
        !(artifact.surface == Surface::NativeExecutable && artifact.target.starts_with("nix-"))
    });
    assert_eq!(
        fixture.inventory.validate_complete(),
        Err(ReleaseError::PartialSet)
    );
}

#[test]
fn native_cache_proof_rejects_untrusted_fields_and_signatures() {
    let fixture = support::Fixture::new();
    for mutation in 0..10 {
        let (signed, prepared) = fixture.published_with(
            |artifact, statement| {
                if artifact.surface != Surface::Nix {
                    return;
                }
                let native =
                    &mut statement["predicate"]["buildDefinition"]["externalParameters"]["native"];
                let original = native["narinfo"].as_str().unwrap();
                let text = match mutation {
                    0 => original.replace("NarSize: 312", "NarSize: 313"),
                    1 => original.replace("sha256:08v2", "sha256:18v2"),
                    2 => original.replace("References: \n", "References: invalid\n"),
                    3 => original.replace(
                        "References: \n",
                        "References: 00000000000000000000000000000000-other\n",
                    ),
                    4 => original.replace("Sig: positron-qualification-1:", "Sig: foreign-cache:"),
                    5 => original
                        .lines()
                        .filter(|line| !line.starts_with("Sig:"))
                        .map(|line| format!("{line}\n"))
                        .collect(),
                    6 => format!("{original}NarSize: 312\n"),
                    7 => format!("{original}Unknown: value\n"),
                    8 => "a".repeat(65_537),
                    _ => original.replace(
                        "00000000000000000000000000000000-positron",
                        "10000000000000000000000000000000-positron",
                    ),
                };
                assert_ne!(text, original);
                native["narinfo"] = serde_json::Value::String(text);
            },
            |_, _| {},
        );
        assert!(
            verify_release(
                &signed,
                &prepared.inventory_bytes,
                fixture.key(),
                &fixture.trust(),
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                "linux-aarch64",
                &[]
            )
            .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn native_cache_key_revocation_and_lifetime_are_enforced() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    for expired in [false, true] {
        let trust = fixture.trust_with(|snapshot| {
            if expired {
                snapshot
                    .identities
                    .iter_mut()
                    .find(|identity| identity.public_key == support::nix_cache::key())
                    .unwrap()
                    .expires_unix = support::keyless::NOW as u64;
            } else {
                snapshot.revoked_keys.push(support::nix_cache::key());
            }
        });
        assert!(
            verify_release(
                &signed,
                &prepared.inventory_bytes,
                fixture.key(),
                &trust,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                "linux-aarch64",
                &[]
            )
            .is_err()
        );
    }
}

#[test]
fn full_release_refuses_generic_provenance_in_place_of_native_nix_cache_signature() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let trust = fixture.trust_with(|snapshot| {
        let policy = snapshot
            .native_publishers
            .iter()
            .find(|publisher| matches!(publisher.policy, NativePublisherPolicy::Keyless(_)))
            .unwrap()
            .policy
            .clone();
        for artifact in fixture
            .inventory
            .artifacts
            .iter()
            .filter(|artifact| artifact.surface == Surface::Nix)
        {
            snapshot
                .native_publishers
                .iter_mut()
                .find(|publisher| publisher.registry == artifact.publication.registry)
                .unwrap()
                .policy = policy.clone();
        }
    });
    assert_eq!(
        verify_release(
            &signed,
            &prepared.inventory_bytes,
            fixture.key(),
            &trust,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "linux-aarch64",
            &[]
        )
        .err(),
        Some(ReleaseError::Unsupported)
    );
}

#[test]
fn nix_output_requires_independently_rebuilt_functional_bytes() {
    let mut fixture = support::Fixture::new();
    fixture
        .inventory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.surface == Surface::Nix)
        .unwrap()
        .payload = None;
    assert_eq!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[],
            vec![]
        )
        .err(),
        Some(ReleaseError::Unreproducible)
    );
}

#[test]
fn nix_outputs_are_authenticated_reproduced_and_secret_screened_on_every_target() {
    let mut fixture = support::Fixture::new();
    let (signed, construction) = fixture.published();
    for target in [
        "linux-x86_64",
        "linux-aarch64",
        "macos-x86_64",
        "macos-aarch64",
    ] {
        verify_release(
            &signed,
            &construction.inventory_bytes,
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            target,
            &[],
        )
        .unwrap();
        let artifact = fixture
            .inventory
            .artifacts
            .iter()
            .find(|artifact| artifact.surface == Surface::Nix && artifact.target == target)
            .unwrap()
            .clone();
        let payload = artifact.payload.as_ref().unwrap();
        let original = std::fs::read(fixture.rebuild.join(payload)).unwrap();
        std::fs::write(
            fixture.rebuild.join(payload),
            b"different independent Nix output",
        )
        .unwrap();
        assert_eq!(
            construct_release(
                &fixture.inventory,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                &[],
                vec![]
            )
            .err(),
            Some(ReleaseError::Unreproducible)
        );
        std::fs::write(fixture.rebuild.join(payload), original).unwrap();
    }
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::Nix)
        .unwrap();
    let canary = b"nix-secret-canary-117".to_vec();
    fixture.replace_artifact(index, &canary, &canary);
    assert_eq!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[canary],
            vec![]
        )
        .err(),
        Some(ReleaseError::SecretDetected)
    );
}
