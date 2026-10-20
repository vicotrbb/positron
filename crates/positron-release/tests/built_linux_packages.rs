//! Bind actual native constructions through the existing complete release verifier.
mod support;
use positron_release::*;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires actual version 1.0.0 Debian/RPM packages, independent constructions, and private fixture RPM public certificate"]
fn built_packages_bind_final_bytes_native_proofs_sboms_and_independent_payloads() {
    let target = std::env::var("POSITRON_TEST_TARGET").unwrap();
    let certificate =
        std::fs::read_to_string(std::env::var("POSITRON_TEST_RPM_KEY").unwrap()).unwrap();
    let native_root = json!({"public_key":certificate});
    let registry = "https://github.com/vicotrbb/positron/releases/private-package-qualification";
    let mut fixture = support::Fixture::new();
    for (surface, first, second) in [
        (
            Surface::Debian,
            "POSITRON_TEST_DEB",
            "POSITRON_TEST_DEB_REBUILD",
        ),
        (
            Surface::Rpm,
            "POSITRON_TEST_RPM",
            "POSITRON_TEST_RPM_REBUILD",
        ),
    ] {
        let bytes = std::fs::read(std::env::var(first).unwrap()).unwrap();
        let rebuilt = std::fs::read(std::env::var(second).unwrap()).unwrap();
        let payload = if surface == Surface::Rpm {
            rpm_functional_payload(&bytes).unwrap()
        } else {
            &bytes
        };
        let independent = if surface == Surface::Rpm {
            rpm_functional_payload(&rebuilt).unwrap()
        } else {
            &rebuilt
        };
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == surface && artifact.target == target)
            .unwrap();
        fixture.replace_artifact(index, &bytes, payload);
        let artifact = &mut fixture.inventory.artifacts[index];
        std::fs::write(
            fixture.rebuild.join(artifact.payload.as_ref().unwrap()),
            independent,
        )
        .unwrap();
        if surface == Surface::Rpm {
            artifact.publication.registry = registry.into();
        }
    }
    let (signed, prepared) = fixture.published_with(
        |artifact, statement| {
            if artifact.surface == Surface::Rpm && artifact.target == target {
                statement["predicate"]["buildDefinition"]["externalParameters"]["native"] =
                    json!({"trustedRoot":native_root});
            }
        },
        |_, _| {},
    );
    let trust = fixture.trust_with(|snapshot| {
        snapshot
            .native_publishers
            .iter_mut()
            .find(|publisher| publisher.registry == registry)
            .unwrap()
            .policy = NativePublisherPolicy::Rpm {
            trusted_root_sha256: Sha256::digest(serde_json::to_vec(&native_root).unwrap()).into(),
        };
    });
    let result = verify_release(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &trust,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        &target,
        &[],
    );
    assert!(result.is_ok(), "{result:?}");
}
