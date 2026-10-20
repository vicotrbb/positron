//! Direct Debian downloads use native workflow evidence, not an APT repository claim.
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use positron_release::*;
use serde_json::json;

fn verify(
    fixture: &support::Fixture,
    signed: &[u8],
    prepared: &ReleaseConstruction,
    trust: &VerifiedTrust,
) -> Result<ReleaseVerificationReport, ReleaseError> {
    verify_release(
        signed,
        &prepared.inventory_bytes,
        fixture.key(),
        trust,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-x86_64",
        &[],
    )
}
#[test]
fn real_dpkg_deb_downloads_bind_both_targets_to_native_workflow_and_final_manifest() {
    let fixture = support::Fixture::new();
    for artifact in fixture
        .inventory
        .artifacts
        .iter()
        .filter(|artifact| artifact.surface == Surface::Debian)
    {
        let bytes = std::fs::read(fixture.root.join("bundle").join(&artifact.file)).unwrap();
        assert!(bytes.starts_with(b"!<arch>\n"));
    }
    let (signed, prepared) = fixture.published();
    assert!(verify(&fixture, &signed, &prepared, &fixture.trust()).is_ok());
}
#[test]
fn direct_debian_downloads_require_both_native_attestation_and_project_publication_proofs() {
    for mode in 0..4 {
        let fixture = support::Fixture::new();
        let (signed, prepared) = fixture.published_with(
            |artifact, statement| {
                if artifact.surface != Surface::Debian {
                    return;
                }
                let native =
                    &mut statement["predicate"]["buildDefinition"]["externalParameters"]["native"];
                match mode {
                    0 => *native = serde_json::Value::Null,
                    1 => {
                        native["bundle"]["dsseEnvelope"]["signatures"][0]["sig"] =
                            json!(STANDARD.encode([0; 64]))
                    },
                    _ => {},
                }
            },
            |_, _| {},
        );
        let receipt = fixture
            .inventory
            .artifacts
            .iter()
            .find(|artifact| artifact.surface == Surface::Debian)
            .unwrap()
            .publication
            .proof
            .clone();
        let path = fixture.root.join("bundle").join(receipt);
        if mode == 2 {
            std::fs::remove_file(path).unwrap();
        } else if mode == 3 {
            let mut proof: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            proof["dsseEnvelope"]["signatures"][0]["sig"] = json!(STANDARD.encode([0; 64]));
            std::fs::write(path, serde_json::to_vec(&proof).unwrap()).unwrap();
        }
        assert!(
            verify(&fixture, &signed, &prepared, &fixture.trust()).is_err(),
            "proof mutation {mode}"
        );
    }
}
#[test]
fn direct_debian_proofs_bind_exact_package_manifest_source_and_installed_native_trust() {
    for mode in 0..5 {
        let fixture = support::Fixture::new();
        let (signed, prepared) = fixture.published_with_native(
            |artifact, statement| {
                if artifact.surface == Surface::Debian && mode < 2 {
                    statement["subject"][mode]["digest"]["sha256"] = json!("00".repeat(32));
                }
            },
            |_, _| {},
            |artifact, statement| {
                if artifact.surface != Surface::Debian {
                    return;
                }
                if mode == 2 {
                    statement["subject"][0]["digest"]["sha256"] = json!("00".repeat(32));
                } else if mode == 3 {
                    statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]
                        ["gitCommit"] = json!("00".repeat(20));
                }
            },
        );
        let registry = &fixture
            .inventory
            .artifacts
            .iter()
            .find(|artifact| artifact.surface == Surface::Debian)
            .unwrap()
            .publication
            .registry;
        let trust = fixture.trust_with(|snapshot| {
            if mode == 4 {
                let publisher = snapshot
                    .native_publishers
                    .iter_mut()
                    .find(|publisher| &publisher.registry == registry)
                    .unwrap();
                let NativePublisherPolicy::Keyless(policy) = &mut publisher.policy else {
                    panic!("native workflow fixture");
                };
                policy.trusted_root_sha256 = [8; 32];
            }
        });
        assert!(
            verify(&fixture, &signed, &prepared, &trust).is_err(),
            "identity mutation {mode}"
        );
    }
}
