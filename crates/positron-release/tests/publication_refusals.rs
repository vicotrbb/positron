mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use positron_release::*;
use serde_json::{Value, json};
fn verify(
    fixture: &support::Fixture,
    signed: &[u8],
    prepared: &ReleaseConstruction,
) -> Result<ReleaseVerificationReport, ReleaseError> {
    verify_release(
        signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &fixture.trust(),
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-x86_64",
        &[],
    )
}
#[test]
fn correctly_signed_and_logged_publication_claims_must_match_registry_artifact_and_manifest() {
    for pointer in [
        "/_type",
        "/predicateType",
        "/predicate/buildDefinition/buildType",
        "/predicate/buildDefinition/externalParameters/registry",
        "/predicate/buildDefinition/externalParameters/immutable_identity",
        "/subject/0/digest/sha256",
        "/subject/1/digest/sha256",
    ] {
        let fixture = support::Fixture::new();
        let (signed, prepared) = fixture.published_with(
            |_, statement| *statement.pointer_mut(pointer).unwrap() = json!("mismatched"),
            |_, _| {},
        );
        assert_eq!(
            verify(&fixture, &signed, &prepared).err(),
            Some(ReleaseError::IdentityMismatch),
            "{pointer}"
        );
    }
}
#[test]
fn an_authenticated_log_leaf_must_cover_the_exact_dsse_payload_signature_and_verifier() {
    for pointer in [
        "/kind",
        "/apiVersion",
        "/spec/payloadHash/algorithm",
        "/spec/payloadHash/value",
        "/spec/signatures/0/signature",
        "/spec/signatures/0/verifier",
    ] {
        let fixture = support::Fixture::new();
        let (signed, prepared) = fixture.published_with(
            |_, _| {},
            |_, body| *body.pointer_mut(pointer).unwrap() = json!("mismatched"),
        );
        assert!(verify(&fixture, &signed, &prepared).is_err(), "{pointer}");
    }
}
#[test]
fn native_oci_signature_claims_are_verified_even_when_outer_provenance_is_valid() {
    for pointer in [
        "/critical/type",
        "/critical/identity/docker-reference",
        "/critical/image/docker-manifest-digest",
        "/optional/positron-release-manifest",
    ] {
        let fixture = support::Fixture::new();
        let (signed, prepared) = fixture.published_with(
            |artifact, statement| {
                if artifact.surface != Surface::OciImage {
                    return;
                }
                let proof = statement
                    .pointer_mut("/predicate/buildDefinition/externalParameters/cosign")
                    .unwrap();
                let mut payload: Value = serde_json::from_slice(
                    &STANDARD.decode(proof["payload"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                *payload.pointer_mut(pointer).unwrap() = json!("mismatched");
                let bytes = serde_json::to_vec(&payload).unwrap();
                proof["payload"] = json!(STANDARD.encode(&bytes));
                proof["signature"] = json!(STANDARD.encode(fixture.pair.sign(&bytes).as_ref()));
            },
            |_, _| {},
        );
        assert_eq!(
            verify(&fixture, &signed, &prepared).err(),
            Some(ReleaseError::IdentityMismatch),
            "{pointer}"
        );
    }
}
#[test]
fn malformed_unsupported_untrusted_and_missing_bundle_proofs_are_refused() {
    let changes: [(&str, Value); 14] = [
        ("/mediaType", json!("unknown")),
        (
            "/verificationMaterial/publicKey/hint",
            json!("uninstalled-key"),
        ),
        ("/dsseEnvelope/payloadType", json!("text/plain")),
        ("/dsseEnvelope/payload", json!("%%%")),
        ("/dsseEnvelope/signatures", json!([])),
        (
            "/dsseEnvelope/signatures/0/sig",
            json!(STANDARD.encode([0; 64])),
        ),
        ("/verificationMaterial/tlogEntries", json!([])),
        (
            "/verificationMaterial/tlogEntries/0/kindVersion/version",
            json!("99"),
        ),
        (
            "/verificationMaterial/tlogEntries/0/logId/keyId",
            json!(STANDARD.encode([0; 32])),
        ),
        (
            "/verificationMaterial/tlogEntries/0/integratedTime",
            json!("9999999999"),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionPromise/signedEntryTimestamp",
            json!(STANDARD.encode([0; 64])),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/treeSize",
            json!("0"),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/rootHash",
            json!(STANDARD.encode([0; 32])),
        ),
        (
            "/verificationMaterial/tlogEntries/0/inclusionProof/checkpoint/envelope",
            json!("unsigned checkpoint"),
        ),
    ];
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let path = fixture
        .root
        .join("bundle")
        .join(&fixture.inventory.artifacts[0].publication.proof);
    let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (pointer, value) in changes {
        let mut bundle = original.clone();
        *bundle.pointer_mut(pointer).unwrap() = value;
        std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        assert!(verify(&fixture, &signed, &prepared).is_err(), "{pointer}");
    }
}
