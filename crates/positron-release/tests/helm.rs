//! Helm is a same-image standalone distribution authenticated by Release Trust.
use positron_release::*;
#[path = "support/mod.rs"]
mod support;

#[test]
fn chart_is_deterministic_and_pins_the_canonical_image_and_configuration() {
    let fixture = support::Fixture::new();
    let bytes = helm_chart(&fixture.inventory).unwrap();
    assert_eq!(bytes, helm_chart(&fixture.inventory).unwrap());
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
    let mut files = std::collections::BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        let mut content = String::new();
        std::io::Read::read_to_string(&mut entry, &mut content).unwrap();
        files.insert(path, content);
    }
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .find(|a| a.surface == Surface::OciIndex)
        .unwrap();
    let digest = support::hex(&fixture.inventory.file(&index.file).unwrap().identity.sha256);
    let values = &files["positron/values.yaml"];
    assert!(values.contains(&format!("ghcr.io/vicotrbb/positron@sha256:{digest}")));
    assert!(values.contains("terminationGracePeriodSeconds: 3605"));
    assert!(values.contains("schema_version = 1"));
    assert!(files.contains_key("positron/templates/statefulset.yaml"));
    assert!(files.contains_key("positron/templates/maintenance.yaml"));
}

#[test]
fn release_refuses_a_changed_chart_even_with_matching_declared_checksums() {
    let mut fixture = support::Fixture::new();
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::Helm)
        .unwrap();
    let bytes = helm_chart(&fixture.inventory).unwrap();
    fixture.replace_artifact(position, &bytes, &bytes);
    construct_release(
        &fixture.inventory,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        &[],
        vec![],
    )
    .unwrap();
    fixture.replace_artifact(
        position,
        b"not the generated chart",
        b"not the generated chart",
    );
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
fn chart_refuses_missing_ambiguous_and_invalid_image_authority() {
    let mut fixture = support::Fixture::new();
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::OciIndex)
        .unwrap();
    let index = fixture.inventory.artifacts.remove(position);
    assert_eq!(
        helm_chart(&fixture.inventory),
        Err(ReleaseError::PartialSet)
    );
    fixture.inventory.artifacts.push(index.clone());
    let mut duplicate = index;
    duplicate.file = fixture.add("duplicate-helm-index".into(), b"index");
    duplicate.publication.proof = "different-proof".into();
    duplicate.publication.native_subject = "different-subject".into();
    fixture.inventory.artifacts.push(duplicate);
    assert_eq!(
        helm_chart(&fixture.inventory),
        Err(ReleaseError::IdentityMismatch)
    );
    fixture.inventory.source_commit = "YAML: injection".into();
    assert_eq!(helm_chart(&fixture.inventory), Err(ReleaseError::Invalid));
}

#[test]
fn chart_requires_independent_payload_and_refuses_changed_rebuild() {
    let mut fixture = support::Fixture::new();
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::Helm)
        .unwrap();
    let payload = fixture.inventory.artifacts[position]
        .payload
        .take()
        .unwrap();
    assert_eq!(
        fixture.inventory.validate_complete(),
        Err(ReleaseError::Unreproducible)
    );
    fixture.inventory.artifacts[position].payload = Some(payload.clone());
    std::fs::write(
        fixture.rebuild.join(payload),
        b"different independently built chart",
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
}

#[test]
#[ignore = "constructs an unsigned runtime-only chart fixture when explicitly requested"]
fn prepare_runtime_helm_fixture() {
    let Some(output) = std::env::var_os("POSITRON_TEST_HELM_CHART_OUT") else {
        return;
    };
    let mut fixture = support::Fixture::new();
    fixture.inventory.source_commit = std::env::var("POSITRON_TEST_SOURCE_COMMIT").unwrap();
    let index = std::fs::read(std::env::var_os("POSITRON_TEST_HELM_INDEX_FILE").unwrap()).unwrap();
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::OciIndex)
        .unwrap();
    fixture.replace_artifact(position, &index, &index);
    let chart = helm_chart(&fixture.inventory).unwrap();
    write_release_file(std::path::Path::new(&output), &chart).unwrap();
}
