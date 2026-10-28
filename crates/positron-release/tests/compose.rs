//! Compose is a same-image deployment bound to the canonical OCI identity.
use positron_release::*;
#[path = "support/mod.rs"]
mod support;

#[test]
fn compose_pins_the_inventory_index_and_explicit_runtime_boundaries() {
    let fixture = support::Fixture::new();
    let compose = compose_deployment(&fixture.inventory).unwrap();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .find(|a| a.surface == Surface::OciIndex)
        .unwrap();
    let digest = support::hex(&fixture.inventory.file(&index.file).unwrap().identity.sha256);
    assert!(compose.contains(&format!("ghcr.io/vicotrbb/positron@sha256:{digest}")));
    assert!(compose.contains("read_only: true"));
    assert!(compose.contains("stop_grace_period: 3605s"));
    assert!(compose.contains("/var/lib/positron-secrets"));
    assert!(!compose.contains("latest"));
    assert_eq!(compose, compose_deployment(&fixture.inventory).unwrap());
}

#[test]
fn compose_refuses_missing_ambiguous_or_invalid_index_identity() {
    let mut fixture = support::Fixture::new();
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::OciIndex)
        .unwrap();
    let index = fixture.inventory.artifacts.remove(position);
    assert_eq!(
        compose_deployment(&fixture.inventory),
        Err(ReleaseError::PartialSet)
    );
    fixture.inventory.artifacts.push(index.clone());
    let mut duplicate = index;
    duplicate.file = fixture.add("duplicate-index".into(), b"index");
    duplicate.publication.proof = "different-proof".into();
    duplicate.publication.native_subject = "different-subject".into();
    fixture.inventory.artifacts.push(duplicate);
    assert_eq!(
        compose_deployment(&fixture.inventory),
        Err(ReleaseError::IdentityMismatch)
    );
    fixture.inventory.source_commit = "untrusted YAML: injection".into();
    assert_eq!(
        compose_deployment(&fixture.inventory),
        Err(ReleaseError::Invalid)
    );
}

#[test]
fn compose_release_requires_exact_generated_bytes_and_independent_payload() {
    let mut fixture = support::Fixture::new();
    let (signed, construction) = fixture.published();
    verify_release(
        &signed,
        &construction.inventory_bytes,
        fixture.key(),
        &fixture.trust(),
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-aarch64",
        &[],
    )
    .unwrap();
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::Compose)
        .unwrap();
    let compose = compose_deployment(&fixture.inventory).unwrap();
    let changed = compose.replace("read_only: true", "read_only: false");
    fixture.replace_artifact(position, changed.as_bytes(), changed.as_bytes());
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
    fixture.replace_artifact(position, compose.as_bytes(), compose.as_bytes());
    let payload = fixture.inventory.artifacts[position]
        .payload
        .as_ref()
        .unwrap();
    std::fs::write(
        fixture.rebuild.join(payload),
        b"changed independent deployment",
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
fn compose_cannot_omit_independent_payload_or_hide_secrets() {
    let mut fixture = support::Fixture::new();
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::Compose)
        .unwrap();
    fixture.inventory.artifacts[position].payload = None;
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
    let mut fixture = support::Fixture::new();
    let canary = b"compose-secret-canary-119".to_vec();
    let mut changed = compose_deployment(&fixture.inventory).unwrap().into_bytes();
    changed.extend(&canary);
    fixture.replace_artifact(position, &changed, &changed);
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

#[test]
fn generated_stop_allowance_covers_every_accepted_native_deadline_and_rejects_shortening() {
    let mut fixture = support::Fixture::new();
    let compose = compose_deployment(&fixture.inventory).unwrap();
    let grace: u32 = compose
        .lines()
        .find_map(|line| line.strip_prefix("    stop_grace_period: "))
        .unwrap()
        .trim_end_matches('s')
        .parse()
        .unwrap();
    for seconds in ["120", "3600"] {
        let inputs = positron_config::ConfigurationInputs::try_from_sources(
            None,
            [] as [(&str, &str); 0],
            [("runtime.shutdown_grace_seconds", seconds)],
        )
        .unwrap();
        let accepted = positron_config::resolve(inputs).unwrap();
        assert!(
            grace >= u32::from(accepted.shutdown_grace_seconds()) + 5,
            "generated Compose must cover accepted {seconds}s deadline plus safety margin"
        );
    }
    let inputs = positron_config::ConfigurationInputs::try_from_sources(
        None,
        [] as [(&str, &str); 0],
        [("runtime.shutdown_grace_seconds", "3601")],
    )
    .unwrap();
    assert!(positron_config::resolve(inputs).is_err());
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::Compose)
        .unwrap();
    let shortened = compose.replace(
        &format!("stop_grace_period: {grace}s"),
        "stop_grace_period: 65s",
    );
    fixture.replace_artifact(position, shortened.as_bytes(), shortened.as_bytes());
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
