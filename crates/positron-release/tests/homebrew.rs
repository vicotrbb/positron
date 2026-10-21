//! Formula output is derived from the release authority, not a second package manifest.
use positron_release::*;
#[path = "support/mod.rs"]
mod support;

#[test]
fn formula_pins_both_native_archives_and_the_upstream_source() {
    let fixture = support::Fixture::new();
    let formula = homebrew_formula(&fixture.inventory).unwrap();
    assert_eq!(formula, homebrew_formula(&fixture.inventory).unwrap());
    for target in ["macos-aarch64", "macos-x86_64"] {
        let artifact = fixture
            .inventory
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.surface == Surface::NativeArchive && artifact.target == target
            })
            .unwrap();
        assert!(formula.contains(&format!(
            "https://github.com/vicotrbb/positron/releases/download/v1.0.0/{}",
            artifact.file
        )));
        assert!(
            formula.contains(&support::hex(
                &fixture
                    .inventory
                    .file(&artifact.file)
                    .unwrap()
                    .identity
                    .sha256
            ))
        );
    }
    assert!(formula.contains(&fixture.inventory.source_commit));
    assert!(formula.contains("depends_on macos: :sequoia"));
    assert!(formula.contains("stop_timeout 65"));
    assert!(formula.contains("require_root false"));
    assert!(!formula.contains("--init-if-empty"));
    assert!(formula.contains("bin.install \"bin/positron\""));
}

#[test]
fn formula_refuses_missing_or_ambiguous_targets_and_ruby_injection() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| {
            artifact.surface == Surface::NativeArchive && artifact.target == "macos-aarch64"
        })
        .unwrap();
    let archive = fixture.inventory.artifacts.remove(index);
    assert_eq!(
        homebrew_formula(&fixture.inventory),
        Err(ReleaseError::PartialSet)
    );
    fixture.inventory.artifacts.push(archive.clone());
    let mut duplicate = archive;
    duplicate.file = fixture.add("duplicate-archive".into(), b"duplicate");
    duplicate.publication.proof = "duplicate-proof".into();
    duplicate.publication.native_subject = "duplicate-subject".into();
    fixture.inventory.artifacts.push(duplicate);
    assert_eq!(
        homebrew_formula(&fixture.inventory),
        Err(ReleaseError::IdentityMismatch)
    );
    fixture.inventory.artifacts.pop();
    fixture.inventory.source_commit = "#{system('unexpected')}".into();
    assert_eq!(
        homebrew_formula(&fixture.inventory),
        Err(ReleaseError::Invalid)
    );
}

#[test]
fn full_release_refuses_a_formula_that_is_not_bound_to_its_native_archives() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::Homebrew)
        .unwrap();
    fixture.replace_artifact(
        index,
        b"class Positron < Formula\nend\n",
        b"class Positron < Formula\nend\n",
    );
    // Checksummed formula bytes must still describe the selected archive identities.
    let result = construct_release(
        &fixture.inventory,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        &[],
        vec![],
    );
    assert!(matches!(result, Err(ReleaseError::IdentityMismatch)));
}

#[test]
fn generated_formula_requires_authenticated_tap_revision_rebuild_and_secret_screening() {
    let mut fixture = support::Fixture::new();
    let artifact = fixture
        .inventory
        .artifacts
        .iter()
        .find(|artifact| artifact.surface == Surface::Homebrew)
        .unwrap()
        .clone();
    let (signed, construction) = fixture.published();
    let verify = |fixture: &support::Fixture, signed: &[u8], construction: &ReleaseConstruction| {
        verify_release(
            signed,
            &construction.inventory_bytes,
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "macos-aarch64",
            &[],
        )
    };
    verify(&fixture, &signed, &construction).unwrap();
    fixture
        .inventory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.surface == Surface::Homebrew)
        .unwrap()
        .publication
        .native_revision = Some(fixture.inventory.source_commit.clone());
    let (signed, construction) = fixture.published();
    assert!(
        verify(&fixture, &signed, &construction).is_err(),
        "upstream revision cannot replace actual tap revision"
    );
    let payload = artifact.payload.as_ref().unwrap();
    std::fs::write(
        fixture.rebuild.join(payload),
        b"different independent formula",
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
    let fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::Homebrew)
        .unwrap();
    let formula = homebrew_formula(&fixture.inventory).unwrap();
    let canary = b"formula-secret-canary-116".to_vec();
    let mut changed = formula.into_bytes();
    changed.extend(&canary);
    let mut fixture = fixture;
    fixture.replace_artifact(index, &changed, &changed);
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
