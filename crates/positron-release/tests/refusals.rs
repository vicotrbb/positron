mod support;
use positron_release::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

#[test]
fn construction_refuses_partial_target_input_and_unreproducible_sets() {
    let changes: [fn(&mut ReleaseInventory); 11] = [
        |i| {
            i.artifacts.pop();
        },
        |i| {
            i.artifacts[0].target = "windows-x86_64".into();
        },
        |i| {
            i.inputs.pop();
        },
        |i| {
            i.inputs[0].version = "latest".into();
            i.inputs[0].file = "missing".into();
        },
        |i| i.inputs.push(i.inputs[0].clone()),
        |i| i.files.push(i.files[0].clone()),
        |i| i.files[0].identity.sha256 = [0; 32],
        |i| i.source_commit = "a".repeat(41),
        |i| i.artifacts[0].payload = None,
        |i| i.artifacts[0].publication.immutable_identity = "latest".into(),
        |i| i.artifacts[0].publication.registry = "https://host/path?token=secret".into(),
    ];
    for change in changes {
        let mut fixture = support::Fixture::new();
        change(&mut fixture.inventory);
        assert!(
            construct_release(
                &fixture.inventory,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                &[],
                vec![]
            )
            .is_err()
        );
    }
}
#[test]
fn independently_rebuilt_drift_and_real_file_corruption_are_refused() {
    let fixture = support::Fixture::new();
    let payload = fixture.inventory.artifacts[0].payload.as_ref().unwrap();
    std::fs::write(fixture.rebuild.join(payload), b"independent build drift").unwrap();
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
    let id = &fixture.inventory.files[0].id;
    std::fs::write(fixture.root.join("bundle").join(id), b"corrupt input").unwrap();
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
fn current_revocation_covers_keys_manifests_and_any_inventory_file() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let manifest = verify_manifest(&signed, fixture.key(), &fixture.trust()).unwrap();
    for kind in 0..3 {
        let trust = fixture.trust_with(|snapshot| match kind {
            0 => snapshot.revoked_keys.push(fixture.key()),
            1 => snapshot.revoked_manifests.push(manifest.digest()),
            _ => snapshot
                .revoked_artifacts
                .push(fixture.inventory.files[0].identity.sha256),
        });
        assert_eq!(
            verify_release(
                &signed,
                &prepared.inventory_bytes,
                fixture.key(),
                &trust,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                "linux-x86_64",
                &[]
            )
            .err(),
            Some(ReleaseError::Revoked)
        );
    }
}
#[test]
fn authorized_root_rotation_selects_a_delegated_release_signer_without_changing_manifest_identity()
{
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let original = verify_manifest(&signed, fixture.key(), &fixture.trust()).unwrap();
    let successor = Ed25519KeyPair::from_seed_unchecked(&[18; 32]).unwrap();
    let public = successor.public_key().as_ref().try_into().unwrap();
    let trust = fixture.trust_with(|snapshot| {
        snapshot
            .identities
            .retain(|identity| identity.purpose != KeyPurpose::Release);
        snapshot.identities.push(SigningIdentity {
            public_key: public,
            purpose: KeyPurpose::Release,
            not_before_unix: 100,
            expires_unix: support::keyless::NOW as u64 + 50,
        });
    });
    let signature = successor.sign(&prepared.signing_message().unwrap());
    let signed = positron_kernel::release_manifest::SignedReleaseManifest::new(
        prepared.manifest,
        signature.as_ref().try_into().unwrap(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    assert_eq!(
        verify_manifest(&signed, public, &trust).unwrap().digest(),
        original.digest()
    );
    assert_eq!(
        verify_manifest(&signed, fixture.key(), &trust).err(),
        Some(ReleaseError::Authentication)
    );
}
#[test]
fn unsigned_mismatched_stale_unsupported_and_unpublished_sets_are_refused() {
    let fixture = support::Fixture::new();
    let (mut signed, prepared) = fixture.published();
    signed[0] ^= 1;
    assert_eq!(
        verify_release(
            &signed,
            &prepared.inventory_bytes,
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "linux-x86_64",
            &[]
        )
        .err(),
        Some(ReleaseError::Authentication)
    );
    signed[0] ^= 1;
    assert_eq!(
        verify_release(
            &signed,
            b"{}",
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "linux-x86_64",
            &[]
        )
        .err(),
        Some(ReleaseError::IdentityMismatch)
    );
    assert_eq!(
        verify_release(
            &signed,
            &prepared.inventory_bytes,
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "windows-x86_64",
            &[]
        )
        .err(),
        Some(ReleaseError::Unsupported)
    );
    for mutate in [
        |i: &mut ReleaseInventory| i.security_support.expires_unix = 149,
        |i: &mut ReleaseInventory| i.security_support.upgrade_paths.clear(),
        |i: &mut ReleaseInventory| i.artifacts[0].publication.state = PublicationState::Staged,
    ] {
        let mut fixture = support::Fixture::new();
        mutate(&mut fixture.inventory);
        let (signed, prepared) = fixture.published();
        assert!(
            verify_release(
                &signed,
                &prepared.inventory_bytes,
                fixture.key(),
                &fixture.trust(),
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                "linux-x86_64",
                &[]
            )
            .is_err()
        );
    }
}

#[test]
fn fresh_root_metadata_controls_the_current_and_previous_minor_support_window() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let previous_minor = fixture.trust_with(|snapshot| snapshot.current_version.minor = 1);
    verify_release(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &previous_minor,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-x86_64",
        &[],
    )
    .unwrap();
    let unsupported = fixture.trust_with(|snapshot| snapshot.current_version.minor = 2);
    assert!(verify_manifest(&signed, fixture.key(), &unsupported).is_ok());
    assert_eq!(
        verify_release(
            &signed,
            &prepared.inventory_bytes,
            fixture.key(),
            &unsupported,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "linux-x86_64",
            &[]
        )
        .err(),
        Some(ReleaseError::Unsupported)
    );
}
