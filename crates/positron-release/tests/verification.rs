mod support;
use positron_release::*;
#[test]
fn complete_offline_set_is_authenticated_under_installed_authority() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let report = verify_release(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &fixture.trust(),
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        "linux-x86_64",
        &[],
    )
    .unwrap();
    assert_eq!(report.artifact_count(), 35);
    assert_eq!(report.trust_sequence(), 2);
    assert_eq!(
        report.manifest().manifest().version,
        fixture.inventory.version
    );
    std::fs::remove_file(
        fixture
            .root
            .join("bundle")
            .join(&fixture.inventory.artifacts[0].publication.proof),
    )
    .unwrap();
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
        Some(ReleaseError::Unavailable)
    );
}

#[test]
fn project_publisher_provenance_does_not_replace_native_trusted_publishing() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let trust = fixture.trust_with(|snapshot| snapshot.native_publishers.clear());
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
        Some(ReleaseError::Authentication)
    );
}

#[test]
fn target_metadata_requires_the_complete_published_inventory_under_current_authority() {
    use positron_kernel::release_manifest::{ArtifactRole, SignedReleaseManifest};
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let qualified = verify_target_metadata(
        &signed,
        &prepared.inventory_bytes,
        fixture.key(),
        &fixture.trust(),
    )
    .unwrap();
    assert_eq!(
        qualified.verified_manifest().digest(),
        verify_manifest(&signed, fixture.key(), &fixture.trust())
            .unwrap()
            .digest()
    );
    assert_eq!(
        qualified
            .revalidate_at(support::keyless::NOW as u64 + 51)
            .err(),
        Some(ReleaseError::StaleTrust)
    );
    let mut legacy = prepared.manifest.clone();
    legacy
        .artifacts
        .retain(|artifact| artifact.role != ArtifactRole::ReleaseInventory);
    let signature = fixture.pair.sign(&legacy.signing_message().unwrap());
    let legacy = SignedReleaseManifest::new(legacy, signature.as_ref().try_into().unwrap())
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(
        verify_manifest(&legacy, fixture.key(), &fixture.trust()).is_ok(),
        "legacy source remains authenticatable"
    );
    assert_eq!(
        verify_target_metadata(
            &legacy,
            &prepared.inventory_bytes,
            fixture.key(),
            &fixture.trust()
        )
        .err(),
        Some(ReleaseError::IdentityMismatch)
    );
    assert!(verify_target_metadata(&signed, b"{}", fixture.key(), &fixture.trust()).is_err());
    let mut staged = support::Fixture::new();
    staged.inventory.artifacts[0].publication.state = PublicationState::Staged;
    let (signed, prepared) = staged.published();
    assert_eq!(
        verify_target_metadata(
            &signed,
            &prepared.inventory_bytes,
            staged.key(),
            &staged.trust()
        )
        .err(),
        Some(ReleaseError::PartialSet)
    );
}

#[test]
fn historical_source_authorization_is_bounded_current_and_never_target_authority() {
    let fixture = support::Fixture::new();
    let (signed, prepared) = fixture.published();
    let source_only = |snapshot: &mut TrustSnapshot| {
        for identity in &mut snapshot.identities {
            if identity.purpose == KeyPurpose::Release {
                identity.purpose = KeyPurpose::InstalledSource;
            }
        }
    };
    let trust = fixture.trust_with(source_only);
    assert!(verify_installed_source_manifest(&signed, &trust).is_ok());
    assert_eq!(
        verify_manifest(&signed, fixture.key(), &trust).err(),
        Some(ReleaseError::Authentication)
    );
    assert!(
        verify_target_metadata(&signed, &prepared.inventory_bytes, fixture.key(), &trust).is_err()
    );
    let overlap = fixture.trust_with(|snapshot| {
        let mut identity = snapshot
            .identities
            .iter()
            .find(|identity| identity.purpose == KeyPurpose::Release)
            .unwrap()
            .clone();
        identity.purpose = KeyPurpose::InstalledSource;
        snapshot.identities.push(identity);
    });
    assert!(
        verify_installed_source_manifest(&signed, &overlap).is_ok(),
        "overlapping roles are one identity"
    );
    for expiry in [true, false] {
        let trust = fixture.trust_with(|snapshot| {
            source_only(snapshot);
            for identity in &mut snapshot.identities {
                if identity.purpose == KeyPurpose::InstalledSource {
                    if expiry {
                        identity.expires_unix = support::keyless::NOW as u64;
                    } else {
                        identity.not_before_unix = support::keyless::NOW as u64 + 1;
                    }
                }
            }
        });
        assert_eq!(
            verify_installed_source_manifest(&signed, &trust).err(),
            Some(ReleaseError::Authentication)
        );
    }
    for artifact in [false, true] {
        let trust = fixture.trust_with(|snapshot| {
            source_only(snapshot);
            if artifact {
                snapshot
                    .revoked_artifacts
                    .push(prepared.manifest.artifacts[0].sha256);
            } else {
                snapshot.revoked_manifests.push(
                    verify_installed_source_manifest(&signed, &fixture.trust())
                        .unwrap()
                        .digest(),
                );
            }
        });
        assert_eq!(
            verify_installed_source_manifest(&signed, &trust).err(),
            Some(ReleaseError::Revoked)
        );
    }
    let trust = fixture.trust_with(|snapshot| {
        source_only(snapshot);
        snapshot.revoked_keys.push(fixture.key());
    });
    assert_eq!(
        verify_installed_source_manifest(&signed, &trust).err(),
        Some(ReleaseError::Authentication)
    );
    assert!(verify_installed_source_manifest(b"invalid", &fixture.trust()).is_err());
}
