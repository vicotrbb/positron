use positron_release::{
    InstalledProjectTrustRoot, KeyPurpose, ReleaseError, SigningIdentity, TrustSnapshot,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

#[test]
fn offline_trust_requires_root_authentication_freshness_and_installed_sequence() {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
    let key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
    let trust = InstalledProjectTrustRoot {
        public_key: key,
        minimum_sequence: 2,
    };
    let snapshot = TrustSnapshot {
        format: 1,
        sequence: 2,
        current_version: positron_kernel::release_manifest::ProductVersion {
            major: 1,
            minor: 1,
            patch: 0,
        },
        issued_unix: 100,
        expires_unix: 200,
        identities: vec![SigningIdentity {
            public_key: key,
            purpose: KeyPurpose::Release,
            not_before_unix: 100,
            expires_unix: 200,
        }],
        native_publishers: vec![],
        revoked_keys: vec![],
        revoked_manifests: vec![],
        revoked_artifacts: vec![],
    };
    let signed = snapshot.sign(&pair).unwrap();
    assert_eq!(trust.verify(&signed, 150).unwrap().sequence(), 2);
    assert_eq!(
        trust.verify(&signed, 201).err(),
        Some(ReleaseError::StaleTrust)
    );
    assert_eq!(
        trust.verify(&signed, 99).err(),
        Some(ReleaseError::StaleTrust)
    );
    let newer = InstalledProjectTrustRoot {
        minimum_sequence: 3,
        ..trust
    };
    assert_eq!(
        newer.verify(&signed, 150).err(),
        Some(ReleaseError::StaleTrust)
    );
    let foreign = InstalledProjectTrustRoot {
        public_key: [5; 32],
        ..trust
    };
    assert_eq!(
        foreign.verify(&signed, 150).err(),
        Some(ReleaseError::Authentication)
    );
}

#[test]
fn installed_trust_never_falls_back_to_a_raw_key_or_an_invalid_document() {
    use positron_release::InstalledReleaseTrust;
    for bytes in [vec![17; 32], b"{}".to_vec(), b"{\"format\":99}".to_vec()] {
        assert!(InstalledReleaseTrust::from_bytes(&bytes).is_err());
    }
}
