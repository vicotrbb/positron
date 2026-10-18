use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
fn fixture() -> ReleaseManifest {
    let format = FormatCompatibility {
        readable_epochs: vec![2],
        writable_epoch: 2,
        migrations: vec![],
    };
    ReleaseManifest {
        version: ProductVersion {
            major: 0,
            minor: 1,
            patch: 0,
        },
        upgrade_from: vec![],
        source_commit: "9fd68fd9eaa72ed45e070412d30656fda1277d79".into(),
        artifacts: [
            ArtifactRole::NativeExecutable,
            ArtifactRole::Schema,
            ArtifactRole::CompatibilityManifest,
            ArtifactRole::Sbom,
            ArtifactRole::Provenance,
        ]
        .into_iter()
        .map(|role| ReleaseArtifact {
            role,
            platform: "linux-x86_64".into(),
            sha256: [9; 32],
            size: 42,
            complete: true,
        })
        .collect(),
        compatibility: ReleaseCompatibility {
            config_schema: 1,
            previous_config_schema: None,
            persistent: format.clone(),
            backup: format,
            receiver: [6; 32],
            api: [1; 32],
            query: [2; 32],
            schema: [3; 32],
            crd: [4; 32],
            operator: [5; 32],
        },
    }
}
#[test]
fn rejects_absent_independent_claim() {
    let mut manifest = fixture();
    manifest.compatibility.receiver = [0; 32];
    assert_eq!(
        manifest.canonical_bytes(),
        Err(ReleaseManifestError::Invalid)
    );
}
#[test]
fn pinned_root_authenticates_exact_canonical_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).map_err(|_| "test key")?;
    let root = ProjectTrustRoot::new(pair.public_key().as_ref().try_into()?);
    let manifest = fixture();
    let mut message = DOMAIN.to_vec();
    message.extend(manifest.canonical_bytes()?);
    let signed = SignedReleaseManifest::new(manifest, pair.sign(&message).as_ref().try_into()?)?;
    let wire = signed.to_bytes()?;
    let verified = SignedReleaseManifest::from_bytes(&wire)?.verify(&root)?;
    assert_eq!(verified.signed_bytes(), wire);
    assert_eq!(
        verified.manifest().version,
        ProductVersion::parse_exact("0.1.0")?
    );
    assert_eq!(
        signed.verify(&ProjectTrustRoot::new([18; 32])).err(),
        Some(ReleaseManifestError::AuthenticationFailed)
    );
    let foreign = SignedReleaseManifest::new(
        fixture(),
        pair.sign(&fixture().canonical_bytes()?)
            .as_ref()
            .try_into()?,
    )?;
    assert_eq!(
        foreign.verify(&root).err(),
        Some(ReleaseManifestError::AuthenticationFailed)
    );
    assert_ne!(verified.digest(), [0; 32]);
    let mut tampered = wire;
    let last = tampered.last_mut().ok_or("empty wire")?;
    *last = b' ';
    assert!(SignedReleaseManifest::from_bytes(&tampered).is_err());
    Ok(())
}
#[test]
fn rejects_incomplete_inventory_and_unbounded_wire() {
    let mut manifest = fixture();
    manifest.artifacts.pop();
    assert!(manifest.canonical_bytes().is_err());
    assert_eq!(
        SignedReleaseManifest::from_bytes(&vec![0; MAX_RELEASE_MANIFEST_BYTES + 65]).err(),
        Some(ReleaseManifestError::LimitExceeded)
    );
    for value in ["1.0", "01.2.3", "1.2.3.4", "1.2.3-pre", "+1.2.3"] {
        assert!(ProductVersion::parse_exact(value).is_err());
    }
}
#[test]
fn untrusted_input_rejects_ambiguous_claims_and_duplicate_fields()
-> Result<(), Box<dyn std::error::Error>> {
    for mutate in [
        |m: &mut ReleaseManifest| m.artifacts.clear(),
        |m: &mut ReleaseManifest| m.artifacts = vec![m.artifacts[0].clone(); 65],
        |m: &mut ReleaseManifest| m.artifacts.push(m.artifacts[0].clone()),
        |m: &mut ReleaseManifest| m.artifacts[0].platform = "x".repeat(65),
        |m: &mut ReleaseManifest| m.artifacts[0].complete = false,
        |m: &mut ReleaseManifest| m.artifacts[0].size = 0,
        |m: &mut ReleaseManifest| m.artifacts[0].sha256 = [0; 32],
        |m: &mut ReleaseManifest| m.source_commit = "0".repeat(40),
        |m: &mut ReleaseManifest| m.compatibility.config_schema = 0,
        |m: &mut ReleaseManifest| m.compatibility.previous_config_schema = Some(8),
        |m: &mut ReleaseManifest| m.compatibility.persistent.readable_epochs = vec![2; 33],
        |m: &mut ReleaseManifest| m.compatibility.persistent.readable_epochs = vec![2, 2],
        |m: &mut ReleaseManifest| m.compatibility.persistent.writable_epoch = 3,
        |m: &mut ReleaseManifest| {
            m.compatibility.persistent.migrations = vec![MigrationEdge { from: 2, to: 2 }]
        },
        |m: &mut ReleaseManifest| {
            m.compatibility.persistent.migrations = vec![MigrationEdge { from: 1, to: 2 }; 65]
        },
    ] {
        let mut manifest = fixture();
        mutate(&mut manifest);
        assert!(manifest.canonical_bytes().is_err());
    }
    let payload = String::from_utf8(fixture().canonical_bytes()?)?;
    for payload in [
        format!("{{\"unknown\":1,{}", payload.get(1..).ok_or("payload")?),
        format!(
            "{{\"version\":{{\"major\":0,\"minor\":1,\"patch\":0}},{}",
            payload.get(1..).ok_or("payload")?
        ),
        format!(" {payload}"),
    ] {
        let mut wire = vec![0; 64];
        wire.extend(payload.as_bytes());
        assert!(SignedReleaseManifest::from_bytes(&wire).is_err());
    }
    assert!(SignedReleaseManifest::from_bytes(&[0; 63]).is_err());
    Ok(())
}
#[test]
fn rejects_duplicate_and_oversized_published_version_edges() {
    for count in [2, 33] {
        let mut manifest = fixture();
        manifest.upgrade_from = vec![
            ProductVersion {
                major: 0,
                minor: 0,
                patch: 9
            };
            count
        ];
        assert!(manifest.canonical_bytes().is_err());
    }
}
#[test]
fn wire_preserves_the_actual_git_source_object_id() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = fixture();
    let old = format!(
        "\"source_commit\":{}",
        serde_json::to_string(&manifest.source_commit)?
    );
    let payload = String::from_utf8(manifest.canonical_bytes()?)?;
    let commit = "9fd68fd9eaa72ed45e070412d30656fda1277d79";
    let payload = payload.replacen(&old, &format!("\"source_commit\":\"{commit}\""), 1);
    let mut wire = vec![0; 64];
    wire.extend(payload.as_bytes());
    assert!(
        SignedReleaseManifest::from_bytes(&wire).is_ok(),
        "an exact real Git object ID must not require padding or rehashing"
    );
    Ok(())
}

#[test]
fn source_commit_is_an_exact_canonical_git_object_name() {
    for commit in ["a5".repeat(20), "b6".repeat(32)] {
        let mut manifest = fixture();
        manifest.source_commit = commit.clone();
        assert!(manifest.canonical_bytes().is_ok());
        assert_eq!(manifest.source_commit, commit);
    }
    for commit in [
        String::new(),
        "a5".repeat(19),
        "a5".repeat(21),
        "A5".repeat(20),
        "g5".repeat(20),
        "0".repeat(40),
        "0".repeat(64),
        "a".repeat(65),
    ] {
        let mut manifest = fixture();
        manifest.source_commit = commit;
        assert!(manifest.canonical_bytes().is_err());
    }
}

#[test]
fn authoring_uses_the_same_domain_as_offline_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).map_err(|_| "key")?;
    let manifest = fixture();
    let signature = pair.sign(&manifest.signing_message()?);
    let signed = SignedReleaseManifest::new(manifest, signature.as_ref().try_into()?)?;
    signed.verify(&ProjectTrustRoot::new(
        pair.public_key().as_ref().try_into()?,
    ))?;
    signed.verify_signature(&ReleaseSigningPublicKey::new(
        pair.public_key().as_ref().try_into()?,
    ))?;
    Ok(())
}
