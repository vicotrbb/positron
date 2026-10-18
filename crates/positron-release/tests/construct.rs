mod support;
use positron_release::*;
#[test]
fn construction_binds_the_full_set_to_the_existing_canonical_manifest() {
    let fixture = support::Fixture::new();
    let construction = construct_release(
        &fixture.inventory,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        &[],
        vec![],
    )
    .unwrap();
    assert_eq!(construction.manifest.version, fixture.inventory.version);
    assert_eq!(
        construction.manifest.source_commit,
        support::keyless::SOURCE_COMMIT
    );
    assert_eq!(construction.manifest.artifacts.len(), 9);
    assert_ne!(
        construction.signing_message().unwrap(),
        construction.manifest.canonical_bytes().unwrap()
    );
}

#[test]
fn construction_validates_sbom_and_provenance_not_just_their_checksums() {
    let mut fixture = support::Fixture::new();
    let id = fixture.inventory.artifacts[0].spdx.clone();
    std::fs::write(fixture.root.join("bundle").join(&id), b"{}").unwrap();
    fixture
        .inventory
        .files
        .iter_mut()
        .find(|file| file.id == id)
        .unwrap()
        .identity = FileIdentity::of(b"{}");
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
fn unrelated_rebuilt_payload_cannot_qualify_a_linux_executable() {
    let mut fixture = support::Fixture::new();
    let id = fixture.inventory.artifacts[0].file.clone();
    let changed = b"unreproduced executable bytes";
    std::fs::write(fixture.root.join("bundle").join(&id), changed).unwrap();
    fixture
        .inventory
        .files
        .iter_mut()
        .find(|file| file.id == id)
        .unwrap()
        .identity = FileIdentity::of(changed);
    fixture.inventory.artifacts[0]
        .publication
        .immutable_identity = format!("sha256:{}", support::hex(&FileIdentity::of(changed).sha256));
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
fn a_second_name_for_the_same_payload_is_not_an_independent_rebuild() {
    let fixture = support::Fixture::new();
    assert_eq!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.root.join("bundle"),
            &[],
            vec![]
        )
        .err(),
        Some(ReleaseError::Unreproducible)
    );
}

#[test]
fn changed_toolchain_bytes_cannot_reuse_old_build_provenance() {
    let mut fixture = support::Fixture::new();
    let input = fixture.inventory.inputs[0].file.clone();
    std::fs::write(
        fixture.root.join("bundle").join(&input),
        b"different pinned compiler bytes",
    )
    .unwrap();
    fixture
        .inventory
        .files
        .iter_mut()
        .find(|file| file.id == input)
        .unwrap()
        .identity = FileIdentity::of(b"different pinned compiler bytes");
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
fn provenance_cannot_be_reused_for_a_different_build_identity() {
    let mut fixture = support::Fixture::new();
    fixture.inventory.build_identity = "another-build".into();
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
fn signed_nuget_wrap_binds_the_actual_unsigned_rebuilt_zip() {
    let mut fixture = support::Fixture::new();
    let signed = include_bytes!("fixtures/tinyjson.1.0.0.nupkg");
    // Independently recorded native unsigned ZIP: omit the last signature local
    // entry and central entry, then restore the native directory fields.
    let mut unsigned = signed[..6774].to_vec();
    unsigned.extend(&signed[16282..]);
    let signature_cd = unsigned
        .windows(4)
        .rposition(|bytes| bytes == b"PK\x01\x02")
        .unwrap();
    let eocd = unsigned.len() - 22;
    unsigned.drain(signature_cd..eocd);
    let eocd = unsigned.len() - 22;
    unsigned[eocd + 8..eocd + 12].copy_from_slice(&[5, 0, 5, 0]);
    unsigned[eocd + 12..eocd + 16].copy_from_slice(&382_u32.to_le_bytes());
    unsigned[eocd + 16..eocd + 20].copy_from_slice(&6774_u32.to_le_bytes());
    assert_eq!(unsigned.len(), 7178);
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkDotNet)
        .unwrap();
    fixture.replace_artifact(index, signed, &unsigned);
    construct_release(
        &fixture.inventory,
        &fixture.root.join("bundle"),
        &fixture.rebuild,
        &[],
        vec![],
    )
    .unwrap();
    let payload = fixture.inventory.artifacts[index].payload.clone().unwrap();
    let unrelated = b"unrelated independently rebuilt SDK source";
    std::fs::write(fixture.root.join("bundle").join(&payload), unrelated).unwrap();
    std::fs::write(fixture.rebuild.join(&payload), unrelated).unwrap();
    fixture
        .inventory
        .files
        .iter_mut()
        .find(|file| file.id == payload)
        .unwrap()
        .identity = FileIdentity::of(unrelated);
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
