use positron_release::{ReleaseError, ReleaseInventory};

#[test]
fn untrusted_inventory_refuses_empty_partial_and_unknown_contracts() {
    for bytes in [b"{}".as_slice(), b"{\"format\":99}", b"[]", b"null"] {
        assert_eq!(
            ReleaseInventory::from_bytes(bytes).err(),
            Some(ReleaseError::Invalid)
        );
    }
}

#[test]
fn release_one_inventory_has_a_fixed_complete_surface_and_target_matrix() {
    use positron_release::{Surface, required_release_one};
    let required = required_release_one();
    assert!(required.contains(&(Surface::SdkDotNet, "any")));
    assert!(required.contains(&(Surface::NativeExecutable, "macos-aarch64")));
    assert!(required.contains(&(Surface::OciImage, "linux-aarch64")));
    assert_eq!(required.len(), 32);
}

mod support;
#[test]
fn one_sdk_surface_binds_every_required_native_registry_member() {
    use positron_release::Surface;
    let mut fixture = support::Fixture::new();
    assert_eq!(
        fixture
            .inventory
            .artifacts
            .iter()
            .filter(|artifact| artifact.surface == Surface::SdkJava)
            .count(),
        4
    );
    fixture.inventory.canonical_bytes().unwrap();
    fixture.inventory.artifacts.pop();
    assert_eq!(
        fixture.inventory.validate_complete().err(),
        Some(ReleaseError::PartialSet)
    );
}
