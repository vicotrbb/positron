//! Real OCI exports under private protocol trust. This never publishes a release.
mod support;
use positron_release::*;
use serde_json::Value;
use std::{collections::BTreeMap, fs, io::Read, path::Path};

fn layout(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in tar::Archive::new(fs::File::open(path).unwrap())
        .entries()
        .unwrap()
    {
        let mut entry = entry.unwrap();
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry.path().unwrap().to_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert!(files.insert(name, bytes).is_none());
    }
    files
}
fn blob<'a>(files: &'a BTreeMap<String, Vec<u8>>, descriptor: &Value) -> &'a [u8] {
    let digest = descriptor["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let bytes = &files[&format!("blobs/sha256/{digest}")];
    assert_eq!(descriptor["size"].as_u64().unwrap(), bytes.len() as u64);
    assert_eq!(support::hex(&FileIdentity::of(bytes).sha256), digest);
    bytes
}

#[test]
#[ignore = "requires both native architecture layouts and independent rebuilds"]
fn actual_oci_index_and_images_bind_independent_payloads_and_offline_release_trust() {
    let first = layout(Path::new(
        &std::env::var("POSITRON_TEST_OCI_INDEX").unwrap(),
    ));
    let second = layout(Path::new(
        &std::env::var("POSITRON_TEST_OCI_INDEX_REBUILD").unwrap(),
    ));
    let layout_index: Value = serde_json::from_slice(&first["index.json"]).unwrap();
    assert_eq!(first["index.json"], second["index.json"]);
    assert_eq!(layout_index["schemaVersion"], 2);
    assert_eq!(
        layout_index["mediaType"],
        "application/vnd.oci.image.index.v1+json"
    );
    let descriptors = layout_index["manifests"].as_array().unwrap();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(
        descriptors[0]["mediaType"],
        "application/vnd.oci.image.index.v1+json"
    );
    let index_bytes = blob(&first, &descriptors[0]);
    assert_eq!(index_bytes, blob(&second, &descriptors[0]));
    let index: Value = serde_json::from_slice(index_bytes).unwrap();
    let images = index["manifests"].as_array().unwrap();
    assert_eq!(images.len(), 2);
    let mut fixture = support::Fixture::new();
    for (target, architecture) in [("linux-x86_64", "amd64"), ("linux-aarch64", "arm64")] {
        let descriptor = images
            .iter()
            .find(|image| image["platform"]["architecture"] == architecture)
            .unwrap();
        assert_eq!(descriptor["platform"]["os"], "linux");
        let manifest_bytes = blob(&first, descriptor);
        assert_eq!(manifest_bytes, blob(&second, descriptor));
        let manifest: Value = serde_json::from_slice(manifest_bytes).unwrap();
        let layers = manifest["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(
            layers[0]["mediaType"],
            "application/vnd.oci.image.layer.v1.tar"
        );
        let payload = blob(&first, &layers[0]);
        assert_eq!(payload, blob(&second, &layers[0]));
        let configuration = blob(&first, &manifest["config"]);
        let config: Value = serde_json::from_slice(configuration).unwrap();
        assert_eq!(config["config"]["User"], "65532:65532");
        assert_eq!(
            config["config"]["Entrypoint"],
            serde_json::json!(["/usr/bin/positron"])
        );
        let position = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == Surface::OciImage && artifact.target == target)
            .unwrap();
        fixture.replace_artifact(position, manifest_bytes, payload);
        fixture.add(format!("actual-oci-config-{architecture}"), configuration);
    }
    let position = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::OciIndex)
        .unwrap();
    fixture.replace_artifact(position, index_bytes, index_bytes);
    let (signed, prepared) = fixture.published();
    let verify = |signed: &[u8]| {
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
    };
    verify(&signed).unwrap();
    let mut tampered = signed.clone();
    tampered[0] ^= 1;
    assert!(verify(&tampered).is_err());
    let image = fixture
        .inventory
        .artifacts
        .iter()
        .find(|artifact| artifact.surface == Surface::OciImage)
        .unwrap();
    fs::write(
        fixture
            .root
            .join("bundle")
            .join(image.payload.as_ref().unwrap()),
        b"changed filesystem",
    )
    .unwrap();
    assert!(verify(&signed).is_err());
}
