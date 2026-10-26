//! Synthetic metadata refusals only. Native construction claims use actual CI captures.
use super::super::tests::TestCapture;
use super::*;

fn tar(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut archive = tar::Builder::new(Vec::new());
    for (name, bytes) in files {
        let mut header = tar::Header::new_ustar();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    archive.into_inner().unwrap()
}
fn descriptor(files: &mut BTreeMap<String, Vec<u8>>, bytes: Vec<u8>, media: &str) -> Value {
    let identity = FileIdentity::of(&bytes);
    let digest = hex(&identity.sha256);
    files.insert(format!("blobs/sha256/{digest}"), bytes);
    json!({"mediaType":media,"digest":format!("sha256:{digest}"),"size":identity.size})
}

fn fixture() -> (TestCapture, Qualification) {
    let base = TestCapture::new();
    let source_files: Vec<_> = fs::read_dir(&base.0)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let root = base.0.join("oci");
    fs::create_dir(&root).unwrap();
    let mut combined = BTreeMap::new();
    let mut images = vec![];
    for (target, architecture) in [("linux-x86_64", "amd64"), ("linux-aarch64", "arm64")] {
        let binary = format!("synthetic {target} executable").into_bytes();
        let payload = tar(&BTreeMap::from([
            ("usr/bin/positron".into(), binary.clone()),
            (
                "usr/share/licenses/glibc/COPYING.LIB".into(),
                b"Glibc runtime terms from unit fixture\n".to_vec(),
            ),
            (
                "usr/share/licenses/ca-certificates/MPL-2.0.txt".into(),
                b"Mozilla Public License Version 2.0\n".to_vec(),
            ),
        ]));
        let layer = descriptor(
            &mut combined,
            payload,
            "application/vnd.oci.image.layer.v1.tar",
        );
        let config = descriptor(&mut combined, serde_json::to_vec(&json!({"architecture":architecture,"os":"linux","rootfs":{"type":"layers","diff_ids":[layer["digest"]]}})).unwrap(), "application/vnd.oci.image.config.v1+json");
        let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":config,"layers":[layer]})).unwrap();
        let closure = Layout(combined.clone()).closure(&serde_json::from_slice(&manifest).unwrap());
        let mut image = descriptor(
            &mut combined,
            manifest,
            "application/vnd.oci.image.manifest.v1+json",
        );
        image["platform"] = json!({"os":"linux","architecture":architecture});
        images.push(image);
        for build in ["one", "two"] {
            let capture = root.join(format!("oci-{target}/{build}"));
            fs::create_dir_all(&capture).unwrap();
            for source in &source_files {
                fs::copy(source, capture.join(source.file_name().unwrap())).unwrap();
            }
            fs::write(capture.join("positron"), &binary).unwrap();
            fs::write(
                capture.join("closure.json"),
                serde_json::to_vec(&closure).unwrap(),
            )
            .unwrap();
            fs::write(
                capture.join("build-identity.txt"),
                format!("unit-{target}-{build}"),
            )
            .unwrap();
            fs::write(capture.join("build-tools.txt"), "synthetic builder").unwrap();
            fs::write(
                capture.join("native-build-flags.txt"),
                "synthetic compiler flags",
            )
            .unwrap();
            fs::write(
                capture.join("runtime-packages.txt"),
                "glibc\t2.34-unit\tLGPLv2+\n",
            )
            .unwrap();
        }
    }
    combined.insert("index.json".into(), serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":images})).unwrap());
    for build in ["one", "two"] {
        fs::write(root.join(format!("index-{build}.tar")), tar(&combined)).unwrap();
        fs::write(
            root.join(format!("index-{build}-build-identity.txt")),
            format!("unit-index-{build}"),
        )
        .unwrap();
    }
    let qualification = staged_oci(&root, &root.join("staged"));
    (base, qualification)
}

#[test]
fn staged_oci_manifest_binds_both_architectures_current_inputs_and_refuses_drift() {
    let (_base, mut qualification) = fixture();
    qualification.verify().unwrap();
    let mut signed = qualification.sign();
    signed[0] ^= 1;
    let key: [u8; 32] = fs::read(qualification.root.join("test-signing-key.pub"))
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        SignedReleaseManifest::from_bytes(&signed)
            .and_then(|manifest| manifest.verify_signature(&ReleaseSigningPublicKey::new(key)))
            .is_err()
    );
    let image = qualification
        .inventory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.surface == Surface::OciImage)
        .unwrap();
    let target = image.target.clone();
    image.target = "linux-aarch64".into();
    assert!(qualification.verify().is_err());
    qualification
        .inventory
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.surface == Surface::OciImage)
        .unwrap()
        .target = target;
    assert_eq!(
        qualification.inventory.version,
        ProductVersion::parse_exact(env!("CARGO_PKG_VERSION")).unwrap()
    );
    qualification.inventory.source_commit = "f".repeat(40);
    assert_eq!(qualification.verify(), Err(ReleaseError::IdentityMismatch));
    qualification.inventory.source_commit = "e".repeat(40);
    let payload = qualification
        .inventory
        .artifacts
        .iter()
        .find(|artifact| artifact.surface == Surface::OciImage)
        .unwrap()
        .payload
        .as_ref()
        .unwrap();
    fs::write(qualification.root.join(payload), b"changed filesystem").unwrap();
    assert_eq!(qualification.verify(), Err(ReleaseError::IdentityMismatch));
}

#[test]
fn oci_runtime_declared_licenses_and_actual_notices_survive_document_generation() {
    let (_base, qualification) = fixture();
    let image = qualification
        .inventory
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.surface == Surface::OciImage && artifact.target == "linux-aarch64"
        })
        .unwrap();
    let spdx: Value =
        serde_json::from_slice(&fs::read(qualification.root.join(&image.spdx)).unwrap()).unwrap();
    let glibc = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == "rpm:glibc")
        .unwrap();
    assert_eq!(glibc["licenseDeclared"], "LicenseRef-RPM-glibc");
    let extracted = spdx["hasExtractedLicensingInfos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|license| license["licenseId"] == "LicenseRef-RPM-glibc")
        .unwrap();
    assert!(extracted["name"].as_str().unwrap().contains("LGPLv2+"));
    assert!(
        extracted["extractedText"]
            .as_str()
            .unwrap()
            .contains("Glibc runtime terms from unit fixture")
    );
    let cdx: Value =
        serde_json::from_slice(&fs::read(qualification.root.join(&image.cyclonedx)).unwrap())
            .unwrap();
    let glibc = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"] == "rpm:glibc")
        .unwrap();
    assert_eq!(glibc["licenses"][0]["license"]["name"], "LGPLv2+");
    let notices = fs::read_to_string(qualification.root.join(&image.license_notices)).unwrap();
    assert!(notices.contains("Glibc runtime terms from unit fixture"));
    assert!(notices.contains("Mozilla Public License Version 2.0"));
}

#[test]
fn each_native_oci_artifact_retains_its_actual_builder_and_independent_builder() {
    let (_base, qualification) = fixture();
    let index = qualification
        .inventory
        .artifacts
        .iter()
        .find(|artifact| artifact.surface == Surface::OciIndex)
        .unwrap();
    let provenance: Value =
        serde_json::from_slice(&fs::read(qualification.root.join(&index.provenance)).unwrap())
            .unwrap();
    let evidence: Value =
        serde_json::from_slice(&fs::read(qualification.root.join(&index.evidence)).unwrap())
            .unwrap();
    assert_eq!(
        provenance["predicate"]["runDetails"]["builder"]["id"],
        "unit-index-one"
    );
    assert_eq!(evidence["independent_builder"], "unit-index-two");
    for target in ["linux-x86_64", "linux-aarch64"] {
        for surface in [Surface::NativeExecutable, Surface::OciImage] {
            let artifact = qualification
                .inventory
                .artifacts
                .iter()
                .find(|artifact| artifact.surface == surface && artifact.target == target)
                .unwrap();
            let provenance: Value = serde_json::from_slice(
                &fs::read(qualification.root.join(&artifact.provenance)).unwrap(),
            )
            .unwrap();
            let evidence: Value = serde_json::from_slice(
                &fs::read(qualification.root.join(&artifact.evidence)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                provenance["predicate"]["runDetails"]["builder"]["id"],
                format!("unit-{target}-one")
            );
            assert_eq!(
                evidence["independent_builder"],
                format!("unit-{target}-two")
            );
        }
    }
}

#[test]
fn captured_native_executable_is_the_immutable_archive_payload_after_build_directory_reuse() {
    let base = TestCapture::new();
    let capture = base.0.join("capture");
    fs::create_dir(&capture).unwrap();
    let binary = b"synthetic immutable native archive payload";
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(gzip);
    let mut header = tar::Header::new_ustar();
    header.set_size(binary.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    archive
        .append_data(&mut header, "positron/bin/positron", binary.as_slice())
        .unwrap();
    fs::write(
        capture.join("native.tar.gz"),
        archive.into_inner().unwrap().finish().unwrap(),
    )
    .unwrap();
    fs::write(
        capture.join("positron"),
        b"mutable build directory was reused",
    )
    .unwrap();
    capture_oci_executable(&capture);
    assert_eq!(fs::read(capture.join("positron")).unwrap(), binary);
}
