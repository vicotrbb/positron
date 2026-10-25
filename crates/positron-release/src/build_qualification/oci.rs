//! OCI adapter for the shared staged build metadata tests; no publication.
use super::*;
use std::{collections::BTreeMap, io::Read};

struct Layout(BTreeMap<String, Vec<u8>>);
impl Layout {
    fn read(path: &Path) -> Self {
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
        Self(files)
    }
    fn blob(&self, descriptor: &Value) -> &[u8] {
        let digest = descriptor["digest"]
            .as_str()
            .unwrap()
            .strip_prefix("sha256:")
            .unwrap();
        let bytes = &self.0[&format!("blobs/sha256/{digest}")];
        assert_eq!(descriptor["size"].as_u64().unwrap(), bytes.len() as u64);
        assert_eq!(hex(&FileIdentity::of(bytes).sha256), digest);
        bytes
    }
    fn image(&self, architecture: &str) -> &[u8] {
        let index: Value = serde_json::from_slice(&self.0["index.json"]).unwrap();
        let image = index["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|image| image["platform"]["architecture"] == architecture)
            .unwrap();
        self.blob(image)
    }
    fn closure(&self, manifest: &Value) -> Value {
        let mut files = serde_json::Map::new();
        assert_eq!(manifest["layers"].as_array().unwrap().len(), 1);
        assert_eq!(
            manifest["layers"][0]["mediaType"],
            "application/vnd.oci.image.layer.v1.tar"
        );
        for entry in tar::Archive::new(self.blob(&manifest["layers"][0]))
            .entries()
            .unwrap()
        {
            let mut entry = entry.unwrap();
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            let mode = entry.header().mode().unwrap();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            let license = if name == "etc/ssl/certs/ca-certificates.crt" {
                "MPL-2.0"
            } else {
                "NOASSERTION"
            };
            files.insert(name, json!({"sha256":hex(&FileIdentity::of(&bytes).sha256),"size":bytes.len(),"mode":mode,"license":license}));
        }
        Value::Object(files)
    }
}

#[test]
#[ignore = "captures the exact native OCI build inputs"]
fn capture_oci_build_metadata() {
    let capture = PathBuf::from(std::env::var_os("POSITRON_TEST_OCI_CAPTURE").unwrap());
    capture_metadata(&capture);
    let layout = Layout::read(&capture.join("image.tar"));
    let index: Value = serde_json::from_slice(&layout.0["index.json"]).unwrap();
    let manifest: Value = serde_json::from_slice(layout.blob(&index["manifests"][0])).unwrap();
    fs::write(
        capture.join("closure.json"),
        serde_json::to_vec(&layout.closure(&manifest)).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "requires both current native OCI captures and independent index exports"]
fn actual_oci_metadata_is_bound_offline_to_current_build() {
    let root = PathBuf::from(std::env::var_os("POSITRON_TEST_OCI_CAPTURES").unwrap());
    let output = PathBuf::from(std::env::var_os("POSITRON_TEST_OCI_METADATA_OUT").unwrap());
    let qualification = staged_oci(&root, &output);
    qualification.verify().unwrap();
    qualification.sign();
    fs::write(output.join("SCOPE.txt"), "Test-signed current-build staged OCI identity qualification. Actual source, toolchain, Cargo and runtime identities, independent native builds, image/index bytes, SPDX/CycloneDX and provenance are bound to the canonical manifest. No publication, supported Upgrade target or full release acceptance is asserted. Private offline publication protocol signatures are tested separately by built_oci.\n").unwrap();
}

fn staged_oci(root: &Path, output: &Path) -> Qualification {
    let inputs = [
        "source.tar",
        "build-identity.txt",
        "created.txt",
        "Cargo.lock",
        "rust-toolchain.toml",
        "toolchain.txt",
        "build-tools.txt",
        "native-build-flags.txt",
        "runtime-packages.txt",
        "closure.json",
        "cargo-metadata.json",
        "compatibility.json",
        "compatibility-sources.json",
        "source-commit.txt",
        "version.txt",
    ];
    let first = root.join("oci-linux-x86_64/one");
    let second = root.join("oci-linux-x86_64/two");
    let mut qualification = captured(&first, &second, output, &inputs);
    let index = Layout::read(&root.join("index-one.tar"));
    let independent = Layout::read(&root.join("index-two.tar"));
    assert_eq!(index.0["index.json"], independent.0["index.json"]);
    for target in ["linux-x86_64", "linux-aarch64"] {
        for build in ["one", "two"] {
            let capture = root.join(format!("oci-{target}/{build}"));
            for name in inputs {
                if matches!(
                    name,
                    "source.tar"
                        | "Cargo.lock"
                        | "rust-toolchain.toml"
                        | "compatibility.json"
                        | "compatibility-sources.json"
                        | "source-commit.txt"
                        | "version.txt"
                ) {
                    assert_eq!(
                        fs::read(capture.join(name)).unwrap(),
                        fs::read(root.join("oci-linux-x86_64/one").join(name)).unwrap(),
                        "shared source input {name}"
                    );
                    continue;
                }
                qualification.input(
                    &format!("{target}-{build}-{name}"),
                    &fs::read(capture.join(name)).unwrap(),
                );
            }
        }
    }
    let metadata: Value =
        serde_json::from_slice(&fs::read(first.join("cargo-metadata.json")).unwrap()).unwrap();
    let packages = &metadata["packages"];
    let empty = json!({});
    qualification.artifact(
        "openapi.json",
        Surface::Api,
        "any",
        &fs::read(first.join("openapi.json")).unwrap(),
        &fs::read(second.join("openapi.json")).unwrap(),
        (packages, &empty),
    );
    for (target, architecture) in [("linux-x86_64", "amd64"), ("linux-aarch64", "arm64")] {
        let first = root.join(format!("oci-{target}/one"));
        let second = root.join(format!("oci-{target}/two"));
        for name in [
            "source-commit.txt",
            "version.txt",
            "source.tar",
            "Cargo.lock",
            "rust-toolchain.toml",
            "toolchain.txt",
            "native-build-flags.txt",
            "cargo-metadata.json",
            "closure.json",
            "compatibility.json",
            "openapi.json",
        ] {
            assert_eq!(
                fs::read(first.join(name)).unwrap(),
                fs::read(second.join(name)).unwrap(),
                "independent {target}/{name}"
            );
        }
        for capture in [&first, &second] {
            assert_eq!(
                fs::read(capture.join("source-commit.txt")).unwrap(),
                fs::read(root.join("oci-linux-x86_64/one/source-commit.txt")).unwrap()
            );
        }
        assert_ne!(
            fs::read(first.join("build-identity.txt")).unwrap(),
            fs::read(second.join("build-identity.txt")).unwrap()
        );
        let mut platform_packages = packages.as_array().unwrap().clone();
        for line in fs::read_to_string(first.join("runtime-packages.txt"))
            .unwrap()
            .lines()
        {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3);
            platform_packages.push(json!({"name":format!("rpm:{}",fields[0]),"version":fields[1],"license":null,"source":"NOASSERTION"}));
        }
        let platform_packages = Value::Array(platform_packages);
        let manifest_bytes = index.image(architecture);
        assert_eq!(manifest_bytes, independent.image(architecture));
        let manifest: Value = serde_json::from_slice(manifest_bytes).unwrap();
        let closure = index.closure(&manifest);
        assert_eq!(
            closure["usr/bin/positron"]["sha256"],
            hex(&FileIdentity::of(&fs::read(first.join("positron")).unwrap()).sha256),
            "image must preserve the actual native executable"
        );
        assert_eq!(
            closure,
            serde_json::from_slice::<Value>(&fs::read(first.join("closure.json")).unwrap())
                .unwrap()
        );
        qualification.artifact(
            &format!("{target}-positron"),
            Surface::NativeExecutable,
            target,
            &fs::read(first.join("positron")).unwrap(),
            &fs::read(second.join("positron")).unwrap(),
            (&platform_packages, &closure),
        );
        qualification.artifact(
            &format!("{target}-image.json"),
            Surface::OciImage,
            target,
            manifest_bytes,
            independent.image(architecture),
            (&platform_packages, &closure),
        );
        let payload = format!("{target}-rootfs.tar");
        qualification.add(&payload, index.blob(&manifest["layers"][0]));
        fs::write(
            qualification.rebuild.join(&payload),
            independent.blob(&manifest["layers"][0]),
        )
        .unwrap();
        qualification
            .inventory
            .artifacts
            .last_mut()
            .unwrap()
            .payload = Some(payload);
        qualification.add(
            &format!("{target}-config.json"),
            index.blob(&manifest["config"]),
        );
    }
    qualification.artifact(
        "oci-index.json",
        Surface::OciIndex,
        "any",
        &index.0["index.json"],
        &independent.0["index.json"],
        (packages, &empty),
    );
    qualification
}

#[cfg(test)]
mod tests;
