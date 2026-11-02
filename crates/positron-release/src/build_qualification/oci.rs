//! OCI adapter for the shared staged build metadata tests; no publication.
use super::*;
use std::{collections::BTreeMap, io::Read, process::Command};

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
    fn index(&self) -> &[u8] {
        let layout: Value = serde_json::from_slice(&self.0["index.json"]).unwrap();
        assert_eq!(layout["schemaVersion"], 2);
        assert_eq!(
            layout["mediaType"],
            "application/vnd.oci.image.index.v1+json"
        );
        let descriptors = layout["manifests"].as_array().unwrap();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(
            descriptors[0]["mediaType"],
            "application/vnd.oci.image.index.v1+json"
        );
        self.blob(&descriptors[0])
    }
    fn image(&self, architecture: &str) -> &[u8] {
        let index: Value = serde_json::from_slice(self.index()).unwrap();
        let image = index["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|image| image["platform"]["architecture"] == architecture)
            .unwrap();
        self.blob(image)
    }
    fn license_files(&self, manifest: &Value) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        for entry in tar::Archive::new(self.blob(&manifest["layers"][0]))
            .entries()
            .unwrap()
        {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            if entry.header().entry_type().is_file() && name.starts_with("usr/share/licenses/") {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                files.insert(name, bytes);
            }
        }
        files
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
    capture_oci_metadata(&capture);
}
fn capture_oci_metadata(capture: &Path) {
    capture_oci_executable(capture);
    capture_metadata(capture);
    let layout = Layout::read(&capture.join("image.tar"));
    let index: Value = serde_json::from_slice(&layout.0["index.json"]).unwrap();
    let manifest: Value = serde_json::from_slice(layout.blob(&index["manifests"][0])).unwrap();
    fs::write(
        capture.join("closure.json"),
        serde_json::to_vec(&layout.closure(&manifest)).unwrap(),
    )
    .unwrap();
}

fn capture_oci_executable(capture: &Path) {
    // Native Cargo test builds may replace the mutable build-tree executable.
    // The frozen archive is the exact input used to construct this OCI image.
    let executable = Command::new("tar")
        .arg("-xOf")
        .arg(capture.join("native.tar.gz"))
        .arg("positron/bin/positron")
        .output()
        .unwrap();
    assert!(
        executable.status.success(),
        "native archive extraction failed"
    );
    fs::write(capture.join("positron"), executable.stdout).unwrap();
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
    let assembly_builder = fs::read_to_string(root.join("index-one-build-identity.txt"))
        .unwrap()
        .trim()
        .to_owned();
    let assembly_rebuilder = fs::read_to_string(root.join("index-two-build-identity.txt"))
        .unwrap()
        .trim()
        .to_owned();
    assert_ne!(assembly_builder, assembly_rebuilder);
    qualification.inventory.build_identity = assembly_builder.clone();
    qualification.independent_builder = assembly_rebuilder.clone();
    for build in ["one", "two"] {
        let name = format!("index-{build}-build-identity.txt");
        qualification.input(&name, &fs::read(root.join(&name)).unwrap());
    }
    let index = Layout::read(&root.join("index-one.tar"));
    let independent = Layout::read(&root.join("index-two.tar"));
    assert_eq!(index.index(), independent.index());
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
    let builder = qualification.inventory.build_identity.clone();
    let independent_builder = qualification.independent_builder.clone();
    let mut all_notices = vec![];
    qualification.artifact(
        "openapi.json",
        Surface::Api,
        "any",
        &fs::read(first.join("openapi.json")).unwrap(),
        &fs::read(second.join("openapi.json")).unwrap(),
        ArtifactBuild {
            packages,
            closure: &empty,
            builder: &builder,
            independent_builder: &independent_builder,
            notices: &[],
        },
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
        let manifest_bytes = index.image(architecture);
        assert_eq!(manifest_bytes, independent.image(architecture));
        let manifest: Value = serde_json::from_slice(manifest_bytes).unwrap();
        let legal = index.license_files(&manifest);
        let notices = notice_bytes(&legal);
        all_notices.extend_from_slice(&notices);
        let mut platform_packages = packages.as_array().unwrap().clone();
        for line in fs::read_to_string(first.join("runtime-packages.txt"))
            .unwrap()
            .lines()
        {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3);
            let prefix = format!("usr/share/licenses/{}/", fields[0]);
            let package_legal = legal
                .iter()
                .filter(|(path, _)| path.starts_with(&prefix))
                .map(|(path, bytes)| (path.clone(), bytes.clone()))
                .collect();
            let license_text = String::from_utf8(notice_bytes(&package_legal)).unwrap();
            assert!(
                !license_text.is_empty(),
                "actual runtime license text required"
            );
            platform_packages.push(json!({"name":format!("rpm:{}",fields[0]),"version":fields[1],"license":format!("LicenseRef-RPM-{}",fields[0]),"declared_license":fields[2],"license_text":license_text,"source":"NOASSERTION"}));
        }
        let platform_packages = Value::Array(platform_packages);
        let builder = fs::read_to_string(first.join("build-identity.txt"))
            .unwrap()
            .trim()
            .to_owned();
        let independent_builder = fs::read_to_string(second.join("build-identity.txt"))
            .unwrap()
            .trim()
            .to_owned();
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
            ArtifactBuild {
                packages: &platform_packages,
                closure: &closure,
                builder: &builder,
                independent_builder: &independent_builder,
                notices: &notices,
            },
        );
        qualification.artifact(
            &format!("{target}-image.json"),
            Surface::OciImage,
            target,
            manifest_bytes,
            independent.image(architecture),
            ArtifactBuild {
                packages: &platform_packages,
                closure: &closure,
                builder: &builder,
                independent_builder: &independent_builder,
                notices: &notices,
            },
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
        index.index(),
        independent.index(),
        ArtifactBuild {
            packages,
            closure: &empty,
            builder: &builder,
            independent_builder: &independent_builder,
            notices: &all_notices,
        },
    );
    let compose = compose_deployment(&qualification.inventory).unwrap();
    let mut independent_inventory = qualification.inventory.clone();
    let index_file = independent_inventory
        .artifacts
        .iter()
        .find(|a| a.surface == Surface::OciIndex)
        .unwrap()
        .file
        .clone();
    independent_inventory
        .files
        .iter_mut()
        .find(|f| f.id == index_file)
        .unwrap()
        .identity = FileIdentity::of(independent.index());
    let rebuilt_compose = compose_deployment(&independent_inventory).unwrap();
    qualification.artifact(
        "compose.yaml",
        Surface::Compose,
        "any",
        compose.as_bytes(),
        rebuilt_compose.as_bytes(),
        ArtifactBuild {
            packages: &json!([]),
            closure: &empty,
            builder: &assembly_builder,
            independent_builder: &assembly_rebuilder,
            notices: &[],
        },
    );
    let chart = helm_chart(&qualification.inventory).unwrap();
    let rebuilt_chart = helm_chart(&independent_inventory).unwrap();
    qualification.artifact(
        "positron.tgz",
        Surface::Helm,
        "any",
        &chart,
        &rebuilt_chart,
        ArtifactBuild {
            packages: &json!([]),
            closure: &empty,
            builder: &assembly_builder,
            independent_builder: &assembly_rebuilder,
            notices: &[],
        },
    );
    qualification
}

fn notice_bytes(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut notices = Vec::new();
    for (path, bytes) in files {
        notices.extend_from_slice(format!("\n\n===== {path} =====\n").as_bytes());
        notices.extend_from_slice(bytes);
    }
    notices
}

#[cfg(test)]
mod tests;
