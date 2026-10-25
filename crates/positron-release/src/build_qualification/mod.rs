//! Test-signed, staged current-build metadata. This is deliberately not a published release.
mod documents;
mod oci;
mod tests;

use crate::{files::Bundle, inventory::hex, *};
use positron_kernel::release_manifest::{
    ArtifactRole, FormatCompatibility, ProductVersion, ReleaseArtifact, ReleaseCompatibility,
    ReleaseManifest, ReleaseSigningPublicKey, SignedReleaseManifest,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

struct ArtifactBuild<'a> {
    packages: &'a Value,
    closure: &'a Value,
    builder: &'a str,
    independent_builder: &'a str,
    notices: &'a [u8],
}

struct Qualification {
    root: PathBuf,
    rebuild: PathBuf,
    inventory: ReleaseInventory,
    independent_builder: String,
}
impl Qualification {
    fn add(&mut self, name: &str, bytes: &[u8]) -> String {
        fs::write(self.root.join(name), bytes).unwrap();
        self.inventory.files.push(InventoryFile {
            id: name.into(),
            identity: FileIdentity::of(bytes),
        });
        name.into()
    }
    fn input(&mut self, name: &str, bytes: &[u8]) {
        let file = self.add(name, bytes);
        self.inventory.inputs.push(BuildInput {
            name: name.into(),
            version: hex(&FileIdentity::of(bytes).sha256),
            file,
        });
    }
    fn verify(&self) -> Result<(), ReleaseError> {
        let inventory = ReleaseInventory::from_bytes(&self.inventory.canonical_bytes()?)?;
        // Source archives retain public test keys and adversarial fuzz seeds.
        // Measure the exact input, but make no full-release source-secret claim.
        for file in &inventory.files {
            let measured = if file.id == "source.tar" {
                FileIdentity::of(&read_release_file(&self.root.join(&file.id), 512 << 20)?)
            } else {
                scan_release_contents(&self.root, &file.id, &[])?;
                inspect_file(&self.root, &file.id, &[])?
            };
            if measured != file.identity {
                return Err(ReleaseError::IdentityMismatch);
            }
        }
        let bundle = Bundle::open(&self.root)?;
        let rebuilt = Bundle::open(&self.rebuild)?;
        for artifact in &inventory.artifacts {
            let payload = artifact.payload.as_ref().unwrap();
            if bundle.same_file(&rebuilt, payload)?
                || inspect_file(&self.rebuild, payload, &[])? != inventory.file(payload)?.identity
            {
                return Err(ReleaseError::Unreproducible);
            }
            scan_release_contents(&self.rebuild, payload, &[])?;
        }
        crate::metadata::verify_identities(&inventory, &bundle)?;
        crate::oci::verify_oci(&inventory, &bundle)
    }
}

fn captured(capture: &Path, rebuild: &Path, output: &Path, inputs: &[&str]) -> Qualification {
    fs::create_dir_all(output).unwrap();
    let independent = output.join("independent");
    fs::create_dir_all(&independent).unwrap();
    let version = ProductVersion::parse_exact(
        fs::read_to_string(capture.join("version.txt"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let source_commit = fs::read_to_string(capture.join("source-commit.txt"))
        .unwrap()
        .trim()
        .to_owned();
    let api = fs::read(capture.join("openapi.json")).unwrap();
    let compatibility: ReleaseCompatibility =
        serde_json::from_slice(&fs::read(capture.join("compatibility.json")).unwrap()).unwrap();
    assert_eq!(compatibility.schema, FileIdentity::of(&api).sha256);
    let mut result = Qualification {
        independent_builder: fs::read_to_string(rebuild.join("build-identity.txt"))
            .unwrap()
            .trim()
            .into(),
        root: output.into(),
        rebuild: independent,
        inventory: ReleaseInventory {
            format: 1,
            version,
            source_commit,
            build_identity: fs::read_to_string(capture.join("build-identity.txt"))
                .unwrap()
                .trim()
                .into(),
            api_version: "positron.v1".into(),
            compatibility,
            inputs: vec![],
            files: vec![],
            artifacts: vec![],
            security_support: SecuritySupport {
                expires_unix: 0,
                upgrade_paths: vec![],
            },
        },
    };
    for name in inputs {
        result.input(name, &fs::read(capture.join(name)).unwrap());
    }
    let source_scan = inspect_file(capture, "source.tar", &[]);
    result.add("source-input-scan.json", &serde_json::to_vec(&json!({
        "input":"source.tar", "result":match source_scan { Ok(_) => "no recognized credential forms".into(), Err(error) => error.to_string() },
        "scope":"exact captured build input only; never an accepted Source release artifact or full release secret-scan claim"
    })).unwrap());
    result
}

fn staged(capture: &Path, rebuild: &Path, output: &Path, target: &str) -> Qualification {
    let mut result = captured(
        capture,
        rebuild,
        output,
        &[
            "source.tar",
            "build-identity.txt",
            "created.txt",
            "Cargo.lock",
            "flake.lock",
            "rust-toolchain.toml",
            "toolchain.txt",
            "closure.json",
            "cargo-metadata.json",
            "compatibility.json",
            "compatibility-sources.json",
            "source-commit.txt",
            "version.txt",
        ],
    );
    let api = fs::read(capture.join("openapi.json")).unwrap();
    let metadata: Value =
        serde_json::from_slice(&fs::read(capture.join("cargo-metadata.json")).unwrap()).unwrap();
    let packages = &metadata["packages"];
    let closure: Value =
        serde_json::from_slice(&fs::read(capture.join("closure.json")).unwrap()).unwrap();
    let builder = result.inventory.build_identity.clone();
    let independent_builder = result.independent_builder.clone();
    let build = || ArtifactBuild {
        packages,
        closure: &closure,
        builder: &builder,
        independent_builder: &independent_builder,
        notices: &[],
    };
    result.artifact(
        "openapi.json",
        Surface::Api,
        "any",
        &api,
        &fs::read(rebuild.join("openapi.json")).unwrap(),
        build(),
    );
    result.artifact(
        "positron",
        Surface::NativeExecutable,
        &format!("nix-{target}"),
        &fs::read(capture.join("positron")).unwrap(),
        &fs::read(rebuild.join("positron")).unwrap(),
        build(),
    );
    result.artifact(
        "positron.nar",
        Surface::Nix,
        target,
        &fs::read(capture.join("positron.nar")).unwrap(),
        &fs::read(rebuild.join("positron.nar")).unwrap(),
        build(),
    );
    result
}

#[test]
#[ignore = "requires independently built native Nix outputs and captured build inputs"]
fn actual_nix_metadata_is_bound_offline_to_current_build() {
    let first = PathBuf::from(std::env::var_os("POSITRON_TEST_NIX_CAPTURE").unwrap());
    let second = PathBuf::from(std::env::var_os("POSITRON_TEST_NIX_CAPTURE_REBUILD").unwrap());
    let output = PathBuf::from(std::env::var_os("POSITRON_TEST_NIX_METADATA_OUT").unwrap());
    let target = std::env::var("POSITRON_TEST_TARGET").unwrap();
    for name in [
        "source-commit.txt",
        "version.txt",
        "source.tar",
        "Cargo.lock",
        "flake.lock",
        "rust-toolchain.toml",
        "toolchain.txt",
        "compatibility.json",
        "openapi.json",
    ] {
        assert_eq!(
            fs::read(first.join(name)).unwrap(),
            fs::read(second.join(name)).unwrap(),
            "independent {name}"
        );
    }
    assert_ne!(
        fs::read(first.join("build-identity.txt")).unwrap(),
        fs::read(second.join("build-identity.txt")).unwrap()
    );
    let qualification = staged(&first, &second, &output, &target);
    qualification.verify().unwrap();
    qualification.sign();
    fs::write(output.join("SCOPE.txt"),"Test-signed current-build staged Nix identity qualification. No published release, supported upgrade target, or complete release validation evidence is asserted. Native cache signatures are independently verified by built_nix under the existing Release Trust owner.\n").unwrap();
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn compatibility_sources(repo: &Path) -> (ReleaseCompatibility, Vec<u8>) {
    let mut definitions = serde_json::Map::new();
    for (claim, paths) in [
        ("receiver", vec!["crates/positron-ingest/src"]),
        ("api", vec!["api/positron/v1"]),
        ("query", vec!["crates/positron-query/src"]),
        (
            "crd",
            vec!["docs/adr/0050-make-kubernetes-compatibility-a-tested-product-contract.md"],
        ),
        (
            "operator",
            vec!["docs/adr/0049-ship-an-optional-same-binary-kubernetes-operator-in-release-1.md"],
        ),
    ] {
        let mut selected = Vec::new();
        fn collect(path: &Path, selected: &mut Vec<PathBuf>) {
            if path.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    collect(&entry.unwrap().path(), selected);
                }
            } else {
                selected.push(path.into());
            }
        }
        for path in paths {
            collect(&repo.join(path), &mut selected);
        }
        selected.sort();
        let files: Vec<_> = selected.iter().map(|path| json!({"path":path.strip_prefix(repo).unwrap().to_str().unwrap(),"sha256":hex(&FileIdentity::of(&fs::read(path).unwrap()).sha256)})).collect();
        assert!(!files.is_empty());
        definitions.insert(claim.into(), Value::Array(files));
    }
    let fingerprint =
        |name: &str| FileIdentity::of(&serde_json::to_vec(&definitions[name]).unwrap()).sha256;
    let compatibility = ReleaseCompatibility {
        config_schema: 1,
        previous_config_schema: None,
        persistent: FormatCompatibility {
            readable_epochs: vec![
                positron_kernel::FormatEpoch::CATALOG_V1.value(),
                positron_kernel::FormatEpoch::CATALOG_V2.value(),
            ],
            writable_epoch: positron_kernel::FormatEpoch::CATALOG_V2.value(),
            migrations: vec![],
        },
        backup: FormatCompatibility {
            readable_epochs: vec![2],
            writable_epoch: 2,
            migrations: vec![],
        },
        receiver: fingerprint("receiver"),
        api: fingerprint("api"),
        query: fingerprint("query"),
        crd: fingerprint("crd"),
        operator: fingerprint("operator"),
        schema: FileIdentity::of(&fs::read(repo.join("api/positron/v1/openapi.json")).unwrap())
            .sha256,
    };
    (compatibility, serde_json::to_vec(&definitions).unwrap())
}

#[test]
#[ignore = "captures metadata for the native Nix build in POSITRON_TEST_NIX_CAPTURE"]
fn capture_nix_build_metadata() {
    let capture = PathBuf::from(std::env::var_os("POSITRON_TEST_NIX_CAPTURE").unwrap());
    capture_metadata(&capture);
}

fn capture_metadata(capture: &Path) {
    let repo = repository();
    let (compatibility, definitions) = compatibility_sources(&repo);
    fs::write(
        capture.join("compatibility.json"),
        serde_json::to_vec(&compatibility).unwrap(),
    )
    .unwrap();
    fs::write(capture.join("compatibility-sources.json"), definitions).unwrap();
    fs::copy(
        repo.join("api/positron/v1/openapi.json"),
        capture.join("openapi.json"),
    )
    .unwrap();
    fs::write(capture.join("version.txt"), env!("CARGO_PKG_VERSION")).unwrap();
    for (file, args) in [
        ("source-commit.txt", vec!["rev-parse", "HEAD"]),
        ("source.tar", vec!["archive", "--format=tar", "HEAD"]),
    ] {
        let output = std::process::Command::new("git")
            .current_dir(&repo)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        fs::write(capture.join(file), output.stdout).unwrap();
    }
}
