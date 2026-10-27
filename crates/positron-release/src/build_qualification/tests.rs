//! Unit fixture and identity refusal regressions; these are not native build claims.
use super::*;

pub(super) struct TestCapture(pub(super) PathBuf);
impl TestCapture {
    pub(super) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "positron-nix-metadata-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let repo = repository();
        for name in ["Cargo.lock", "flake.lock", "rust-toolchain.toml"] {
            fs::copy(repo.join(name), root.join(name)).unwrap();
        }
        let (compatibility, definitions) = compatibility_sources(&repo);
        fs::write(
            root.join("compatibility.json"),
            serde_json::to_vec(&compatibility).unwrap(),
        )
        .unwrap();
        fs::write(root.join("compatibility-sources.json"), definitions).unwrap();
        fs::copy(
            repo.join("api/positron/v1/openapi.json"),
            root.join("openapi.json"),
        )
        .unwrap();
        fs::write(root.join("version.txt"), env!("CARGO_PKG_VERSION")).unwrap();
        fs::write(root.join("created.txt"), "2026-01-01T00:00:00Z").unwrap();
        fs::write(root.join("build-identity.txt"), "unit-fixture").unwrap();
        // This unit fixture exercises captured identities; only the ignored native
        // qualification above captures an actual Git build and executable.
        fs::write(root.join("source-commit.txt"), "e".repeat(40)).unwrap();
        for (name, bytes) in [
            ("source.tar", b"unit test source archive".as_slice()),
            ("toolchain.txt", b"unit test compiler"),
            ("closure.json", b"{}"),
            ("cargo-metadata.json", b"{\"packages\":[]}"),
            ("positron", b"unit test executable"),
            (
                "positron.nar",
                include_bytes!("../../tests/fixtures/positron.nar"),
            ),
        ] {
            fs::write(root.join(name), bytes).unwrap();
        }
        Self(root)
    }
    fn qualification(&self) -> Qualification {
        staged(&self.0, &self.0, &self.0.join("metadata"), "linux-aarch64")
    }
}
impl Drop for TestCapture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn nix_qualification_records_the_actual_product_version_and_source() {
    let capture = TestCapture::new();
    let qualification = capture.qualification();
    assert_eq!(
        qualification.inventory.version,
        ProductVersion::parse_exact(env!("CARGO_PKG_VERSION")).unwrap()
    );
    assert_eq!(
        qualification.inventory.source_commit,
        fs::read_to_string(capture.0.join("source-commit.txt"))
            .unwrap()
            .trim()
    );
    qualification.verify().unwrap();
    assert!(!qualification.sign().is_empty());
    assert_eq!(
        construct_release(
            &qualification.inventory,
            &qualification.root,
            &qualification.rebuild,
            &[],
            vec![]
        )
        .err(),
        Some(ReleaseError::PartialSet)
    );
}

#[test]
fn staged_identity_rejects_wrong_source_version_build_inputs_and_metadata() {
    for mutation in [
        "source",
        "source-bytes",
        "target",
        "version",
        "input",
        "toolchain",
        "spdx",
        "provenance",
    ] {
        let capture = TestCapture::new();
        let mut qualification = capture.qualification();
        match mutation {
            "source" => qualification.inventory.source_commit = "f".repeat(40),
            "source-bytes" => {
                fs::write(qualification.root.join("source.tar"), b"different source").unwrap()
            },
            "target" => qualification.inventory.artifacts[0].target = "wrong-target".into(),
            "version" => qualification.inventory.version.patch += 1,
            "input" => qualification.inventory.inputs[0].version = "wrong-source-input".into(),
            "toolchain" => {
                let file = qualification
                    .inventory
                    .files
                    .iter_mut()
                    .find(|file| file.id == "toolchain.txt")
                    .unwrap();
                fs::write(qualification.root.join(&file.id), b"different compiler").unwrap();
                file.identity = FileIdentity::of(b"different compiler");
            },
            "spdx" | "provenance" => {
                let artifact = &qualification.inventory.artifacts[0];
                let id = if mutation == "spdx" {
                    &artifact.spdx
                } else {
                    &artifact.provenance
                }
                .clone();
                fs::write(qualification.root.join(&id), b"{}").unwrap();
                qualification
                    .inventory
                    .files
                    .iter_mut()
                    .find(|file| file.id == id)
                    .unwrap()
                    .identity = FileIdentity::of(b"{}");
            },
            _ => unreachable!(),
        }
        assert_eq!(
            qualification.verify(),
            Err(ReleaseError::IdentityMismatch),
            "{mutation}"
        );
    }
}

#[test]
fn exact_source_test_keys_remain_visible_but_shipped_credentials_are_refused() {
    let key = include_bytes!(
        "../../../positron-runtime/tests/native_transport/fixtures/api-test-key.pem"
    );
    let capture = TestCapture::new();
    fs::write(capture.0.join("source.tar"), key).unwrap();
    let qualification = capture.qualification();
    assert_eq!(
        fs::read(qualification.root.join("source.tar")).unwrap(),
        key
    );
    assert_eq!(
        inspect_file(&qualification.root, "source.tar", &[]),
        Err(ReleaseError::SecretDetected)
    );
    qualification.verify().unwrap();
    let scan: Value = serde_json::from_slice(
        &fs::read(qualification.root.join("source-input-scan.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(scan["result"], "release refused: SecretDetected");

    for id in [
        "positron",
        "positron.nar",
        "openapi.json",
        "positron.spdx.json",
    ] {
        let capture = TestCapture::new();
        let mut qualification = capture.qualification();
        fs::write(qualification.root.join(id), key).unwrap();
        qualification
            .inventory
            .files
            .iter_mut()
            .find(|file| file.id == id)
            .unwrap()
            .identity = FileIdentity::of(key);
        assert_eq!(
            qualification.verify(),
            Err(ReleaseError::SecretDetected),
            "{id}"
        );
    }
}

#[test]
fn captured_catalog_compatibility_uses_the_canonical_current_epoch() {
    let capture = TestCapture::new();
    let qualification = capture.qualification();
    assert_eq!(
        qualification
            .inventory
            .compatibility
            .persistent
            .writable_epoch,
        positron_kernel::FormatEpoch::CATALOG_V2.value()
    );
    assert!(
        qualification
            .inventory
            .compatibility
            .persistent
            .readable_epochs
            .contains(&positron_kernel::FormatEpoch::CATALOG_V2.value())
    );
}
