//! JVM archive identity is authenticated by the existing signed Release Trust path.
mod support;
use positron_release::*;
use std::io::{Cursor, Read, Write};
fn rewrite(bytes: &[u8], path: &str, replacement: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut output = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let mut found = false;
    for index in 0..archive.len() {
        let mut entry = archive.by_index_raw(index).unwrap();
        let name = entry.name().unwrap().into_owned();
        if name.ends_with('/') {
            continue;
        }
        let mut data = Vec::new();
        match entry.compression() {
            zip::CompressionMethod::Stored => {
                entry.read_to_end(&mut data).unwrap();
            },
            zip::CompressionMethod::DEFLATE => {
                flate2::read::DeflateDecoder::new(&mut entry)
                    .read_to_end(&mut data)
                    .unwrap();
            },
            _ => panic!("unsupported fixture"),
        }
        if name == path {
            data = replacement.into();
            found = true;
        }
        output
            .start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        output.write_all(&data).unwrap();
    }
    if !found {
        output
            .start_file(
                path,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        output.write_all(replacement).unwrap();
    }
    output.finish().unwrap().into_inner()
}
#[test]
fn java_sdk_refuses_unbound_generated_jar_metadata() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::SdkJava && a.file == "sdk-1.0.0.jar")
        .unwrap();
    let bytes = std::fs::read(
        fixture
            .root
            .join("bundle")
            .join(&fixture.inventory.artifacts[index].file),
    )
    .unwrap();
    let changed = rewrite(&bytes, "dev/positron/release.json", b"{}");
    fixture.replace_artifact(index, &changed, &changed);
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
fn actual_java_jars_bind_signed_inventory_and_independent_rebuild() {
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .arg(root.join("sdk/tests/java/release.py"))
        .arg(&fixture.root)
        .arg(support::keyless::SOURCE_COMMIT)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut actual = std::collections::BTreeMap::new();
    for suffix in [".pom", ".jar", "-sources.jar", "-javadoc.jar"] {
        let file = format!("sdk-1.0.0{suffix}");
        let bytes = std::fs::read(fixture.root.join("payload-first").join(&file)).unwrap();
        let rebuilt = std::fs::read(fixture.root.join("payload-second").join(&file)).unwrap();
        assert_eq!(bytes, rebuilt, "{file}");
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|a| a.surface == Surface::SdkJava && a.file == file)
            .unwrap();
        fixture.replace_artifact(index, &bytes, &rebuilt);
        actual.insert(file, bytes);
    }
    fixture.refresh_java_publications(&actual);
    let (signed, construction) = fixture.published_with_native(|_, _| {}, |_, _| {}, |_, _| {});
    let verify = |manifest: &[u8]| {
        verify_release(
            manifest,
            &construction.inventory_bytes,
            fixture.key(),
            &fixture.trust(),
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            "linux-x86_64",
            &[],
        )
    };
    verify(&signed).unwrap();
    let mut changed = signed.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(verify(&changed).is_err());
    for artifact in fixture
        .inventory
        .artifacts
        .iter()
        .filter(|a| a.surface == Surface::SdkJava)
    {
        for file in [
            &artifact.file,
            &artifact.spdx,
            &artifact.cyclonedx,
            &artifact.provenance,
        ] {
            let path = fixture.root.join("bundle").join(file);
            let original = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"{}").unwrap();
            assert!(verify(&signed).is_err());
            std::fs::write(path, original).unwrap();
        }
        if let Some(payload) = &artifact.payload {
            let path = fixture.rebuild.join(payload);
            let original = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"rebuild drift").unwrap();
            assert_eq!(verify(&signed).err(), Some(ReleaseError::Unreproducible));
            std::fs::write(path, original).unwrap();
        }
    }
    assert_eq!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            "sdk-1.0.0.jar",
            &[b"dev.positron.sdk".to_vec()]
        )
        .err(),
        Some(ReleaseError::SecretDetected)
    );
    assert!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            "sdk-1.0.0.jar",
            &[b"private-java-secret-canary".to_vec()]
        )
        .is_ok()
    );
}

#[test]
fn java_sdk_metadata_and_canonical_member_mutations_are_refused() {
    for field in [
        "group",
        "artifact",
        "version",
        "source_commit",
        "api_version",
        "schema_digest",
        "release_manifest_surface",
        "registry",
        "generator",
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|a| a.surface == Surface::SdkJava && a.file == "sdk-1.0.0.jar")
            .unwrap();
        let bytes = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        let mut release = Vec::new();
        archive
            .by_name("dev/positron/release.json")
            .unwrap()
            .read_to_end(&mut release)
            .unwrap();
        let mut metadata: serde_json::Value = serde_json::from_slice(&release).unwrap();
        metadata[field] = serde_json::json!("unbound");
        let changed = rewrite(
            &bytes,
            "dev/positron/release.json",
            &serde_json::to_vec(&metadata).unwrap(),
        );
        fixture.replace_artifact(index, &changed, &changed);
        assert_eq!(
            construct_release(
                &fixture.inventory,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                &[],
                vec![]
            )
            .err(),
            Some(ReleaseError::IdentityMismatch),
            "{field}"
        );
    }
    for (file, path) in [
        ("sdk-1.0.0.jar", "dev/positron/api/positron.proto"),
        ("sdk-1.0.0.jar", "dev/positron/api/schema.sha256"),
        ("sdk-1.0.0.jar", "dev/positron/contract.json"),
        ("sdk-1.0.0.jar", "dev/positron/Client.class"),
        ("sdk-1.0.0.jar", "META-INF/MANIFEST.MF"),
        ("sdk-1.0.0.jar", "META-INF/maven/dev.positron/sdk/pom.xml"),
        ("sdk-1.0.0-sources.jar", "dev/positron/Codec.java"),
        (
            "sdk-1.0.0-javadoc.jar",
            "dev.positron.sdk/dev/positron/Client.html",
        ),
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|a| a.surface == Surface::SdkJava && a.file == file)
            .unwrap();
        let bytes = std::fs::read(fixture.root.join("bundle").join(file)).unwrap();
        let changed = rewrite(&bytes, path, b"");
        fixture.replace_artifact(index, &changed, &changed);
        assert!(
            construct_release(
                &fixture.inventory,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                &[],
                vec![]
            )
            .is_err(),
            "{file}:{path}"
        );
    }
}

#[test]
fn java_dependency_sboms_and_local_zip_identity_cannot_diverge() {
    for key in ["spdx", "cyclonedx"] {
        let mut fixture = support::Fixture::new();
        let artifact = fixture
            .inventory
            .artifacts
            .iter()
            .find(|a| a.surface == Surface::SdkJava && a.file == "sdk-1.0.0.jar")
            .unwrap();
        let id = if key == "spdx" {
            artifact.spdx.clone()
        } else {
            artifact.cyclonedx.clone()
        };
        let path = fixture.root.join("bundle").join(&id);
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        document[if key == "spdx" {
            "packages"
        } else {
            "components"
        }]
        .as_array_mut()
        .unwrap()
        .truncate(1);
        let bytes = serde_json::to_vec(&document).unwrap();
        std::fs::write(path, &bytes).unwrap();
        fixture
            .inventory
            .files
            .iter_mut()
            .find(|f| f.id == id)
            .unwrap()
            .identity = FileIdentity::of(&bytes);
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
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::SdkJava && a.file == "sdk-1.0.0.jar")
        .unwrap();
    let mut bytes = std::fs::read(fixture.root.join("bundle").join("sdk-1.0.0.jar")).unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let member = archive.by_name("dev/positron/release.json").unwrap();
    let offset = member.header_start() as usize + 30;
    drop(member);
    drop(archive);
    bytes[offset] = b'x';
    fixture.replace_artifact(index, &bytes, &bytes);
    assert_eq!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[],
            vec![]
        )
        .err(),
        Some(ReleaseError::Invalid)
    );
}
