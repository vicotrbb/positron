//! Actual Go module identity is bound by the existing signed Release Trust path.
mod support;
use positron_release::*;
use std::io::{Cursor, Read, Write};
fn rewrite(bytes: &[u8], field: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut output = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let name = entry.name().unwrap().into_owned();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        if let Some(path) = field.strip_prefix("file:") {
            if name.ends_with(&format!("/{path}")) {
                data.clear();
            }
        } else if name.ends_with("/release.json") {
            let mut metadata: serde_json::Value = serde_json::from_slice(&data).unwrap();
            metadata[field] = serde_json::json!("unbound");
            data = serde_json::to_vec(&metadata).unwrap();
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
    output.finish().unwrap().into_inner()
}
#[test]
fn go_sdk_refuses_unbound_generated_module_metadata() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkGo)
        .unwrap();
    let bytes = std::fs::read(
        fixture
            .root
            .join("bundle")
            .join(&fixture.inventory.artifacts[index].file),
    )
    .unwrap();
    let changed = rewrite(&bytes, "schema_digest");
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

fn actual_module(root: &std::path::Path) -> Vec<u8> {
    fn collect(
        root: &std::path::Path,
        directory: &std::path::Path,
        files: &mut Vec<(String, Vec<u8>)>,
    ) {
        let mut entries = std::fs::read_dir(directory)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if entry.file_type().unwrap().is_dir() {
                collect(root, &entry.path(), files);
            } else {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let mut data = std::fs::read(entry.path()).unwrap();
                if relative == "release.json" {
                    let mut metadata: serde_json::Value = serde_json::from_slice(&data).unwrap();
                    metadata["version"] = serde_json::json!("1.0.0");
                    metadata["source_commit"] = serde_json::json!(support::keyless::SOURCE_COMMIT);
                    data = serde_json::to_vec(&metadata).unwrap();
                }
                files.push((relative, data));
            }
        }
    }
    let mut files = Vec::new();
    collect(root, root, &mut files);
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        archive
            .start_file(
                format!("github.com/vicotrbb/positron/sdk/go@v1.0.0/{name}"),
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        archive.write_all(&bytes).unwrap();
    }
    archive.finish().unwrap().into_inner()
}
#[test]
fn actual_generated_go_module_binds_signed_inventory_and_independent_rebuild() {
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/go");
    let bytes = actual_module(&source);
    let rebuilt = actual_module(&source);
    assert_eq!(bytes, rebuilt);
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::SdkGo)
        .unwrap();
    fixture.replace_artifact(index, &bytes, &rebuilt);
    fixture.refresh_go_publication(bytes.clone());
    let (signed, construction) = fixture.published_with_native(|_, _| {}, |_, _| {}, |_, _| {});
    let verify = |signed: &[u8]| {
        verify_release(
            signed,
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
    let artifact = &fixture.inventory.artifacts[index];
    let payload = artifact.payload.as_ref().unwrap();
    std::fs::write(fixture.rebuild.join(payload), b"independent drift").unwrap();
    assert_eq!(verify(&signed).err(), Some(ReleaseError::Unreproducible));
    std::fs::write(fixture.rebuild.join(payload), &rebuilt).unwrap();
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
    assert_eq!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            &artifact.file,
            &[b"Code generated by positron-api".to_vec()]
        )
        .err(),
        Some(ReleaseError::SecretDetected)
    );
    assert!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            &artifact.file,
            &[b"private-go-secret-canary".to_vec()]
        )
        .is_ok()
    );
}
#[test]
fn go_module_identity_source_schema_and_generator_mutations_are_refused() {
    for field in [
        "module",
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
            .position(|a| a.surface == Surface::SdkGo)
            .unwrap();
        let original = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let changed = rewrite(&original, field);
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
}

#[test]
fn standard_deflated_go_module_is_accepted() {
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/go");
    let stored = actual_module(&source);
    let input = fixture.root.join("stored.zip");
    std::fs::write(&input, &stored).unwrap();
    let output=std::process::Command::new("python3").args(["-c", "import io,sys,zipfile\nz=zipfile.ZipFile(sys.argv[1]); b=io.BytesIO()\nwith zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as out:\n for name in z.namelist(): out.writestr(name,z.read(name))\nsys.stdout.buffer.write(b.getvalue())"]).arg(input).output().unwrap();
    assert!(output.status.success());
    let bytes = output.stdout;
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::SdkGo)
        .unwrap();
    fixture.replace_artifact(index, &bytes, &bytes);
    fixture.refresh_go_publication(bytes);
    assert!(
        construct_release(
            &fixture.inventory,
            &fixture.root.join("bundle"),
            &fixture.rebuild,
            &[],
            vec![]
        )
        .is_ok()
    );
}

#[test]
fn go_module_canonical_files_and_dependency_injection_fail_closed() {
    for path in [
        "go.mod",
        "release.json",
        "contract.json",
        "api/positron.proto",
        "api/schema.sha256",
        "types.go",
        "methods.go",
        "codec.go",
        "client.go",
        "query.go",
        "README.md",
        "LICENSE",
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|a| a.surface == Surface::SdkGo)
            .unwrap();
        let bytes = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let changed = rewrite(&bytes, &format!("file:{path}"));
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
            "{path}"
        );
    }
}
