//! Actual NuGet payloads, private native signatures and signed Release Manifest binding.
mod support;
use positron_release::*;
#[test]
fn generated_dotnet_package_binds_native_signature_manifest_and_independent_payload() {
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .arg(root.join("sdk/tests/dotnet/release.py"))
        .arg(&fixture.root)
        .arg(support::keyless::SOURCE_COMMIT)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let unsigned = std::fs::read(
        fixture
            .root
            .join("dotnet-payload-first/Positron.SDK.1.0.0.nupkg"),
    )
    .unwrap();
    let rebuilt = std::fs::read(
        fixture
            .root
            .join("dotnet-payload-second/Positron.SDK.1.0.0.nupkg"),
    )
    .unwrap();
    assert!(unsigned == rebuilt, "independent NuGet payload differs");
    let native = support::dotnet::package(unsigned, "1.0.0");
    fixture.replace_dotnet_publication(native);
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
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::SdkDotNet)
        .unwrap();
    let artifact = &fixture.inventory.artifacts[index];
    for file in [
        &artifact.file,
        &artifact.spdx,
        &artifact.cyclonedx,
        &artifact.provenance,
        &artifact.publication.proof,
    ] {
        let path = fixture.root.join("bundle").join(file);
        let original = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"{}").unwrap();
        assert!(verify(&signed).is_err(), "{file}");
        std::fs::write(path, original).unwrap();
    }
    let payload = artifact.payload.as_ref().unwrap();
    let path = fixture.rebuild.join(payload);
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"rebuild drift").unwrap();
    assert_eq!(verify(&signed).err(), Some(ReleaseError::Unreproducible));
    std::fs::write(path, original).unwrap();
    let mut changed = signed.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(verify(&changed).is_err());
    assert_eq!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            &artifact.file,
            &[b"Positron.SDK".to_vec()]
        )
        .err(),
        Some(ReleaseError::SecretDetected)
    );
    assert!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            &artifact.file,
            &[b"private-dotnet-secret-canary".to_vec()]
        )
        .is_ok()
    );
}
#[test]
fn dotnet_registry_identity_cannot_be_replaced_by_another_native_package() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|a| a.surface == Surface::SdkDotNet)
        .unwrap();
    fixture.inventory.artifacts[index]
        .publication
        .native_subject = "pkg:nuget/TinyJson@1.0.0".into();
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
fn rewrite(bytes: &[u8], path: &str, replacement: &[u8]) -> Vec<u8> {
    use std::io::{Cursor, Read, Write};
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let mut file = archive.by_index_raw(index).unwrap();
        let name = std::str::from_utf8(file.name_raw()).unwrap().to_owned();
        let mut content = Vec::new();
        match file.compression() {
            zip::CompressionMethod::Stored => {
                file.read_to_end(&mut content).unwrap();
            },
            zip::CompressionMethod::DEFLATE => {
                flate2::read::DeflateDecoder::new(&mut file)
                    .read_to_end(&mut content)
                    .unwrap();
            },
            _ => panic!("fixture compression"),
        };
        writer
            .start_file(
                &name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer
            .write_all(if name == path { replacement } else { &content })
            .unwrap();
    }
    writer.finish().unwrap().into_inner()
}
#[test]
fn dotnet_metadata_and_generated_member_mutations_are_refused() {
    for field in [
        "name",
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
            .position(|a| a.surface == Surface::SdkDotNet)
            .unwrap();
        let artifact = &fixture.inventory.artifacts[index];
        let unsigned = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(artifact.payload.as_ref().unwrap()),
        )
        .unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&unsigned)).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut zip.by_name("positron/release.json").unwrap(),
            &mut bytes,
        )
        .unwrap();
        let mut metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        metadata[field] = serde_json::json!("drift");
        let changed = rewrite(
            &unsigned,
            "positron/release.json",
            &serde_json::to_vec(&metadata).unwrap(),
        );
        let native = support::dotnet::package(changed, "1.0.0");
        fixture.replace_dotnet_publication(native);
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
    for path in [
        "positron/contract.json",
        "positron/api/positron.proto",
        "positron/api/schema.sha256",
        "positron/source/Codec.cs",
        "positron/source/Query.cs",
        "positron/source/BatchTracker.cs",
        "positron/source/PositronException.cs",
        "positron/source/Client.cs",
        "positron/source/Types.cs",
        "lib/net8.0/Positron.SDK.dll",
        "lib/net8.0/Positron.SDK.xml",
        "positron/LICENSE",
        "Positron.SDK.nuspec",
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|a| a.surface == Surface::SdkDotNet)
            .unwrap();
        let unsigned = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(fixture.inventory.artifacts[index].payload.as_ref().unwrap()),
        )
        .unwrap();
        let changed = rewrite(&unsigned, path, b"{}");
        fixture.replace_dotnet_publication(support::dotnet::package(changed, "1.0.0"));
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
