//! Actual Python wheel identity belongs to the existing signed Release Trust path.
mod support;
use positron_release::*;
use std::io::{Cursor, Read, Write};

fn rewrite(bytes: &[u8], mut change: impl FnMut(&str, Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut output = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let mut entry = archive.by_index_raw(index).unwrap();
        let name = entry.name().unwrap().into_owned();
        let mut bytes = Vec::new();
        let mut input: Box<dyn Read> = if entry.compression() == zip::CompressionMethod::Stored {
            Box::new(&mut entry)
        } else {
            Box::new(flate2::read::DeflateDecoder::new(&mut entry))
        };
        input.read_to_end(&mut bytes).unwrap();
        let bytes = change(&name, bytes);
        output
            .start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        output.write_all(&bytes).unwrap();
    }
    output.finish().unwrap().into_inner()
}

fn repair_record(bytes: &[u8]) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut record = String::new();
    let mut record_path = String::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let path = entry.name().unwrap().into_owned();
        if path.ends_with("/RECORD") {
            record_path = path;
            continue;
        }
        let mut content = Vec::new();
        entry.read_to_end(&mut content).unwrap();
        record.push_str(&format!(
            "{path},sha256={},{}\n",
            URL_SAFE_NO_PAD.encode(Sha256::digest(&content)),
            content.len()
        ));
    }
    record.push_str(&format!("{record_path},,\n"));
    rewrite(bytes, |path, bytes| {
        if path == record_path {
            record.as_bytes().to_vec()
        } else {
            bytes
        }
    })
}

#[test]
fn signed_inventory_refuses_python_sdk_without_canonical_bindings() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkPython)
        .unwrap();
    let artifact = &fixture.inventory.artifacts[index];
    let bytes = std::fs::read(fixture.root.join("bundle").join(&artifact.file)).unwrap();
    let invalid = rewrite(&bytes, |path, bytes| {
        if path == "positron_sdk/release.json" {
            b"{}".to_vec()
        } else {
            bytes
        }
    });
    fixture.replace_artifact(index, &invalid, &invalid);
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
fn python_wheel_identity_schema_and_dependency_mutations_fail_closed() {
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
            .position(|artifact| artifact.surface == Surface::SdkPython)
            .unwrap();
        let bytes = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let invalid = rewrite(&bytes, |path, bytes| {
            if path != "positron_sdk/release.json" {
                return bytes;
            }
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value[field] = serde_json::json!("unbound");
            serde_json::to_vec(&value).unwrap()
        });
        fixture.replace_artifact(index, &invalid, &invalid);
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
        "positron_sdk/api/positron.proto",
        "positron_sdk/api/schema.sha256",
        "positron_sdk/client.py",
        "positron_sdk/types.py",
        "positron_sdk/query.py",
        "positron_sdk/contract.json",
        "positron_sdk-1.0.0.dist-info/METADATA",
        "positron_sdk-1.0.0.dist-info/WHEEL",
        "positron_sdk-1.0.0.dist-info/RECORD",
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == Surface::SdkPython)
            .unwrap();
        let bytes = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let invalid = rewrite(
            &bytes,
            |name, bytes| if name == path { vec![] } else { bytes },
        );
        fixture.replace_artifact(index, &invalid, &invalid);
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
    for path in [
        "positron_sdk-1.0.0.dist-info/METADATA",
        "positron_sdk-1.0.0.dist-info/WHEEL",
    ] {
        let mut fixture = support::Fixture::new();
        let index = fixture
            .inventory
            .artifacts
            .iter()
            .position(|artifact| artifact.surface == Surface::SdkPython)
            .unwrap();
        let bytes = std::fs::read(
            fixture
                .root
                .join("bundle")
                .join(&fixture.inventory.artifacts[index].file),
        )
        .unwrap();
        let invalid = rewrite(&bytes, |name, mut bytes| {
            if name == path {
                bytes.extend_from_slice(if path.ends_with("METADATA") {
                    b"Requires-Dist: untrusted\n"
                } else {
                    b"Tag: py3-none-any\n"
                });
            }
            bytes
        });
        fixture.replace_artifact(index, &invalid, &invalid);
        let expected = if path.ends_with("METADATA") {
            ReleaseError::Unsupported
        } else {
            ReleaseError::IdentityMismatch
        };
        assert_eq!(
            construct_release(
                &fixture.inventory,
                &fixture.root.join("bundle"),
                &fixture.rebuild,
                &[],
                vec![]
            )
            .err(),
            Some(expected)
        );
    }
}

#[test]
fn actual_python_wheel_is_bound_to_signed_release_and_independent_payload() {
    let mut fixture =
        support::Fixture::new_with_api(include_bytes!("../../../api/positron/v1/positron.proto"));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let python = std::env::var_os("POSITRON_PYTHON").unwrap_or_else(|| "python3".into());
    let script = r#"
import json, os, pathlib, shutil, subprocess, sys
root, target, commit = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
source = target / 'python-source'
shutil.copytree(root / 'sdk/python', source, ignore=shutil.ignore_patterns('__pycache__', 'build', 'dist', '*.egg-info'))
project = source / 'pyproject.toml'
project.write_text(project.read_text().replace('version = "0.0.0"', 'version = "1.0.0"'))
release = source / 'positron_sdk/release.json'
metadata = json.loads(release.read_text()); metadata.update(version='1.0.0', source_commit=commit)
release.write_text(json.dumps(metadata, sort_keys=True))
env = dict(os.environ, SOURCE_DATE_EPOCH='1700000000', PYTHONHASHSEED='0')
for build in ['first', 'second']:
    subprocess.run([sys.executable, '-m', 'build', '--wheel', '--no-isolation', '--outdir', str(target / build), str(source)], env=env, check=True, capture_output=True)
first = next((target / 'first').glob('*.whl')); second = next((target / 'second').glob('*.whl'))
assert first.read_bytes() == second.read_bytes()
"#;
    let output = std::process::Command::new(python)
        .args(["-c", script])
        .arg(root)
        .arg(&fixture.root)
        .arg(support::keyless::SOURCE_COMMIT)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Python wheel build: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let package = std::fs::read(
        fixture
            .root
            .join("first/positron_sdk-1.0.0-py3-none-any.whl"),
    )
    .unwrap();
    let rebuilt = std::fs::read(
        fixture
            .root
            .join("second/positron_sdk-1.0.0-py3-none-any.whl"),
    )
    .unwrap();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkPython)
        .unwrap();
    fixture.replace_artifact(index, &package, &rebuilt);
    fixture.refresh_python_publication(package.clone());
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
    let mut changed_signature = signed.clone();
    *changed_signature.last_mut().unwrap() ^= 1;
    assert!(verify(&changed_signature).is_err());
    let artifact = &fixture.inventory.artifacts[index];
    let payload = artifact.payload.as_ref().unwrap();
    std::fs::write(fixture.rebuild.join(payload), b"independent wheel drift").unwrap();
    assert_eq!(verify(&signed).err(), Some(ReleaseError::Unreproducible));
    std::fs::write(fixture.rebuild.join(payload), &rebuilt).unwrap();
    for file in [
        &artifact.provenance,
        &artifact.spdx,
        &artifact.cyclonedx,
        &artifact.file,
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
            &[b"Generated typed client".to_vec()]
        )
        .err(),
        Some(ReleaseError::SecretDetected)
    );
    assert!(
        scan_release_contents(
            &fixture.root.join("bundle"),
            &artifact.file,
            &[b"private-python-secret-canary".to_vec()]
        )
        .is_ok()
    );
}

#[test]
fn python_wheel_refuses_conflicting_local_archive_identity() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkPython)
        .unwrap();
    let mut bytes = std::fs::read(
        fixture
            .root
            .join("bundle")
            .join(&fixture.inventory.artifacts[index].file),
    )
    .unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let local = archive.by_index_raw(0).unwrap().header_start() as usize;
    drop(archive);
    bytes[local + 30] ^= 1;
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

#[test]
fn python_wheel_refuses_conflicting_core_metadata_headers() {
    let mut fixture = support::Fixture::new();
    let index = fixture
        .inventory
        .artifacts
        .iter()
        .position(|artifact| artifact.surface == Surface::SdkPython)
        .unwrap();
    let bytes = std::fs::read(
        fixture
            .root
            .join("bundle")
            .join(&fixture.inventory.artifacts[index].file),
    )
    .unwrap();
    let invalid = rewrite(&bytes, |path, mut bytes| {
        if path.ends_with("/METADATA") {
            bytes.extend_from_slice(b"Name: unbound-name\n");
        }
        bytes
    });
    let invalid = repair_record(&invalid);
    fixture.replace_artifact(index, &invalid, &invalid);
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
