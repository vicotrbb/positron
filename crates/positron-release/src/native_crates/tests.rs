use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const NAME: &str = "positron-sdk";
const VERSION: &str = "1.1.0";
const COMMIT: &str = "193b5bd7d3985809503963ae400594ea16df31cf";
const REPOSITORY: &str = "vicotrbb/positron";
const MANIFEST: &[u8] =
    b"[package]\nname = \"positron-sdk\"\nversion = \"1.1.0\"\nedition = \"2024\"\n";

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(gzip);
    for (name, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{NAME}-{VERSION}/{name}"), *bytes)
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn proof(bytes: &[u8]) -> Value {
    json!({"profile":"crates-io-oidc-upload-no-offline-receipt-v1",
            "index":{"name":NAME,"vers":VERSION,"cksum":crate::inventory::hex(&Sha256::digest(bytes)),"yanked":false},
            "trustpub":{"provider":"github","repository":REPOSITORY,"run_id":"28987632348","sha":COMMIT}})
}

#[test]
fn validates_crates_io_projection_and_normalized_package_identity() {
    let vcs = serde_json::to_vec(&json!({"git":{"sha1":COMMIT},"path_in_vcs":"sdk/rust"})).unwrap();
    let bytes = archive(&[
        ("Cargo.toml", MANIFEST),
        ("src/lib.rs", b"pub struct Client;\n"),
        (".cargo_vcs_info.json", &vcs),
    ]);
    assert_eq!(
        verify(&proof(&bytes), &bytes, NAME, VERSION, COMMIT, REPOSITORY),
        Ok(())
    );
}
fn check(bytes: &[u8]) -> Result<(), ReleaseError> {
    verify(&proof(bytes), bytes, NAME, VERSION, COMMIT, REPOSITORY)
}

#[test]
fn rejects_mismatched_or_ambiguous_native_metadata() {
    let bytes = archive(&[("Cargo.toml", MANIFEST)]);
    for (pointer, value) in [
        ("/index/name", json!("other")),
        ("/index/vers", json!("1.2.0")),
        ("/index/yanked", json!(true)),
        ("/trustpub/repository", json!("other/project")),
        (
            "/trustpub/sha",
            json!("0000000000000000000000000000000000000000"),
        ),
    ] {
        let mut metadata = proof(&bytes);
        *metadata.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            verify(&metadata, &bytes, NAME, VERSION, COMMIT, REPOSITORY),
            Err(ReleaseError::IdentityMismatch)
        );
    }
    for value in [
        json!("0"),
        json!("01"),
        json!("+1"),
        json!(1),
        json!("18446744073709551616"),
    ] {
        let mut metadata = proof(&bytes);
        metadata["trustpub"]["run_id"] = value;
        assert_eq!(
            verify(&metadata, &bytes, NAME, VERSION, COMMIT, REPOSITORY),
            Err(ReleaseError::Invalid)
        );
    }
    let mut metadata = proof(&bytes);
    metadata["index"]["extra"] = json!(true);
    assert_eq!(
        verify(&metadata, &bytes, NAME, VERSION, COMMIT, REPOSITORY),
        Err(ReleaseError::Invalid)
    );
    metadata = proof(&bytes);
    metadata["index"]["cksum"] = json!("0".repeat(64));
    assert_eq!(
        verify(&metadata, &bytes, NAME, VERSION, COMMIT, REPOSITORY),
        Err(ReleaseError::Authentication)
    );
    metadata = proof(&bytes);
    metadata["trustpub"]["provider"] = json!("gitlab");
    assert_eq!(
        verify(&metadata, &bytes, NAME, VERSION, COMMIT, REPOSITORY),
        Err(ReleaseError::Unsupported)
    );
}

#[test]
fn rejects_package_and_embedded_source_disagreement() {
    assert_eq!(
        check(&archive(&[("src/lib.rs", b"")])),
        Err(ReleaseError::Invalid)
    );
    assert_eq!(
        check(&archive(&[(
            "Cargo.toml",
            b"[package]\nname='other'\nversion='1.1.0'\n"
        )])),
        Err(ReleaseError::IdentityMismatch)
    );
    assert_eq!(
        check(&archive(&[(
            "Cargo.toml",
            b"[package]\nname='positron-sdk'\nversion={workspace=true}\n"
        )])),
        Err(ReleaseError::IdentityMismatch)
    );
    assert_eq!(
        check(&archive(&[(
            "Cargo.toml",
            b"[package]\nname='positron-sdk'\nname='other'\n"
        )])),
        Err(ReleaseError::Invalid)
    );
    for vcs in [
        json!({"git":{"sha1":"0000000000000000000000000000000000000000"},"path_in_vcs":""}),
        json!({"git":{"sha1":COMMIT,"dirty":true},"path_in_vcs":""}),
    ] {
        let encoded = serde_json::to_vec(&vcs).unwrap();
        assert_eq!(
            check(&archive(&[
                ("Cargo.toml", MANIFEST),
                (".cargo_vcs_info.json", &encoded)
            ])),
            Err(ReleaseError::IdentityMismatch)
        );
    }
    let vcs =
        serde_json::to_vec(&json!({"git":{"sha1":COMMIT,"dirty":false},"path_in_vcs":""})).unwrap();
    assert_eq!(
        check(&archive(&[
            ("Cargo.toml", MANIFEST),
            (".cargo_vcs_info.json", &vcs)
        ])),
        Ok(())
    );
}

#[test]
fn rejects_duplicate_case_and_directory_aliases() {
    for files in [
        vec![("Cargo.toml", MANIFEST), ("Cargo.toml", MANIFEST)],
        vec![("Cargo.toml", MANIFEST), ("cargo.toml", MANIFEST)],
        vec![("Cargo.toml", MANIFEST), ("src", b""), ("src/lib.rs", b"")],
        vec![("Cargo.toml", MANIFEST), ("src/lib.rs", b""), ("src", b"")],
    ] {
        assert_eq!(check(&archive(&files)), Err(ReleaseError::Invalid));
    }
}

#[test]
fn rejects_corrupt_gzip_concatenation_and_hidden_tar_members() {
    use std::io::Write;
    let bytes = archive(&[("Cargo.toml", MANIFEST)]);
    let mut corrupt = bytes.clone();
    let position = corrupt.len() - 8;
    corrupt[position] ^= 1;
    assert_eq!(check(&corrupt), Err(ReleaseError::Invalid));
    let mut concatenated = bytes.clone();
    concatenated.extend_from_slice(&bytes);
    assert_eq!(check(&concatenated), Err(ReleaseError::Invalid));
    let mut junk = bytes.clone();
    junk.push(0);
    assert_eq!(check(&junk), Err(ReleaseError::Invalid));
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .read_to_end(&mut tar)
        .unwrap();
    tar.extend_from_slice(b"hidden member");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&tar).unwrap();
    assert_eq!(check(&gzip.finish().unwrap()), Err(ReleaseError::Invalid));
}

#[test]
fn bounds_manifest_members_and_metadata_before_parsing() {
    assert_eq!(
        check(&archive(&[("Cargo.toml", &vec![b' '; (1 << 20) + 1])])),
        Err(ReleaseError::LimitExceeded)
    );
    let bytes = archive(&[("Cargo.toml", MANIFEST)]);
    let mut metadata = proof(&bytes);
    metadata["trustpub"]["repository"] = json!("a".repeat(257));
    assert_eq!(
        verify(&metadata, &bytes, NAME, VERSION, COMMIT, REPOSITORY),
        Err(ReleaseError::LimitExceeded)
    );
    let mut files = vec![("Cargo.toml", MANIFEST)];
    let paths: Vec<String> = (0..16_384).map(|i| format!("file{i}")).collect();
    files.extend(paths.iter().map(|path| (path.as_str(), b"".as_slice())));
    assert_eq!(check(&archive(&files)), Err(ReleaseError::LimitExceeded));
}

#[test]
fn refuses_links_extensions_traversal_and_oversized_declared_members() {
    use std::io::Write;
    let bytes = archive(&[("Cargo.toml", MANIFEST)]);
    let mut original = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .read_to_end(&mut original)
        .unwrap();
    for (path, kind, size, expected) in [
        (
            "positron-sdk-1.1.0/../Cargo.toml",
            b'0',
            MANIFEST.len() as u64,
            ReleaseError::Invalid,
        ),
        (
            "other-1.1.0/Cargo.toml",
            b'0',
            MANIFEST.len() as u64,
            ReleaseError::IdentityMismatch,
        ),
        (
            "positron-sdk-1.1.0/Cargo.toml",
            b'2',
            0,
            ReleaseError::Unsupported,
        ),
        (
            "positron-sdk-1.1.0/Cargo.toml",
            b'x',
            0,
            ReleaseError::Unsupported,
        ),
        (
            "positron-sdk-1.1.0/Cargo.toml",
            b'L',
            0,
            ReleaseError::Unsupported,
        ),
        (
            "positron-sdk-1.1.0/Cargo.toml",
            b'0',
            MAX_MEMBER + 1,
            ReleaseError::LimitExceeded,
        ),
    ] {
        let mut tar = original.clone();
        let header = tar::Header::from_byte_slice(&tar[..512]);
        let mut edited = header.clone();
        edited.as_mut_bytes()[..100].fill(0);
        edited.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        edited.set_entry_type(tar::EntryType::new(kind));
        edited.set_size(size);
        edited.set_cksum();
        tar[..512].copy_from_slice(edited.as_bytes());
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&tar).unwrap();
        assert_eq!(check(&gzip.finish().unwrap()), Err(expected));
    }
}
