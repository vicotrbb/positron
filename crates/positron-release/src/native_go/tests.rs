use super::*;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use signed_note::{Note, StandardSigner};
use std::io::{Cursor, Write};

const MODULE: &str = "example.com/positron/sdk";
const VERSION: &str = "v1.1.0";
const GO_MOD: &[u8] = b"module example.com/positron/sdk\n\ngo 1.24.0\n";
// Independently evaluated from Go dirhash.Hash1's documented file-name/content algorithm.
const ZIP_H1: &str = "h1:w3qGBXoQifonINWp7uZBXeTtDefG3LIbEn2/soRZfGY=";
const MOD_H1: &str = "h1:z6D8mEr+xQgDU2Kjbi4WZrFqBfvRm1Pcajnv7JSzfL8=";

fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        writer
            .start_file(
                format!("{MODULE}@{VERSION}/{name}"),
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn authority(seed: u8) -> (String, StandardSigner) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let name = "sumdb.test.invalid";
    let mut public = vec![1];
    public.extend(key.public_key().as_ref());
    let id = signed_note::key_id(name, &public);
    let mut private = vec![1];
    private.extend([seed; 32]);
    let signer = StandardSigner::new(&format!(
        "PRIVATE+KEY+{name}+{id:08x}+{}",
        B64.encode(private)
    ))
    .unwrap();
    (format!("{name}+{id:08x}+{}", B64.encode(public)), signer)
}

fn signed_note(text: &str) -> String {
    let (_, signer) = authority(45);
    let mut note = Note::new(text.as_bytes(), &[]).unwrap();
    note.add_sigs(&[&signer]).unwrap();
    String::from_utf8(note.to_bytes()).unwrap()
}

fn tree(size: u64, hash: &str) -> String {
    signed_note(&format!("go.sum database tree\n{size}\n{hash}\n"))
}

fn fixture() -> (Value, Value, Vec<u8>) {
    let (verifier_key, _) = authority(45);
    let text = format!("{MODULE} {VERSION} {ZIP_H1}\n{MODULE} {VERSION}/go.mod {MOD_H1}\n");
    let hash = sigstore_merkle::hash_leaf(text.as_bytes());
    let checkpoint = tree(1, &B64.encode(hash.as_bytes()));
    let root = json!({"verifier_key":verifier_key,"checkpoint":checkpoint});
    let proof = json!({"record":{"id":0,"text":text},"checkpoint":checkpoint,"inclusion":[],"consistency":[]});
    (
        root,
        proof,
        archive(&[("sdk.go", b"package positron\n"), ("go.mod", GO_MOD)]),
    )
}

#[test]
fn authenticates_both_go_hashes_under_installed_sumdb_checkpoint() {
    let (root, proof, bytes) = fixture();
    assert_eq!(verify(&root, &proof, &bytes, MODULE, VERSION), Ok(()));
    // Go's HashZip hashes sorted paths and content, not ZIP entry ordering.
    let reordered = archive(&[("go.mod", GO_MOD), ("sdk.go", b"package positron\n")]);
    assert_ne!(bytes, reordered);
    assert_eq!(verify(&root, &proof, &reordered, MODULE, VERSION), Ok(()));
}

#[test]
fn bounds_implicit_directory_collision_metadata() {
    let (root, proof, _) = fixture();
    let names = (0..5)
        .map(|index| format!("d{index}/{}file.go", "a/".repeat(1020)))
        .collect::<Vec<_>>();
    let mut files = vec![("go.mod", GO_MOD)];
    files.extend(names.iter().map(|name| (name.as_str(), b"x".as_slice())));
    assert_eq!(
        verify(&root, &proof, &archive(&files), MODULE, VERSION),
        Err(ReleaseError::LimitExceeded)
    );
}

#[test]
fn authenticates_official_go_record_hash_inclusion_and_tree_growth() {
    // Go's golden RecordHash("hello world") from golang/mod/sumdb/tlog/note_test.go.
    const PRIOR: &str = "TszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=";
    // Independent SHA256 calculation over the literal native record and RFC 6962 prefix bytes.
    const LEAF: &str = "EZXAaf21+bRrELBtzSfe266eeUWNMeIq1rdiI7UC8MU=";
    const ROOT: &str = "SxP6cdMlKoMpaEECbSGvl0SauRUuTnAs9Y/WHVL5EAs=";
    let (mut root, mut proof, bytes) = fixture();
    root["checkpoint"] = tree(1, PRIOR).into();
    proof["record"]["id"] = 1.into();
    proof["checkpoint"] = tree(2, ROOT).into();
    proof["inclusion"] = json!([PRIOR]);
    proof["consistency"] = json!([LEAF]);
    assert_eq!(verify(&root, &proof, &bytes, MODULE, VERSION), Ok(()));
    for (path, replacement) in [
        ("consistency", json!([])),
        ("consistency", json!([PRIOR])),
        ("inclusion", json!([LEAF])),
        ("inclusion", json!([PRIOR, LEAF])),
    ] {
        let mut bad = proof.clone();
        bad[path] = replacement;
        assert_eq!(
            verify(&root, &bad, &bytes, MODULE, VERSION),
            Err(ReleaseError::Authentication)
        );
    }
    root["checkpoint"] = tree(2, ROOT).into();
    proof["consistency"] = json!([]);
    assert_eq!(verify(&root, &proof, &bytes, MODULE, VERSION), Ok(()));
    proof["checkpoint"] = tree(1, PRIOR).into();
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Authentication)
    );
    let (mut root, proof, bytes) = fixture();
    root["checkpoint"] = tree(0, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=").into();
    assert_eq!(verify(&root, &proof, &bytes, MODULE, VERSION), Ok(()));
    root["checkpoint"] = tree(0, PRIOR).into();
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
}

#[test]
fn accepts_independently_encoded_deflate_module_zip() {
    // Python zipfile, DEFLATE, fixed 1980 timestamps, same two file contents.
    let bytes = B64.decode("UEsDBBQAAAAIAAAAIQCk7/LVEwAAABEAAAAmAAAAZXhhbXBsZS5jb20vcG9zaXRyb24vc2RrQHYxLjEuMC9zZGsuZ28rSEzOTkxPVSjIL84sKcrP4wIAUEsDBBQAAAAIAAAAIQDLMnqtLQAAACsAAAAmAAAAZXhhbXBsZS5jb20vcG9zaXRyb24vc2RrQHYxLjEuMC9nby5tb2TLzU8pzUlVSK1IzC3ISdVLzs/VL8gvziwpys/TL07J5uJKz1cw1DMy0TPgAgBQSwECFAMUAAAACAAAACEApO/y1RMAAAARAAAAJgAAAAAAAAAAAAAAgAEAAAAAZXhhbXBsZS5jb20vcG9zaXRyb24vc2RrQHYxLjEuMC9zZGsuZ29QSwECFAMUAAAACAAAACEAyzJ6rS0AAAArAAAAJgAAAAAAAAAAAAAAgAFXAAAAZXhhbXBsZS5jb20vcG9zaXRyb24vc2RrQHYxLjEuMC9nby5tb2RQSwUGAAAAAAIAAgCoAAAAyAAAAAAA").unwrap();
    let (root, proof, _) = fixture();
    assert_eq!(verify(&root, &proof, &bytes, MODULE, VERSION), Ok(()));
}

#[test]
fn rejects_untrusted_keys_tampered_records_and_malformed_checkpoints() {
    let (root, proof, bytes) = fixture();
    let mut wrong_key = root.clone();
    wrong_key["verifier_key"] = authority(46).0.into();
    assert_eq!(
        verify(&wrong_key, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Authentication)
    );
    let mut bad = proof.clone();
    bad["record"]["text"] = "forged native checksum record\n".into();
    assert_eq!(
        verify(&root, &bad, &bytes, MODULE, VERSION),
        Err(ReleaseError::Authentication)
    );
    let mut bad = proof.clone();
    bad["record"]["id"] = 1.into();
    assert_eq!(
        verify(&root, &bad, &bytes, MODULE, VERSION),
        Err(ReleaseError::Authentication)
    );
    let mut bad = proof.clone();
    bad["checkpoint"] = bad["checkpoint"]
        .as_str()
        .unwrap()
        .replace("\n1\n", "\n2\n")
        .into();
    assert_eq!(
        verify(&root, &bad, &bytes, MODULE, VERSION),
        Err(ReleaseError::Authentication)
    );
    for (text, error) in [
        ("malformed note".to_owned(), ReleaseError::Invalid),
        (
            signed_note("other tree\n1\nEZXAaf21+bRrELBtzSfe266eeUWNMeIq1rdiI7UC8MU=\n"),
            ReleaseError::IdentityMismatch,
        ),
        (
            signed_note("go.sum database tree\n01\nEZXAaf21+bRrELBtzSfe266eeUWNMeIq1rdiI7UC8MU=\n"),
            ReleaseError::Invalid,
        ),
        (
            signed_note(
                "go.sum database tree\n9223372036854775808\nEZXAaf21+bRrELBtzSfe266eeUWNMeIq1rdiI7UC8MU=\n",
            ),
            ReleaseError::Invalid,
        ),
        (
            signed_note("go.sum database tree\n1\ninvalid\n"),
            ReleaseError::Invalid,
        ),
        (
            signed_note(
                "go.sum database tree\n1\nEZXAaf21+bRrELBtzSfe266eeUWNMeIq1rdiI7UC8MU=\nextension\n",
            ),
            ReleaseError::Unsupported,
        ),
    ] {
        let mut bad = proof.clone();
        bad["checkpoint"] = text.into();
        assert_eq!(verify(&root, &bad, &bytes, MODULE, VERSION), Err(error));
    }
    let mut bad = proof.clone();
    bad["inclusion"] = json!(["not-base64"]);
    assert_eq!(
        verify(&root, &bad, &bytes, MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
    let mut bad = proof.clone();
    bad["inclusion"] = json!(["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="]);
    assert_eq!(
        verify(&root, &bad, &bytes, MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
    let mut bad = proof.clone();
    bad["unexpected"] = true.into();
    assert_eq!(
        verify(&root, &bad, &bytes, MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
    let mut bad = root.clone();
    bad["unexpected"] = true.into();
    assert_eq!(
        verify(&bad, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
}

#[test]
fn authenticating_one_go_hash_cannot_replace_the_other() {
    for (old, new) in [(MOD_H1, ZIP_H1), (ZIP_H1, MOD_H1)] {
        let (mut root, mut proof, bytes) = fixture();
        let text = proof["record"]["text"].as_str().unwrap().replace(old, new);
        let hash = sigstore_merkle::hash_leaf(text.as_bytes());
        let checkpoint = tree(1, &B64.encode(hash.as_bytes()));
        proof["record"]["text"] = text.into();
        root["checkpoint"] = checkpoint.clone().into();
        proof["checkpoint"] = checkpoint.into();
        assert_eq!(
            verify(&root, &proof, &bytes, MODULE, VERSION),
            Err(ReleaseError::Authentication)
        );
    }
}

#[test]
fn rejects_native_archive_identity_content_and_path_confusion() {
    let (root, proof, _) = fixture();
    for (name, error) in [
        ("../sdk.go", ReleaseError::Invalid),
        ("a\\sdk.go", ReleaseError::Invalid),
        ("a\nsdk.go", ReleaseError::Invalid),
        ("nested/go.mod", ReleaseError::Invalid),
        ("GO.MOD", ReleaseError::Invalid),
        ("con.txt", ReleaseError::Invalid),
        ("NUL", ReleaseError::Invalid),
        ("name.", ReleaseError::Invalid),
        ("é.go", ReleaseError::Unsupported),
        ("empty/", ReleaseError::Unsupported),
    ] {
        let bytes = archive(&[("go.mod", GO_MOD), (name, b"package positron\n")]);
        assert_eq!(
            verify(&root, &proof, &bytes, MODULE, VERSION),
            Err(error),
            "{name}"
        );
    }
    for names in [["sdk.go", "SDK.go"], ["dir", "dir/a"], ["Dir/a", "dir/b"]] {
        let bytes = archive(&[("go.mod", GO_MOD), (names[0], b"a"), (names[1], b"b")]);
        assert_eq!(
            verify(&root, &proof, &bytes, MODULE, VERSION),
            Err(ReleaseError::Invalid)
        );
    }
    let bytes = archive(&[("go.mod", GO_MOD), ("sdk.go", b"package impostor\n")]);
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Authentication)
    );
    assert_eq!(
        verify(&root, &proof, &bytes, "example.com/other", VERSION),
        Err(ReleaseError::IdentityMismatch)
    );
    let bytes = archive(&[("sdk.go", b"package positron\n")]);
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Unsupported)
    );
    let bytes = archive(&[("go.mod", b"module example.com/other\n")]);
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::IdentityMismatch)
    );
    let bytes = archive(&[(
        "go.mod",
        b"// older profile\nmodule example.com/positron/sdk\n",
    )]);
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Unsupported)
    );
    let mut bytes = archive(&[("go.mod", GO_MOD), ("sdk.go", b"a"), ("dup.go", b"b")]);
    for offset in bytes
        .windows(6)
        .enumerate()
        .filter_map(|(i, window)| (window == b"dup.go").then_some(i))
        .collect::<Vec<_>>()
    {
        bytes
            .get_mut(offset..offset + 6)
            .unwrap()
            .copy_from_slice(b"sdk.go");
    }
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
}

fn change_zip_headers(bytes: &mut [u8], local_offset: usize, central_offset: usize, value: &[u8]) {
    let offsets = bytes
        .windows(4)
        .enumerate()
        .filter_map(|(i, window)| {
            if window == b"PK\x03\x04" {
                Some(i + local_offset)
            } else if window == b"PK\x01\x02" {
                Some(i + central_offset)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for offset in offsets {
        bytes
            .get_mut(offset..offset + value.len())
            .unwrap()
            .copy_from_slice(value);
    }
}

#[test]
fn rejects_encryption_symlinks_unsupported_compression_and_size_or_crc_mismatch() {
    let (root, proof, bytes) = fixture();
    for (local, central, value, error) in [
        (6, 8, vec![1, 0], ReleaseError::Unsupported),
        (8, 10, vec![12, 0], ReleaseError::Unsupported),
        (
            22,
            24,
            (u32::try_from(MAX_MEMBER).unwrap() + 1)
                .to_le_bytes()
                .to_vec(),
            ReleaseError::LimitExceeded,
        ),
        (22, 24, 0_u32.to_le_bytes().to_vec(), ReleaseError::Invalid),
    ] {
        let mut bad = bytes.clone();
        change_zip_headers(&mut bad, local, central, &value);
        assert_eq!(verify(&root, &proof, &bad, MODULE, VERSION), Err(error));
    }
    let mut bad = bytes.clone();
    let offset = bad
        .windows(7)
        .position(|window| window == b"package")
        .unwrap();
    *bad.get_mut(offset).unwrap() ^= 1;
    assert_eq!(
        verify(&root, &proof, &bad, MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_symlink(
            format!("{MODULE}@{VERSION}/sdk.go"),
            "other",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    let symlink = writer.finish().unwrap().into_inner();
    assert_eq!(
        verify(&root, &proof, &symlink, MODULE, VERSION),
        Err(ReleaseError::Unsupported)
    );
}

#[test]
fn rejects_unbounded_inputs_and_unsupported_go_identity_profiles() {
    let (root, proof, bytes) = fixture();
    for (field, value) in [
        (
            "inclusion",
            json!(vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; 65]),
        ),
        (
            "consistency",
            json!(vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; 65]),
        ),
        ("checkpoint", json!("x".repeat(65_537))),
    ] {
        let mut bad = proof.clone();
        bad[field] = value;
        assert_eq!(
            verify(&root, &bad, &bytes, MODULE, VERSION),
            Err(ReleaseError::LimitExceeded)
        );
    }
    let mut bad = proof.clone();
    bad["record"]["text"] = "x".repeat(4097).into();
    assert_eq!(
        verify(&root, &bad, &bytes, MODULE, VERSION),
        Err(ReleaseError::LimitExceeded)
    );
    let mut bad = root.clone();
    bad["verifier_key"] = "x".repeat(1025).into();
    assert_eq!(
        verify(&bad, &proof, &bytes, MODULE, VERSION),
        Err(ReleaseError::LimitExceeded)
    );
    assert_eq!(
        verify(&root, &proof, &vec![0; MAX_ARCHIVE + 1], MODULE, VERSION),
        Err(ReleaseError::LimitExceeded)
    );
    assert_eq!(
        verify(&root, &proof, &bytes, &"a".repeat(513), VERSION),
        Err(ReleaseError::LimitExceeded)
    );
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, &"v".repeat(65)),
        Err(ReleaseError::LimitExceeded)
    );
    for version in [
        "main",
        "1.1.0",
        "v1.1",
        "v01.1.0",
        "v1.1.0-rc.1",
        "v1.1.0+incompatible",
        "v0.0.0-20250101000000-0123456789ab",
    ] {
        assert_eq!(
            verify(&root, &proof, &bytes, MODULE, version),
            Err(ReleaseError::Unsupported),
            "{version}"
        );
    }
    assert_eq!(
        verify(&root, &proof, &bytes, "gopkg.in/yaml.v2", "v2.0.0"),
        Err(ReleaseError::Unsupported)
    );
    assert_eq!(
        verify(&root, &proof, &bytes, MODULE, "v2.0.0"),
        Err(ReleaseError::IdentityMismatch)
    );
    assert_eq!(
        verify(&root, &proof, &[], MODULE, VERSION),
        Err(ReleaseError::Invalid)
    );
}
