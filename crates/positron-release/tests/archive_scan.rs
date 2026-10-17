use positron_release::{ReleaseError, scan_release_contents};
use std::io::Write;
#[test]
fn a_secret_inside_a_gzip_source_archive_is_scanned_after_decoding() {
    let path =
        std::env::temp_dir().join(format!("positron-release-archive-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let credential = format!(
        "ghp_{}",
        (0..36)
            .map(|index| char::from(b'a' + index % 26))
            .collect::<String>()
    );
    let compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(compressed);
    let mut header = tar::Header::new_gnu();
    header.set_size(credential.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    archive
        .append_data(&mut header, "source/config.txt", credential.as_bytes())
        .unwrap();
    let compressed = archive.into_inner().unwrap().finish().unwrap();
    std::fs::write(path.join("source.tgz"), compressed).unwrap();
    assert_eq!(
        scan_release_contents(&path, "source.tgz", &[]),
        Err(ReleaseError::SecretDetected)
    );
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn zip_source_packages_are_scanned_without_extracting_paths() {
    let path = std::env::temp_dir().join(format!("positron-release-zip-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let file = std::fs::File::create(path.join("sdk.zip")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "sdk/config.txt",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(b"plant-secret-canary-123").unwrap();
    zip.finish().unwrap();
    assert_eq!(
        scan_release_contents(&path, "sdk.zip", &[b"plant-secret-canary-123".to_vec()]),
        Err(ReleaseError::SecretDetected)
    );
    assert!(!path.join("sdk").exists());
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn duplicate_zip_names_cannot_hide_an_unscanned_secret_member() {
    let path =
        std::env::temp_dir().join(format!("positron-release-duplicate-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file(
        "a.txt",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(&vec![b'p'; 1024]).unwrap();
    zip.write_all(b"hidden-member-canary-123").unwrap();
    zip.start_file(
        "b.txt",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(b"clean").unwrap();
    let mut bytes = zip.finish().unwrap().into_inner();
    for offset in 0..bytes.len() - 4 {
        if bytes.get(offset..offset + 5) == Some(b"b.txt") {
            bytes[offset] = b'a';
        }
    }
    std::fs::write(path.join("duplicate.zip"), bytes).unwrap();
    assert_eq!(
        scan_release_contents(
            &path,
            "duplicate.zip",
            &[b"hidden-member-canary-123".to_vec()]
        ),
        Err(ReleaseError::Invalid)
    );
    std::fs::remove_dir_all(path).unwrap();
}

fn metadata_tar(kind: u8, declared: u64, contents: &[u8]) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_path("metadata").unwrap();
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_size(declared);
    header.set_mode(0o644);
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(contents);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    let mut file = tar::Header::new_gnu();
    file.set_path("source/clean.txt").unwrap();
    file.set_size(0);
    file.set_mode(0o644);
    file.set_cksum();
    bytes.extend_from_slice(file.as_bytes());
    bytes.extend_from_slice(&[0; 1024]);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&bytes).unwrap();
    gzip.finish().unwrap()
}

#[test]
fn tar_extension_metadata_is_scanned_before_automatic_expansion() {
    let path = std::env::temp_dir().join(format!(
        "positron-release-tar-metadata-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    let canary = b"metadata-hidden-canary-123";
    let payload = b"38 comment=metadata-hidden-canary-123\n";
    assert_eq!(payload.len(), 38);
    for (kind, contents) in [(b'x', payload.as_slice()), (b'K', canary.as_slice())] {
        std::fs::write(
            path.join("metadata.tgz"),
            metadata_tar(kind, contents.len() as u64, contents),
        )
        .unwrap();
        assert_eq!(
            scan_release_contents(&path, "metadata.tgz", &[canary.to_vec()]),
            Err(ReleaseError::SecretDetected)
        );
    }
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn declared_oversized_tar_extensions_are_refused_before_reading_their_payload() {
    let path =
        std::env::temp_dir().join(format!("positron-release-tar-limit-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    for kind in [b'L', b'K', b'x'] {
        std::fs::write(
            path.join("oversized.tgz"),
            metadata_tar(kind, 536_870_913, &[]),
        )
        .unwrap();
        assert_eq!(
            scan_release_contents(&path, "oversized.tgz", &[]),
            Err(ReleaseError::LimitExceeded)
        );
    }
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn tar_metadata_members_consume_the_member_budget() {
    let path =
        std::env::temp_dir().join(format!("positron-release-tar-count-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    let mut extension = tar::Header::new_gnu();
    extension.set_path("metadata").unwrap();
    extension.set_entry_type(tar::EntryType::new(b'K'));
    extension.set_size(0);
    extension.set_cksum();
    let mut file = tar::Header::new_gnu();
    file.set_path("source/clean.txt").unwrap();
    file.set_size(0);
    file.set_cksum();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for _ in 0..8193 {
        gzip.write_all(extension.as_bytes()).unwrap();
        gzip.write_all(file.as_bytes()).unwrap();
    }
    gzip.write_all(&[0; 1024]).unwrap();
    std::fs::write(path.join("members.tgz"), gzip.finish().unwrap()).unwrap();
    assert_eq!(
        scan_release_contents(&path, "members.tgz", &[]),
        Err(ReleaseError::LimitExceeded)
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn gnu_sparse_expansion_is_explicitly_unsupported() {
    let path = std::env::temp_dir().join(format!(
        "positron-release-tar-sparse-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("sparse.tgz"), metadata_tar(b'S', 0, &[])).unwrap();
    assert_eq!(
        scan_release_contents(&path, "sparse.tgz", &[]),
        Err(ReleaseError::Unsupported)
    );
    std::fs::remove_dir_all(path).unwrap();
}
