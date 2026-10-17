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
