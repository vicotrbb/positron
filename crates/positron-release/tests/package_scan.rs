use positron_release::{ReleaseError, scan_release_contents};
use std::io::Write;

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    out.write_all(bytes).unwrap();
    out.finish().unwrap()
}
fn cpio(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        1,
        0o100644,
        0,
        0,
        1,
        0,
        bytes.len(),
        0,
        0,
        0,
        0,
        name.len() + 1,
        0
    )
    .into_bytes();
    out.extend(name.as_bytes());
    out.push(0);
    out.resize(out.len().next_multiple_of(4), 0);
    out.extend(bytes);
    out.resize(out.len().next_multiple_of(4), 0);
    out
}
fn ar(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    out.extend(
        format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name,
            0,
            0,
            0,
            "100644",
            bytes.len()
        )
        .as_bytes(),
    );
    out.extend(bytes);
    if !bytes.len().is_multiple_of(2) {
        out.push(b'\n');
    }
    out
}
fn scan(bytes: &[u8], suffix: &str) -> Result<(), ReleaseError> {
    let path = std::env::temp_dir().join(format!(
        "positron-package-scan-{}-{suffix}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("package"), bytes).unwrap();
    let result = scan_release_contents(
        &path,
        "package",
        &[b"decoded-package-secret-canary".to_vec()],
    );
    std::fs::remove_dir_all(path).unwrap();
    result
}
#[test]
fn debian_ar_members_are_decoded_before_secret_screening() {
    let compressed = gzip(b"decoded-package-secret-canary");
    assert_eq!(
        scan(&ar("data.tar.gz/", &compressed), "deb"),
        Err(ReleaseError::SecretDetected)
    );
}
#[test]
fn rpm_newc_members_are_decoded_recursively_before_secret_screening() {
    let mut bytes = cpio("./etc/config.gz", &gzip(b"decoded-package-secret-canary"));
    bytes.extend(cpio("TRAILER!!!", &[]));
    assert_eq!(scan(&bytes, "cpio"), Err(ReleaseError::SecretDetected));
}
#[test]
fn native_archive_framing_refuses_truncated_members_and_oversized_names() {
    let mut bytes = ar("data.tar.gz/", b"clean");
    bytes.truncate(bytes.len() - 3);
    assert_eq!(scan(&bytes, "ar-truncated"), Err(ReleaseError::Invalid));
    let bytes = cpio(&"x".repeat(4097), b"");
    assert_eq!(scan(&bytes, "cpio-name"), Err(ReleaseError::LimitExceeded));
}

#[test]
fn nested_package_members_share_the_enclosing_depth_and_member_budgets() {
    let mut nested = b"clean".to_vec();
    for _ in 0..5 {
        nested = ar("nested", &nested);
    }
    assert_eq!(scan(&nested, "depth"), Err(ReleaseError::LimitExceeded));
    let mut many = Vec::new();
    for _ in 0..16385 {
        many.extend(cpio("./empty", &[]));
    }
    many.extend(cpio("TRAILER!!!", &[]));
    assert_eq!(scan(&many, "members"), Err(ReleaseError::LimitExceeded));
}
#[test]
fn malformed_cpio_and_unsupported_debian_compression_fail_explicitly() {
    let mut bytes = cpio("./config", b"clean");
    bytes.truncate(bytes.len() - 5);
    assert_eq!(scan(&bytes, "cpio-truncated"), Err(ReleaseError::Invalid));
    assert_eq!(
        scan(&ar("data.tar.xz/", b"unsupported"), "xz"),
        Err(ReleaseError::Unsupported)
    );
    let mut bytes = cpio("TRAILER!!!", &[]);
    bytes.extend(b"hidden tail");
    assert_eq!(scan(&bytes, "cpio-tail"), Err(ReleaseError::Invalid));
}
#[test]
fn genuine_native_rpm_payloads_are_decoded_without_extracting_files() {
    assert_eq!(
        scan(
            include_bytes!("fixtures/positron-1.0.0-1.aarch64.rpm"),
            "native-rpm"
        ),
        Ok(())
    );
}

#[test]
fn rpm_decoding_refuses_unbounded_headers_and_unbound_mutable_regions() {
    let original = include_bytes!("fixtures/positron-1.0.0-1.aarch64.rpm");
    for (offset, value, error) in [
        (96, 0, ReleaseError::Invalid),
        (104, 4097, ReleaseError::LimitExceeded),
        (128, 62, ReleaseError::Invalid),
        (156, 0, ReleaseError::Invalid),
        (184, 445, ReleaseError::Invalid),
        (108, 8_388_609, ReleaseError::LimitExceeded),
        (112, 63, ReleaseError::Invalid),
        (120, 0, ReleaseError::Invalid),
        (132, 0, ReleaseError::Unsupported),
    ] {
        let mut bytes = original.to_vec();
        bytes[offset..offset + 4].copy_from_slice(&u32::to_be_bytes(value));
        assert_eq!(scan(&bytes, &format!("rpm-{offset}")), Err(error));
    }
    assert_eq!(
        scan(&original[..100], "rpm-truncated"),
        Err(ReleaseError::Invalid)
    );
}
#[test]
fn rpm_screening_covers_signature_metadata_and_the_decoded_payload() {
    let original = include_bytes!("fixtures/positron-1.0.0-1.aarch64.rpm");
    let word = |offset: usize| {
        u32::from_be_bytes(original[offset..offset + 4].try_into().unwrap()) as usize
    };
    let main = (96 + 16 + word(104) * 16 + word(108)).next_multiple_of(8);
    let payload = main + 16 + word(main + 8) * 16 + word(main + 12);
    let canary = b"decoded-package-secret-canary";
    let mut metadata = original.to_vec();
    metadata[4000..4000 + canary.len()].copy_from_slice(canary);
    assert_eq!(
        scan(&metadata, "rpm-metadata"),
        Err(ReleaseError::SecretDetected)
    );
    let mut archive = cpio("./config", canary);
    archive.extend(cpio("TRAILER!!!", &[]));
    let mut bytes = original[..payload].to_vec();
    bytes.extend(gzip(&archive));
    assert_eq!(
        scan(&bytes, "rpm-payload-secret"),
        Err(ReleaseError::SecretDetected)
    );
}

#[test]
fn cpio_metadata_after_the_initial_prefix_is_screened_as_serialized_bytes() {
    let mut bytes = cpio("./first", &[0; 1024]);
    let mut second = cpio("./second", &[]);
    let canary = b"decoded-package-secret-canary";
    second[6..6 + canary.len()].copy_from_slice(canary);
    bytes.extend(second);
    bytes.extend(cpio("TRAILER!!!", &[]));
    assert_eq!(
        scan(&bytes, "cpio-metadata"),
        Err(ReleaseError::SecretDetected)
    );
}

#[test]
fn appended_rpm_header_entries_cannot_escape_the_signed_immutable_region() {
    let mut bytes = include_bytes!("fixtures/positron-1.0.0-1.aarch64.rpm").to_vec();
    let word =
        |offset: usize| u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    let main = (96 + 16 + word(104) * 16 + word(108)).next_multiple_of(8);
    let count = word(main + 8);
    let data = main + 16 + count * 16;
    let mut dribble = Vec::new();
    for value in [99999u32, 7, 0, 1] {
        dribble.extend(value.to_be_bytes());
    }
    bytes.splice(data..data, dribble);
    bytes[main + 8..main + 12].copy_from_slice(&((count + 1) as u32).to_be_bytes());
    assert_eq!(scan(&bytes, "rpm-dribble"), Err(ReleaseError::Invalid));
}

#[test]
fn package_container_headers_enforce_membership_framing_and_declared_size_limits() {
    assert_eq!(scan(&ar("plain/", b"clean"), "ar-clean"), Ok(()));
    let mut bad_header = ar("plain/", b"clean");
    bad_header[67] = b'x';
    assert_eq!(scan(&bad_header, "ar-header"), Err(ReleaseError::Invalid));
    let mut bad_pad = ar("plain/", b"clean");
    *bad_pad.last_mut().unwrap() = 0;
    assert_eq!(scan(&bad_pad, "ar-pad"), Err(ReleaseError::Invalid));
    let mut huge = ar("plain/", b"");
    huge[56..66].copy_from_slice(b"536870913 ");
    assert_eq!(scan(&huge, "ar-huge"), Err(ReleaseError::LimitExceeded));
    for (offset, value, error) in [
        (0, b"070702".as_slice(), ReleaseError::Unsupported),
        (54, b"20000001", ReleaseError::LimitExceeded),
        (102, b"00000001", ReleaseError::Invalid),
    ] {
        let mut bytes = cpio("./x", &[]);
        bytes[offset..offset + value.len()].copy_from_slice(value);
        assert_eq!(scan(&bytes, &format!("cpio-field-{offset}")), Err(error));
    }
    let mut no_nul = cpio("./x", &[]);
    no_nul[113] = b'x';
    assert_eq!(scan(&no_nul, "cpio-nul"), Err(ReleaseError::Invalid));
    let mut bad_pad = cpio("./x", &[]);
    bad_pad[114] = 1;
    assert_eq!(scan(&bad_pad, "cpio-pad"), Err(ReleaseError::Invalid));
    assert_eq!(
        scan(&cpio("TRAILER!!!", b"x"), "cpio-trailer-data"),
        Err(ReleaseError::Invalid)
    );
}
#[test]
fn rpm_profile_rejects_unsupported_compression_padding_and_payload_framing() {
    let original = include_bytes!("fixtures/positron-1.0.0-1.aarch64.rpm");
    let word = |offset: usize| {
        u32::from_be_bytes(original[offset..offset + 4].try_into().unwrap()) as usize
    };
    let sig_end = 96 + 16 + word(104) * 16 + word(108);
    let main = sig_end.next_multiple_of(8);
    let payload = main + 16 + word(main + 8) * 16 + word(main + 12);
    let mut padding = original.to_vec();
    padding[sig_end] = 1;
    assert_eq!(scan(&padding, "rpm-padding"), Err(ReleaseError::Invalid));
    let mut compressed = original.to_vec();
    let compressor = compressed[main..payload]
        .windows(5)
        .position(|bytes| bytes == b"gzip\0")
        .unwrap()
        + main;
    compressed[compressor] = b'x';
    assert_eq!(
        scan(&compressed, "rpm-compressor"),
        Err(ReleaseError::Unsupported)
    );
    let mut bad_magic = original.to_vec();
    bad_magic[payload] = 0;
    assert_eq!(
        scan(&bad_magic, "rpm-payload-magic"),
        Err(ReleaseError::Invalid)
    );
    assert_eq!(
        positron_release::rpm_functional_payload(&vec![0; (64 << 20) + 1]),
        Err(ReleaseError::LimitExceeded)
    );
}
