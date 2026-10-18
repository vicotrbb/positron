use positron_release::{FileIdentity, ReleaseError, inspect_file};
#[test]
fn inspection_hashes_exact_bytes_and_refuses_credentials_and_non_files() {
    let root =
        std::env::temp_dir().join(format!("positron-release-inspect-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("good"), b"functional payload").unwrap();
    assert_eq!(
        inspect_file(&root, "good", &[]).unwrap(),
        FileIdentity::of(b"functional payload")
    );
    std::fs::write(
        root.join("secret"),
        format!(
            "ghp_{}",
            (0..36)
                .map(|index| char::from(b'a' + index % 26))
                .collect::<String>()
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        inspect_file(&root, "secret", &[]).err(),
        Some(ReleaseError::SecretDetected)
    );
    assert_eq!(
        inspect_file(&root, "../good", &[]).err(),
        Some(ReleaseError::Invalid)
    );
    assert_eq!(
        inspect_file(&root, "missing", &[]).err(),
        Some(ReleaseError::Unavailable)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inspection_refuses_complete_twenty_character_aws_access_key_ids() {
    let root = std::env::temp_dir().join(format!("positron-release-aws-id-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for prefix in ["AKIA", "ASIA"] {
        let value = format!(
            "{prefix}{}",
            (0..16)
                .map(|index| char::from(b'A' + index))
                .collect::<String>()
        );
        std::fs::write(root.join("credential"), value).unwrap();
        assert_eq!(
            inspect_file(&root, "credential", &[]).err(),
            Some(ReleaseError::SecretDetected)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inspection_accepts_adjacent_public_literals_after_a_pem_marker() {
    let root = std::env::temp_dir().join(format!(
        "positron-release-public-literals-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    // Public production constants from publication.rs and positron-config/lib.rs
    // can be adjacent in a compiled binary; they are not encoded private-key DER.
    let contents = [
        "-----BEGIN EC PRIVATE KEY-----\n",
        "A",
        "/predicate/buildDefinition/externalParameters/cosign",
        "/payload",
        "https",
    ]
    .concat();
    std::fs::write(root.join("public"), &contents).unwrap();
    assert_eq!(
        inspect_file(&root, "public", &[]),
        Ok(FileIdentity::of(contents.as_bytes()))
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inspection_refuses_real_and_truncated_der_private_keys_across_chunks() {
    use base64::Engine;
    use der::Reader;
    use rand::SeedableRng;
    use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePrivateKey};
    let mut random = rand::rngs::StdRng::seed_from_u64(113);
    let rsa = rsa::RsaPrivateKey::new(&mut random, 2048).unwrap();
    let ec = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let mut reader = der::SliceReader::new(ec.as_ref()).unwrap();
    let sec1 = reader
        .sequence(|reader| {
            let _: u8 = reader.decode()?;
            let _: der::asn1::AnyRef<'_> = reader.decode()?;
            let inner: der::asn1::OctetStringRef<'_> = reader.decode()?;
            Ok(inner.as_bytes().to_vec())
        })
        .unwrap();
    let root =
        std::env::temp_dir().join(format!("positron-release-real-pem-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for (label, bytes) in [
        (
            "PRIVATE KEY",
            rsa.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        ),
        (
            "RSA PRIVATE KEY",
            rsa.to_pkcs1_der().unwrap().as_bytes().to_vec(),
        ),
        ("EC PRIVATE KEY", sec1),
        ("PRIVATE KEY", ec.as_ref().to_vec()),
    ] {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        for truncated in [false, true] {
            for boundary in [0, 65_520] {
                let mut contents = vec![b' '; boundary];
                let newline = if boundary == 0 { "\n" } else { "\r\n" };
                contents.extend_from_slice(format!("-----BEGIN {label}-----{newline}").as_bytes());
                if truncated {
                    contents.extend_from_slice(encoded.get(..32).unwrap().as_bytes());
                } else {
                    // Legal PEM wrapping/whitespace must retain detection.
                    for chunk in encoded.as_bytes().chunks(16) {
                        contents.extend_from_slice(chunk);
                        contents.extend_from_slice(newline.as_bytes());
                    }
                    contents.extend_from_slice(format!("\n-----END {label}-----\n").as_bytes());
                }
                std::fs::write(root.join("private"), contents).unwrap();
                assert_eq!(
                    inspect_file(&root, "private", &[]),
                    Err(ReleaseError::SecretDetected)
                );
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn inspection_preserves_token_thresholds_alphabets_and_embedded_prefixes() {
    let root = std::env::temp_dir().join(format!("positron-release-prefix-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for (prefix, minimum, aws) in [
        ("ghp_", 32, false),
        ("github_pat_", 32, false),
        ("sk-proj-", 32, false),
        ("AKIA", 16, true),
        ("ASIA", 16, true),
    ] {
        for leading in ["", "embedded_word"] {
            for length in [minimum - 1, minimum, minimum + 4] {
                for byte in if aws { [b'A', b'9'] } else { [b'A', b'_'] } {
                    let mut contents = format!("{leading}{prefix}").into_bytes();
                    contents.extend(std::iter::repeat_n(byte, length));
                    contents.push(b'.');
                    std::fs::write(root.join("token"), &contents).unwrap();
                    let expected = if length >= minimum {
                        Err(ReleaseError::SecretDetected)
                    } else {
                        Ok(FileIdentity::of(&contents))
                    };
                    assert_eq!(inspect_file(&root, "token", &[]), expected);
                }
            }
            let mut contents = format!("{leading}{prefix}").into_bytes();
            contents.extend(std::iter::repeat_n(b'A', minimum - 1));
            contents.push(if aws { b'a' } else { b'.' });
            contents.extend(std::iter::repeat_n(b'A', 8));
            std::fs::write(root.join("token"), &contents).unwrap();
            assert_eq!(
                inspect_file(&root, "token", &[]),
                Ok(FileIdentity::of(&contents))
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
