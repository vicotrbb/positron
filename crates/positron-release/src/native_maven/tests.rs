use super::*;
use pgp::{
    composed::{
        Deserializable, DetachedSignature, DsaKeySize, KeyType, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey,
    },
    crypto::hash::HashAlgorithm,
    packet::{KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{Duration, KeyDetails, Password, Timestamp},
};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;

const NOW: u32 = 2_000_000_000;
const CONTENTS: &[u8] = b"independently reproducible Maven artifact\n";

fn key(seed: u64) -> SignedSecretKey {
    key_version(seed, KeyVersion::V4)
}

fn key_version(seed: u64, version: KeyVersion) -> SignedSecretKey {
    key_algorithm(
        seed,
        version,
        if version == KeyVersion::V6 {
            KeyType::Ed25519
        } else {
            KeyType::Ed25519Legacy
        },
    )
}

fn key_algorithm(seed: u64, version: KeyVersion, algorithm: KeyType) -> SignedSecretKey {
    SecretKeyParamsBuilder::default()
        .version(version)
        .key_type(algorithm)
        .can_certify(true)
        .can_sign(true)
        .created_at(Timestamp::from_secs(NOW - 1_000))
        .primary_user_id("Positron synthetic test publisher".into())
        .build()
        .unwrap()
        .generate(StdRng::seed_from_u64(seed))
        .unwrap()
}

fn config(key: &SignedSecretKey, typ: SignatureType, hash: HashAlgorithm) -> SignatureConfig {
    let mut config = if key.version() == KeyVersion::V6 {
        SignatureConfig::v6(&mut StdRng::seed_from_u64(94), typ, key.algorithm(), hash).unwrap()
    } else {
        SignatureConfig::v4(typ, key.algorithm(), hash)
    };
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            NOW - 100,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
    ];
    config
}

fn certificate(key: &SignedSecretKey, lifetime: Option<u32>) -> SignedPublicKey {
    let mut public = key.to_public_key();
    let mut certification = config(key, SignatureType::Key, HashAlgorithm::Sha256);
    let mut flags = KeyFlags::default();
    flags.set_sign(true);
    flags.set_certify(true);
    certification
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap());
    if let Some(seconds) = lifetime {
        certification.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
                seconds,
            )))
            .unwrap(),
        );
    }
    public.details.direct_signatures.push(
        certification
            .sign_key(&key.primary_key, &Password::empty(), &public.primary_key)
            .unwrap(),
    );
    public
}

fn root(public: &SignedPublicKey) -> Value {
    json!({"public_key":public.to_armored_string(None.into()).unwrap()})
}

fn proof(key: &SignedSecretKey, hash: HashAlgorithm, expiry: Option<u32>) -> Value {
    let mut signature = config(key, SignatureType::Binary, hash);
    if let Some(seconds) = expiry {
        signature.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::SignatureExpirationTime(Duration::from_secs(
                seconds,
            )))
            .unwrap(),
        );
    }
    let signature = signature
        .sign(&key.primary_key, &Password::empty(), CONTENTS)
        .unwrap();
    json!({"signature":DetachedSignature::new(signature).to_armored_string(None.into()).unwrap()})
}

#[test]
fn maven_authenticates_the_exact_artifact_with_the_installed_native_key() {
    let key = key(31);
    let root = root(&certificate(&key, None));
    let proof = proof(&key, HashAlgorithm::Sha256, None);
    assert_eq!(verify(&root, &proof, CONTENTS, NOW.into()), Ok(()));
    assert!(verify(&root, &proof, b"changed artifact", NOW.into()).is_err());
    assert!(
        verify(
            &self::root(&certificate(&self::key(32), None)),
            &proof,
            CONTENTS,
            NOW.into()
        )
        .is_err()
    );
}

#[test]
fn maven_refuses_expired_primary_keys_and_detached_signatures() {
    let key = key(31);
    let proof = proof(&key, HashAlgorithm::Sha256, None);
    assert_eq!(
        verify(
            &root(&certificate(&key, None)),
            &proof,
            CONTENTS,
            NOW.into()
        ),
        Ok(())
    );
    assert!(
        verify(
            &root(&certificate(&key, Some(500))),
            &proof,
            CONTENTS,
            NOW.into()
        )
        .is_err()
    );
    assert!(
        verify(
            &root(&certificate(&key, None)),
            &self::proof(&key, HashAlgorithm::Sha256, Some(50)),
            CONTENTS,
            NOW.into()
        )
        .is_err()
    );
}

#[test]
fn maven_refuses_a_cryptographically_revoked_primary_key() {
    let key = key(31);
    let mut public = certificate(&key, None);
    let proof = proof(&key, HashAlgorithm::Sha256, None);
    assert_eq!(verify(&root(&public), &proof, CONTENTS, NOW.into()), Ok(()));
    public.details.revocation_signatures.push(
        config(&key, SignatureType::KeyRevocation, HashAlgorithm::Sha256)
            .sign_key(&key.primary_key, &Password::empty(), &public.primary_key)
            .unwrap(),
    );
    assert!(verify(&root(&public), &proof, CONTENTS, NOW.into()).is_err());
}

#[test]
fn maven_refuses_weak_hash_selection_before_crypto() {
    let key = key(31);
    let root = root(&certificate(&key, None));
    let valid = proof(&key, HashAlgorithm::Sha256, None);
    assert_eq!(verify(&root, &valid, CONTENTS, NOW.into()), Ok(()));
    // Upstream already refuses to create weak Ed25519 signatures. Separately
    // prove that an untrusted weak hash declaration is refused at our boundary.
    assert!(
        config(&key, SignatureType::Binary, HashAlgorithm::Sha1)
            .sign(&key.primary_key, &Password::empty(), CONTENTS)
            .is_err()
    );
    let original = DetachedSignature::from_string(valid["signature"].as_str().unwrap())
        .unwrap()
        .0;
    let mut weak = original.signature.config().unwrap().clone();
    weak.hash_alg = HashAlgorithm::Sha1;
    let weak = pgp::packet::Signature::from_config(
        weak,
        original.signature.signed_hash_value().unwrap(),
        original.signature.signature().unwrap().clone(),
    )
    .unwrap();
    let weak =
        json!({"signature":DetachedSignature::new(weak).to_armored_string(None.into()).unwrap()});
    assert_eq!(
        verify(&root, &weak, CONTENTS, NOW.into()),
        Err(ReleaseError::Unsupported)
    );
}

#[test]
fn maven_never_discards_unsupported_certificate_packets() {
    let key = key(31);
    let mut public = certificate(&key, None);
    let proof = proof(&key, HashAlgorithm::Sha256, None);
    assert_eq!(verify(&root(&public), &proof, CONTENTS, NOW.into()), Ok(()));
    let detached = DetachedSignature::from_string(proof["signature"].as_str().unwrap())
        .unwrap()
        .0;
    // rPGP's general certificate parser drops a non-certification signature
    // after a User ID. The supported native profile must refuse it explicitly.
    public
        .details
        .users
        .first_mut()
        .unwrap()
        .signatures
        .push(detached.signature);
    assert_eq!(
        verify(&root(&public), &proof, CONTENTS, NOW.into()),
        Err(ReleaseError::Unsupported)
    );
}

#[test]
fn maven_authenticates_a_version_six_signing_primary() {
    let key = key_version(51, KeyVersion::V6);
    assert_eq!(
        verify(
            &root(&certificate(&key, None)),
            &proof(&key, HashAlgorithm::Sha512, None),
            CONTENTS,
            NOW.into()
        ),
        Ok(())
    );
}

#[test]
fn maven_refuses_future_signatures_and_latest_metadata_without_signing_authority() {
    let key = key(31);
    let mut public = certificate(&key, None);
    let proof = proof(&key, HashAlgorithm::Sha256, None);
    assert_eq!(verify(&root(&public), &proof, CONTENTS, NOW.into()), Ok(()));
    let mut future = config(&key, SignatureType::Binary, HashAlgorithm::Sha256);
    future
        .hashed_subpackets
        .retain(|packet| !matches!(packet.data, SubpacketData::SignatureCreationTime(_)));
    future.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            NOW + 1,
        )))
        .unwrap(),
    );
    let future = DetachedSignature::new(
        future
            .sign(&key.primary_key, &Password::empty(), CONTENTS)
            .unwrap(),
    );
    let future = json!({"signature":future.to_armored_string(None.into()).unwrap()});
    assert!(verify(&root(&public), &future, CONTENTS, NOW.into()).is_err());
    let mut no_signing = config(&key, SignatureType::Key, HashAlgorithm::Sha256);
    no_signing
        .hashed_subpackets
        .retain(|packet| !matches!(packet.data, SubpacketData::SignatureCreationTime(_)));
    no_signing.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            NOW - 99,
        )))
        .unwrap(),
    );
    public.details.direct_signatures.push(
        no_signing
            .sign_key(&key.primary_key, &Password::empty(), &public.primary_key)
            .unwrap(),
    );
    assert!(verify(&root(&public), &proof, CONTENTS, NOW.into()).is_err());
}

#[test]
fn maven_accepts_rsa_2048_and_refuses_a_real_dsa_signer() {
    let rsa = key_algorithm(71, KeyVersion::V4, KeyType::Rsa(2048));
    assert_eq!(
        verify(
            &root(&certificate(&rsa, None)),
            &proof(&rsa, HashAlgorithm::Sha256, None),
            CONTENTS,
            NOW.into()
        ),
        Ok(())
    );
    // The maintained key builder refuses insecure RSA sizes itself. DSA is
    // natively verifiable but outside this deliberately small eligibility profile.
    let dsa = key_algorithm(72, KeyVersion::V4, KeyType::Dsa(DsaKeySize::B1024));
    let detached = proof(&dsa, HashAlgorithm::Sha256, None);
    let signed = DetachedSignature::from_string(detached["signature"].as_str().unwrap())
        .unwrap()
        .0;
    signed
        .verify(&dsa.to_public_key().primary_key, CONTENTS)
        .unwrap();
    assert_eq!(
        verify(
            &root(&certificate(&dsa, None)),
            &detached,
            CONTENTS,
            NOW.into()
        ),
        Err(ReleaseError::Unsupported)
    );
}

#[test]
fn maven_refuses_unknown_json_fields_and_oversized_native_material() {
    let key = key(31);
    let mut root = root(&certificate(&key, None));
    let mut proof = proof(&key, HashAlgorithm::Sha256, None);
    assert_eq!(verify(&root, &proof, CONTENTS, NOW.into()), Ok(()));
    root["alternate_key"] = json!("untrusted");
    assert!(verify(&root, &proof, CONTENTS, NOW.into()).is_err());
    root.as_object_mut().unwrap().remove("alternate_key");
    proof["public_key"] = json!("untrusted");
    assert!(verify(&root, &proof, CONTENTS, NOW.into()).is_err());
    proof.as_object_mut().unwrap().remove("public_key");
    proof["signature"] = json!("a".repeat(65_537));
    assert_eq!(
        verify(&root, &proof, CONTENTS, NOW.into()),
        Err(ReleaseError::LimitExceeded)
    );
}

#[test]
fn maven_refuses_incomplete_trailing_signature_packets_instead_of_discarding_them() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let key = key(31);
    let root = root(&certificate(&key, None));
    let proof = proof(&key, HashAlgorithm::Sha256, None);
    let mut decoded = Vec::new();
    Dearmor::new(proof["signature"].as_str().unwrap().as_bytes())
        .read_to_end(&mut decoded)
        .unwrap();
    for trailing in [false, true] {
        let mut bytes = decoded.clone();
        if trailing {
            bytes.push(0xc2);
        }
        let proof = json!({"signature":format!("-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----",STANDARD.encode(bytes))});
        assert_eq!(
            verify(&root, &proof, CONTENTS, NOW.into()),
            if trailing {
                Err(ReleaseError::Invalid)
            } else {
                Ok(())
            }
        );
    }
}
