//! Private Sigstore authorities for integration tests; never production trust.
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair as CertificateKey, KeyUsagePurpose, SanType,
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    der::{
        Decode, Encode,
        asn1::{OctetString, Utf8StringRef},
    },
};

pub const SAN: &str =
    "https://github.com/vicotrbb/positron/.github/workflows/release.yml@refs/heads/main";
pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const REPOSITORY: &str = "https://github.com/vicotrbb/positron";
pub const SOURCE_COMMIT: &str = "193b5bd7d3985809503963ae400594ea16df31cf";
pub const REF: &str = "refs/heads/main";
pub const NOW: i64 = 1_750_000_000;

pub struct KeylessFixture {
    root: Value,
    certificate: Vec<u8>,
    leaf: Ed25519KeyPair,
    log: Ed25519KeyPair,
    log_id: [u8; 32],
}

impl KeylessFixture {
    pub fn new() -> Self {
        Self::mint(true)
    }

    pub fn for_workflow(identity: &str, repository: &str, revision: &str) -> Self {
        Self::mint_workflow(true, identity, repository, revision)
    }
    fn mint(valid_sct: bool) -> Self {
        Self::mint_workflow(valid_sct, SAN, REPOSITORY, SOURCE_COMMIT)
    }
    fn mint_workflow(valid_sct: bool, identity: &str, repository: &str, revision: &str) -> Self {
        let ca_key = certificate_key(41);
        let leaf_key = certificate_key(42);
        let mut ca_params = CertificateParams::default();
        ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        ca_params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        ca_params.serial_number = Some(1_u64.into());
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Positron test Fulcio");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let mut params = CertificateParams::default();
        params.not_before = rcgen::date_time_ymd(2025, 6, 15);
        params.not_after = rcgen::date_time_ymd(2025, 6, 16);
        params.serial_number = Some(2_u64.into());
        params
            .distinguished_name
            .push(DnType::CommonName, "Positron test signer");
        params.subject_alt_names = vec![SanType::URI(identity.try_into().unwrap())];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        for (suffix, value) in [
            (8, ISSUER),
            (9, identity),
            (10, revision),
            (12, repository),
            (13, revision),
            (14, REF),
            (18, identity),
            (19, revision),
        ] {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 57264, 1, suffix],
                    Utf8StringRef::new(value).unwrap().to_der().unwrap(),
                ));
        }
        let precert = params.clone().signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let tbs = Certificate::from_der(precert.der())
            .unwrap()
            .tbs_certificate
            .to_der()
            .unwrap();
        let (ct_key, ct_spki) = ct_key();
        let ct_id: [u8; 32] = Sha256::digest(&ct_spki).into();
        let mut data = vec![0, 0]; // RFC 6962 v1, certificate_timestamp.
        data.extend((u64::try_from(NOW).unwrap() * 1000).to_be_bytes());
        data.extend([0, 1]); // precert_entry.
        data.extend(Sha256::digest(ca_key.public_key_der()));
        let tbs_len = u32::try_from(tbs.len()).unwrap().to_be_bytes();
        data.extend(tbs_len.get(1..).unwrap());
        data.extend(tbs);
        data.extend([0, 0]); // No SCT extensions.
        let mut signature = ct_key
            .sign(&SystemRandom::new(), &data)
            .unwrap()
            .as_ref()
            .to_vec();
        if !valid_sct {
            *signature.last_mut().unwrap() ^= 1;
        }
        let mut sct = vec![0];
        sct.extend(ct_id);
        sct.extend((u64::try_from(NOW).unwrap() * 1000).to_be_bytes());
        sct.extend([0, 0, 4, 3]); // Empty extensions, SHA256/ECDSA.
        sct.extend(u16::try_from(signature.len()).unwrap().to_be_bytes());
        sct.extend(signature);
        let mut list = u16::try_from(sct.len() + 2).unwrap().to_be_bytes().to_vec();
        list.extend(u16::try_from(sct.len()).unwrap().to_be_bytes());
        list.extend(sct);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 4, 2],
                OctetString::new(list).unwrap().to_der().unwrap(),
            ));
        let certificate = params
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap()
            .der()
            .to_vec();
        let leaf = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
        let log = Ed25519KeyPair::from_seed_unchecked(&[43; 32]).unwrap();
        let mut log_spki = vec![0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3, 0x21, 0];
        log_spki.extend(log.public_key().as_ref());
        let log_id: [u8; 32] = Sha256::digest(&log_spki).into();
        let root = json!({
            "mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "certificateAuthorities":[{"uri":"https://fulcio.test.invalid","certChain":{"certificates":[{"rawBytes":B64.encode(ca.der())}]}}],
            "ctlogs":[{"baseUrl":"https://ct.test.invalid","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":B64.encode(ct_spki),"keyDetails":"PKIX_ECDSA_P256_SHA_256"},"logId":{"keyId":B64.encode(ct_id)}}],
            "tlogs":[{"baseUrl":"https://rekor.test.invalid","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":B64.encode(log_spki),"keyDetails":"PKIX_ED25519"},"logId":{"keyId":B64.encode(log_id)}}]
        });
        Self {
            root,
            certificate,
            leaf,
            log,
            log_id,
        }
    }

    pub fn trusted_root(&self) -> Value {
        self.root.clone()
    }

    pub fn bundle(&self, payload: &[u8]) -> Value {
        let mut pae =
            format!("DSSEv1 28 application/vnd.in-toto+json {} ", payload.len()).into_bytes();
        pae.extend(payload);
        let signature = B64.encode(self.leaf.sign(&pae).as_ref());
        let envelope = json!({"payloadType":"application/vnd.in-toto+json","payload":B64.encode(payload),"signatures":[{"sig":signature}]});
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(&self.certificate)
        );
        let body = serde_json::to_vec(&json!({"apiVersion":"0.0.1","kind":"dsse","spec":{
            "signatures":[{"signature":signature,"verifier":B64.encode(pem.as_bytes())}],
            "envelopeHash":{"algorithm":"sha256","value":hex(&Sha256::digest(serde_json::to_vec(&envelope).unwrap()))},
            "payloadHash":{"algorithm":"sha256","value":hex(&Sha256::digest(payload))}
        }})).unwrap();
        let set = serde_json::to_vec(&json!({"body":B64.encode(&body),"integratedTime":NOW,"logID":hex(&self.log_id),"logIndex":0})).unwrap();
        let mut leaf = vec![0];
        leaf.extend(&body);
        let root = Sha256::digest(leaf);
        let checkpoint = format!("positron-test-rekor\n1\n{}\n", B64.encode(root));
        let mut note_signature = self.log_id.get(..4).unwrap().to_vec();
        note_signature.extend(self.log.sign(checkpoint.as_bytes()).as_ref());
        let checkpoint = format!(
            "{checkpoint}\n— positron-test-rekor {}\n",
            B64.encode(note_signature)
        );
        json!({"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{
            "certificate":{"rawBytes":B64.encode(&self.certificate)},
            "tlogEntries":[{"logIndex":"0","logId":{"keyId":B64.encode(self.log_id)},"kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":NOW.to_string(),"canonicalizedBody":B64.encode(&body),
                "inclusionPromise":{"signedEntryTimestamp":B64.encode(self.log.sign(&set).as_ref())},
                "inclusionProof":{"logIndex":"0","rootHash":B64.encode(root),"treeSize":"1","hashes":[],"checkpoint":{"envelope":checkpoint}}}]
        },"dsseEnvelope":envelope})
    }
}

fn certificate_key(seed: u8) -> CertificateKey {
    // RFC 8410 PKCS#8: the seed is synthetic test material, derived here.
    let mut der = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    der.extend([seed; 32]);
    CertificateKey::try_from(der).unwrap()
}

fn ct_key() -> (EcdsaKeyPair, Vec<u8>) {
    // SEC 2 P-256 generator G and scalar 1 give reproducible test-only CT keys.
    let point = [
        4, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];
    let mut scalar = [0; 32];
    *scalar.last_mut().unwrap() = 1;
    let key = EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &scalar,
        &point,
        &SystemRandom::new(),
    )
    .unwrap();
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1, 6, 8, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 3, 1, 7, 3, 0x42, 0,
    ];
    spki.extend(point);
    (key, spki)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_verify::{
        VerificationPolicy, Verifier,
        trust_root::TrustedRoot,
        types::{Bundle, Sha256Hash},
    };

    #[test]
    fn strict_keyless_bundle_authenticates_payload_identity_and_logs() {
        let fixture = KeylessFixture::new();
        let digest = Sha256::digest(b"positron artifact");
        let payload = serde_json::to_vec(&json!({
            "_type":"https://in-toto.io/Statement/v1",
            "subject":[{"name":"positron","digest":{"sha256":hex(&digest)}}],
            "predicateType":"https://slsa.dev/provenance/v1", "predicate":{}
        }))
        .unwrap();
        let root = TrustedRoot::from_json(&fixture.trusted_root().to_string()).unwrap();
        let verifier = Verifier::new(&root).unwrap();
        let bundle = Bundle::from_json(&fixture.bundle(&payload).to_string()).unwrap();
        let result = verifier
            .verify(
                Sha256Hash::new(digest.into()),
                &bundle,
                &VerificationPolicy::new(SAN, ISSUER),
            )
            .unwrap();
        assert!(result.certificate_verified());
        assert!(result.sct_verified());
        assert!(result.tlog_verified());
        assert!(result.identity_policy_checked());
        assert_eq!(result.integrated_time().unwrap().as_second(), NOW);
        assert_eq!(
            result
                .certificate()
                .unwrap()
                .ci_claims
                .source_repository_uri
                .as_deref(),
            Some(REPOSITORY)
        );
        assert!(
            verifier
                .verify(
                    Sha256Hash::new(digest.into()),
                    &bundle,
                    &VerificationPolicy::new("https://other.example/workflow", ISSUER)
                )
                .is_err()
        );
        let mut untrusted_ct = fixture.trusted_root();
        untrusted_ct["ctlogs"] = json!([]);
        let root = TrustedRoot::from_json(&untrusted_ct.to_string()).unwrap();
        assert!(
            Verifier::new(&root)
                .unwrap()
                .verify(
                    Sha256Hash::new(digest.into()),
                    &bundle,
                    &VerificationPolicy::new(SAN, ISSUER)
                )
                .is_err()
        );
        let invalid_sct = KeylessFixture::mint(false);
        let bundle = Bundle::from_json(&invalid_sct.bundle(&payload).to_string()).unwrap();
        let root = TrustedRoot::from_json(&invalid_sct.trusted_root().to_string()).unwrap();
        let error = Verifier::new(&root)
            .unwrap()
            .verify(
                Sha256Hash::new(digest.into()),
                &bundle,
                &VerificationPolicy::new(SAN, ISSUER),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("SCT signature verification failed"),
            "{error}"
        );
    }
}
