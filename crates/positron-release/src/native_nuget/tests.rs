use super::*;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sigstore_verify::types::{DerCertificate, SignatureBytes, TimestampToken, TsaAuthority};
use x509_cert::der::{Decode, Encode};
const PACKAGE: &[u8] = include_bytes!("../../tests/fixtures/tinyjson.1.0.0.nupkg");
fn root() -> Value {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(PACKAGE)).unwrap();
    let mut entry = zip.by_name(".signature.p7s").unwrap();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut bytes).unwrap();
    let outer = ContentInfo::from_der(&bytes).unwrap();
    let signed = SignedData::from_der(&outer.content.to_der().unwrap()).unwrap();
    let signer = signed.signer_infos.0.get(0).unwrap();
    let token = signer
        .unsigned_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|attribute| attribute.oid.to_string() == "1.2.840.113549.1.9.16.2.14")
        .unwrap()
        .values
        .get(0)
        .unwrap();
    let timestamp = ContentInfo::from_der(&token.to_der().unwrap()).unwrap();
    let timestamp = SignedData::from_der(&timestamp.content.to_der().unwrap()).unwrap();
    let find = |data: &SignedData, expected: &str| {
        let matches: Vec<_> = data
            .certificates
            .as_ref()
            .unwrap()
            .0
            .iter()
            .filter_map(|choice| match choice {
                CertificateChoices::Certificate(certificate) => Some(certificate.to_der().unwrap()),
                _ => None,
            })
            .filter(|certificate| crate::inventory::hex(&Sha256::digest(certificate)) == expected)
            .collect();
        assert_eq!(matches.len(), 1);
        B64.encode(&matches[0])
    };
    json!({"signer":find(&signed,"0e5f38f57dc1bcc806d8494f4f90fbcedd988b46760709cbeec6f4219aa6157d"),"intermediates":[find(&signed,"51044706bd237b91b89b781337e6d62656c69f0fcffbe8e43741367948127862")],"root":find(&signed,"3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c"),"timestamp":{"leaf":find(&timestamp,"cf7ac17ad047ecd5fdc36822031b12d4ef078b6f2b4c5e6ba41f8ff2cf4bad67"),"intermediates":[find(&timestamp,"f3516ddcc8afc808788bd8b0e840bda2b5e23c6244252ca3000bb6c87170402a")],"root":find(&timestamp,"2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c"),"not_before_unix":1,"expires_unix":1_750_000_000,"policy_oid":"2.16.840.1.113733.1.7.23.3"}})
}
#[test]
fn real_rsa_timestamp_capture_uses_its_installed_authority() {
    let trust: Trust = serde_json::from_value(root()).unwrap();
    let package = crate::nuget_zip::package(PACKAGE).unwrap();
    let primary = cms_profile::document(&package.signature).unwrap();
    cms_profile::verify(
        &primary,
        &Certificate::from_der(&certificate(&trust.signer).unwrap()).unwrap(),
        cms_profile::DATA,
    )
    .expect("native repository CMS and ESS");
    let signer = cms_profile::signer(&primary).unwrap();
    let token = cms_profile::attribute(
        signer.unsigned_attrs.as_ref().unwrap(),
        "1.2.840.113549.1.9.16.2.14",
    )
    .unwrap()
    .to_der()
    .unwrap();
    let timestamp = cms_profile::document(&token).unwrap();
    cms_profile::verify(
        &timestamp,
        &Certificate::from_der(&certificate(&trust.timestamp.leaf).unwrap()).unwrap(),
        cms_profile::TST_INFO,
    )
    .expect("native RSA timestamp CMS and ESS");
    let authority = TsaAuthority::new(
        DerCertificate::new(certificate(&trust.timestamp.leaf).unwrap()),
        trust
            .timestamp
            .intermediates
            .iter()
            .map(|value| DerCertificate::new(certificate(value).unwrap()))
            .collect(),
        DerCertificate::new(certificate(&trust.timestamp.root).unwrap()),
        None,
    );
    let time = sigstore_verify::tsa::verify_timestamp_for_authority(
        &TimestampToken::from_bytes(&token),
        &SignatureBytes::from_bytes(signer.signature.as_bytes()),
        &authority,
    )
    .expect("native RSA timestamp chain, imprint and EKU");
    assert_eq!(time.as_second(), 1_544_711_298);
}
#[test]
fn timestamp_refuses_unsigned_signature_algorithm_substitution() {
    let trust: Trust = serde_json::from_value(root()).unwrap();
    let package = crate::nuget_zip::package(PACKAGE).unwrap();
    let primary = cms_profile::document(&package.signature).unwrap();
    let signer = cms_profile::signer(&primary).unwrap();
    let token = cms_profile::attribute(
        signer.unsigned_attrs.as_ref().unwrap(),
        "1.2.840.113549.1.9.16.2.14",
    )
    .unwrap()
    .to_der()
    .unwrap();
    let mut outer = ContentInfo::from_der(&token).unwrap();
    let mut data = SignedData::from_der(&outer.content.to_der().unwrap()).unwrap();
    let mut altered = data.signer_infos.0.get(0).unwrap().clone();
    altered.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    data.signer_infos.0 = vec![altered].try_into().unwrap();
    outer.content = Any::from_der(&data.to_der().unwrap()).unwrap();
    let altered = outer.to_der().unwrap();
    let authority = TsaAuthority::new(
        DerCertificate::new(certificate(&trust.timestamp.leaf).unwrap()),
        trust
            .timestamp
            .intermediates
            .iter()
            .map(|value| DerCertificate::new(certificate(value).unwrap()))
            .collect(),
        DerCertificate::new(certificate(&trust.timestamp.root).unwrap()),
        None,
    );
    assert!(
        sigstore_verify::tsa::verify_timestamp_for_authority(
            &TimestampToken::from_bytes(&altered),
            &SignatureBytes::from_bytes(signer.signature.as_bytes()),
            &authority
        )
        .is_err()
    );
}
#[test]
fn real_repository_signature_authenticates_native_nuget_package() {
    let trust = root();
    verify(
        &trust,
        PACKAGE,
        "TinyJson",
        "1.0.0",
        "https://api.nuget.org/v3/index.json",
        1_750_000_000,
    )
    .unwrap();
    let mut changed = PACKAGE.to_vec();
    changed[100] ^= 1;
    assert!(
        verify(
            &trust,
            &changed,
            "TinyJson",
            "1.0.0",
            "https://api.nuget.org/v3/index.json",
            1_750_000_000
        )
        .is_err()
    );
    assert!(
        verify(
            &trust,
            PACKAGE,
            "OtherPackage",
            "1.0.0",
            "https://api.nuget.org/v3/index.json",
            1_750_000_000
        )
        .is_err()
    );
    assert!(
        verify(
            &trust,
            PACKAGE,
            "TinyJson",
            "1.1.0",
            "https://api.nuget.org/v3/index.json",
            1_750_000_000
        )
        .is_err()
    );
    assert!(
        verify(
            &trust,
            PACKAGE,
            "TinyJson",
            "1.0.0",
            "https://other.example/index.json",
            1_750_000_000
        )
        .is_err()
    );
}
