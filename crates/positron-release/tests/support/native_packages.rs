//! Real native package fixtures; these are protocol tests, not published Positron SDKs.
use super::{keyless, native_registry::NativeArtifactFixture};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use pgp::{
    composed::{DetachedSignature, KeyType, SecretKeyParamsBuilder},
    crypto::hash::HashAlgorithm,
    packet::{KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{KeyDetails, Password, Timestamp},
};
use positron_release::*;
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};

pub fn fixtures(version: &str) -> Vec<NativeArtifactFixture> {
    let mut fixtures = maven(version);
    fixtures.push(nuget(version));
    fixtures
}
fn maven(version: &str) -> Vec<NativeArtifactFixture> {
    let now = keyless::NOW as u32;
    let key = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .created_at(Timestamp::from_secs(now - 1000))
        .primary_user_id("Positron test Maven publisher".into())
        .build()
        .unwrap()
        .generate(StdRng::seed_from_u64(913))
        .unwrap();
    let config = |typ| {
        let mut config = SignatureConfig::v4(typ, key.algorithm(), HashAlgorithm::Sha256);
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                now - 100,
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
        ];
        config
    };
    let mut public = key.to_public_key();
    let mut certification = config(SignatureType::Key);
    let mut flags = KeyFlags::default();
    flags.set_sign(true);
    flags.set_certify(true);
    certification
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap());
    public.details.direct_signatures.push(
        certification
            .sign_key(&key.primary_key, &Password::empty(), &public.primary_key)
            .unwrap(),
    );
    let root = json!({"public_key":public.to_armored_string(None.into()).unwrap()});
    let digest = Sha256::digest(serde_json::to_vec(&root).unwrap()).into();
    let pom=format!("<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>dev.positron</groupId><artifactId>sdk</artifactId><version>{version}</version></project>").into_bytes();
    [(".pom","type=pom",pom,None),(".jar","type=jar",jar("sdk.txt",b"synthetic compiled SDK payload\n"),Some(())),("-sources.jar","classifier=sources&type=jar",jar("dev/positron/Client.java",b"package dev.positron; public final class Client {}\n"),Some(())),("-javadoc.jar","classifier=javadoc&type=jar",jar("index.html",b"<html><body>SDK fixture documentation</body></html>"),Some(()))].into_iter().map(|(suffix,qualifiers,contents,payload)| {
        let signature=config(SignatureType::Binary).sign(&key.primary_key,&Password::empty(),contents.as_slice()).unwrap();
        NativeArtifactFixture {surface:Surface::SdkJava,filename:format!("sdk-{version}{suffix}"),payload:payload.map(|_|contents.clone()),contents,registry:"https://repo.maven.apache.org/maven2".into(),subject:format!("pkg:maven/dev.positron/sdk@{version}?{qualifiers}"),revision:None,policy:NativePublisherPolicy::Maven{trusted_root_sha256:digest},proof:json!({"trustedRoot":root,"signature":{"signature":DetachedSignature::new(signature).to_armored_string(None.into()).unwrap()}})}
    }).collect()
}
fn jar(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        name,
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(contents).unwrap();
    zip.finish().unwrap().into_inner()
}
fn nuget(version: &str) -> NativeArtifactFixture {
    use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
    use x509_cert::der::{Decode, Encode};
    let bytes = include_bytes!("../fixtures/tinyjson.1.0.0.nupkg");
    assert_eq!(
        version, "1.0.0",
        "captured native package cannot be rebound to another version"
    );
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut signature = Vec::new();
    std::io::Read::read_to_end(&mut zip.by_name(".signature.p7s").unwrap(), &mut signature)
        .unwrap();
    let outer = ContentInfo::from_der(&signature).unwrap();
    let signed = SignedData::from_der(&outer.content.to_der().unwrap()).unwrap();
    let token = signed
        .signer_infos
        .0
        .get(0)
        .unwrap()
        .unsigned_attrs
        .as_ref()
        .unwrap()
        .iter()
        .find(|attribute| attribute.oid.to_string() == "1.2.840.113549.1.9.16.2.14")
        .unwrap()
        .values
        .get(0)
        .unwrap();
    let outer = ContentInfo::from_der(&token.to_der().unwrap()).unwrap();
    let timestamp = SignedData::from_der(&outer.content.to_der().unwrap()).unwrap();
    let find = |data: &SignedData, hash: &str| {
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
            .filter(|bytes| super::hex(&Sha256::digest(bytes)) == hash)
            .collect();
        assert_eq!(matches.len(), 1);
        B64.encode(&matches[0])
    };
    let root = json!({"signer":find(&signed,"0e5f38f57dc1bcc806d8494f4f90fbcedd988b46760709cbeec6f4219aa6157d"),"intermediates":[find(&signed,"51044706bd237b91b89b781337e6d62656c69f0fcffbe8e43741367948127862")],"root":find(&signed,"3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c"),"timestamp":{"leaf":find(&timestamp,"cf7ac17ad047ecd5fdc36822031b12d4ef078b6f2b4c5e6ba41f8ff2cf4bad67"),"intermediates":[find(&timestamp,"f3516ddcc8afc808788bd8b0e840bda2b5e23c6244252ca3000bb6c87170402a")],"root":find(&timestamp,"2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c"),"not_before_unix":1,"expires_unix":1_750_000_001_u64,"policy_oid":"2.16.840.1.113733.1.7.23.3"}});
    let mut unsigned = bytes[..6774].to_vec();
    unsigned.extend(&bytes[16282..]);
    let signature_cd = unsigned
        .windows(4)
        .rposition(|bytes| bytes == b"PK\x01\x02")
        .unwrap();
    let end = unsigned.len() - 22;
    unsigned.drain(signature_cd..end);
    let end = unsigned.len() - 22;
    unsigned[end + 8..end + 12].copy_from_slice(&[5, 0, 5, 0]);
    unsigned[end + 12..end + 16].copy_from_slice(&382_u32.to_le_bytes());
    unsigned[end + 16..end + 20].copy_from_slice(&6774_u32.to_le_bytes());
    NativeArtifactFixture {
        surface: Surface::SdkDotNet,
        filename: "tinyjson.1.0.0.nupkg".into(),
        contents: bytes.to_vec(),
        payload: Some(unsigned),
        registry: "https://api.nuget.org/v3/index.json".into(),
        subject: "pkg:nuget/TinyJson@1.0.0".into(),
        revision: None,
        policy: NativePublisherPolicy::NugetRepository {
            trusted_root_sha256: Sha256::digest(serde_json::to_vec(&root).unwrap()).into(),
        },
        proof: json!({"trustedRoot":root}),
    }
}
