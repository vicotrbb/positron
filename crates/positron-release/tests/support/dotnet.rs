//! Private RSA/CMS/TSA fixtures for actual NuGet payloads; never registry evidence.
use super::{keyless, native_registry::NativeArtifactFixture};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    },
};
use positron_release::*;
use rsa::{
    RsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::EncodePrivateKey,
    signature::{SignatureEncoding, Signer},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Cursor, Write},
    sync::OnceLock,
};
use x509_cert::der::{
    Decode, Encode, Sequence,
    asn1::{Any, GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec, Uint},
};
use x509_cert::{
    Certificate,
    attr::{Attribute, Attributes},
    spki::AlgorithmIdentifierOwned,
};
const SHA: &str = "2.16.840.1.101.3.4.2.1";
fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new(s).unwrap()
}
fn any<T: Encode>(v: &T) -> Any {
    Any::from_der(&v.to_der().unwrap()).unwrap()
}
fn algorithm(s: &str) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oid(s),
        parameters: Some(Any::null()),
    }
}
fn attr<T: Encode>(id: &str, v: &T) -> Attribute {
    Attribute {
        oid: oid(id),
        values: SetOfVec::try_from(vec![any(v)]).unwrap(),
    }
}
#[derive(Clone, Debug, Sequence)]
struct CertId {
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    issuer_serial: Option<Any>,
}
#[derive(Clone, Debug, Sequence)]
struct Ess {
    certs: Vec<CertId>,
    policies: Option<Vec<Any>>,
}
#[derive(Clone, Debug, Sequence)]
struct Commitment {
    commitment_type_id: ObjectIdentifier,
    qualifiers: Option<Vec<Any>>,
}
#[derive(Clone, Debug, Sequence)]
struct Imprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}
#[derive(Clone, Debug, Sequence)]
struct TstInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: Imprint,
    serial_number: Uint,
    gen_time: GeneralizedTime,
}
struct Authority {
    key: RsaPrivateKey,
    signer: Vec<u8>,
    tsa: Vec<u8>,
    root: Vec<u8>,
}
fn authority() -> &'static Authority {
    static VALUE: OnceLock<Authority> = OnceLock::new();
    VALUE.get_or_init(|| {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let der = key.to_pkcs8_der().unwrap();
        let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(der.as_bytes()),
            &rcgen::PKCS_RSA_SHA256,
        )
        .unwrap();
        let mut root = rcgen::CertificateParams::default();
        root.not_before = rcgen::date_time_ymd(2024, 1, 1);
        root.not_after = rcgen::date_time_ymd(2030, 1, 1);
        root.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let root = root.self_signed(&pair).unwrap();
        let leaf = |timestamp: bool| {
            let mut p = rcgen::CertificateParams::default();
            p.not_before = rcgen::date_time_ymd(2025, 1, 1);
            p.not_after = rcgen::date_time_ymd(2026, 1, 1);
            p.distinguished_name.push(
                rcgen::DnType::CommonName,
                if timestamp {
                    "private timestamp fixture"
                } else {
                    "private repository fixture"
                },
            );
            p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            if timestamp {
                p.custom_extensions
                    .push(rcgen::CustomExtension::from_oid_content(
                        &[2, 5, 29, 37],
                        vec![
                            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
                        ],
                    ));
                p.custom_extensions
                    .last_mut()
                    .unwrap()
                    .set_criticality(true);
            } else {
                p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
            }
            p.signed_by(&pair, &root, &pair).unwrap().der().to_vec()
        };
        Authority {
            signer: leaf(false),
            tsa: leaf(true),
            root: root.der().to_vec(),
            key,
        }
    })
}
fn signed(content: &[u8], kind: &str, certificate: &[u8], extra: Vec<Attribute>) -> SignedData {
    let a = authority();
    let cert = Certificate::from_der(certificate).unwrap();
    let mut attrs = vec![
        attr("1.2.840.113549.1.9.3", &oid(kind)),
        attr(
            "1.2.840.113549.1.9.4",
            &OctetString::new(Sha256::digest(content).to_vec()).unwrap(),
        ),
        attr(
            "1.2.840.113549.1.9.5",
            &GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
                keyless::NOW as u64,
            ))
            .unwrap(),
        ),
        attr(
            "1.2.840.113549.1.9.16.2.47",
            &Ess {
                certs: vec![CertId {
                    hash_algorithm: None,
                    cert_hash: OctetString::new(Sha256::digest(certificate).to_vec()).unwrap(),
                    issuer_serial: None,
                }],
                policies: None,
            },
        ),
    ];
    attrs.extend(extra);
    let attrs = Attributes::try_from(attrs).unwrap();
    let signature = SigningKey::<Sha256>::new(a.key.clone())
        .sign(&attrs.to_der().unwrap())
        .to_vec();
    let signer = SignerInfo {
        version: cms::content_info::CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: algorithm(SHA),
        signed_attrs: Some(attrs),
        signature_algorithm: algorithm("1.2.840.113549.1.1.1"),
        signature: OctetString::new(signature).unwrap(),
        unsigned_attrs: None,
    };
    SignedData {
        version: cms::content_info::CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![algorithm(SHA)]).unwrap(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: oid(kind),
            econtent: Some(any(&OctetString::new(content).unwrap())),
        },
        certificates: Some(CertificateSet(
            SetOfVec::try_from(vec![CertificateChoices::Certificate(cert)]).unwrap(),
        )),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer]).unwrap()),
    }
}
fn envelope(data: &SignedData) -> Vec<u8> {
    ContentInfo {
        content_type: oid("1.2.840.113549.1.7.2"),
        content: any(data),
    }
    .to_der()
    .unwrap()
}
pub fn package(unsigned: Vec<u8>, version: &str) -> NativeArtifactFixture {
    let a = authority();
    let content = format!(
        "Version:1\n\n{SHA}-Hash:{}\n\n",
        B64.encode(Sha256::digest(&unsigned))
    );
    let mut primary = signed(
        content.as_bytes(),
        "1.2.840.113549.1.7.1",
        &a.signer,
        vec![
            attr(
                "1.2.840.113549.1.9.16.2.16",
                &Commitment {
                    commitment_type_id: oid("1.2.840.113549.1.9.16.6.2"),
                    qualifiers: None,
                },
            ),
            attr(
                "1.3.6.1.4.1.311.84.2.1.1.1",
                &x509_cert::der::asn1::Ia5String::new("https://api.nuget.org/v3/index.json")
                    .unwrap(),
            ),
        ],
    );
    let mut signer = primary.signer_infos.0.get(0).unwrap().clone();
    let info = TstInfo {
        version: 1,
        policy: oid("1.2.3.4.1"),
        message_imprint: Imprint {
            hash_algorithm: algorithm(SHA),
            hashed_message: OctetString::new(Sha256::digest(signer.signature.as_bytes()).to_vec())
                .unwrap(),
        },
        serial_number: Uint::new(&[1]).unwrap(),
        gen_time: GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            keyless::NOW as u64,
        ))
        .unwrap(),
    };
    let token = envelope(&signed(
        &info.to_der().unwrap(),
        "1.2.840.113549.1.9.16.1.4",
        &a.tsa,
        vec![],
    ));
    signer.unsigned_attrs = Some(
        Attributes::try_from(vec![attr(
            "1.2.840.113549.1.9.16.2.14",
            &Any::from_der(&token).unwrap(),
        )])
        .unwrap(),
    );
    primary.signer_infos = SignerInfos(SetOfVec::try_from(vec![signer]).unwrap());
    let signature = envelope(&primary);
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        ".signature.p7s",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(&signature).unwrap();
    let single = zip.finish().unwrap().into_inner();
    let word = |b: &[u8], i: usize| u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
    let number = |b: &[u8], i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    let eocd = unsigned.len() - 22;
    let central = number(&unsigned, eocd + 16) as usize;
    let count = word(&unsigned, eocd + 8);
    let single_end = single.len() - 22;
    let single_central = number(&single, single_end + 16) as usize;
    let mut signature_central = single[single_central..single_end].to_vec();
    signature_central[42..46].copy_from_slice(&(central as u32).to_le_bytes());
    let mut contents = unsigned[..central].to_vec();
    contents.extend(&single[..single_central]);
    contents.extend(&unsigned[central..eocd]);
    contents.extend(&signature_central);
    let mut end = unsigned[eocd..].to_vec();
    end[8..10].copy_from_slice(&(count + 1).to_le_bytes());
    end[10..12].copy_from_slice(&(count + 1).to_le_bytes());
    end[12..16].copy_from_slice(
        &(number(&unsigned, eocd + 12) + signature_central.len() as u32).to_le_bytes(),
    );
    end[16..20].copy_from_slice(&((central + single_central) as u32).to_le_bytes());
    contents.extend(end);
    let root = json!({"signer":B64.encode(&a.signer),"intermediates":[],"root":B64.encode(&a.root),"timestamp":{"leaf":B64.encode(&a.tsa),"intermediates":[],"root":B64.encode(&a.root),"not_before_unix":keyless::NOW-10,"expires_unix":keyless::NOW+10,"policy_oid":"1.2.3.4.1"}});
    NativeArtifactFixture {
        surface: Surface::SdkDotNet,
        filename: format!("Positron.SDK.{version}.nupkg"),
        contents,
        payload: Some(unsigned),
        registry: "https://api.nuget.org/v3/index.json".into(),
        subject: format!("pkg:nuget/Positron.SDK@{version}"),
        revision: None,
        policy: NativePublisherPolicy::NugetRepository {
            trusted_root_sha256: Sha256::digest(serde_json::to_vec(&root).unwrap()).into(),
        },
        proof: json!({"trustedRoot":root}),
    }
}
pub fn fixture(version: &str, source: &str, api: &[u8]) -> NativeArtifactFixture {
    let schema = super::hex(&Sha256::digest(api));
    let release=serde_json::to_vec(&json!({"name":"Positron.SDK","version":version,"source_commit":source,"api_version":"positron.v1","schema_digest":schema,"release_manifest_surface":"SdkDotNet","registry":"https://api.nuget.org/v3/index.json","generator":"positron-api=1,dotnet=8.0.427,protoc-bin-vendored=3.2.0"})).unwrap();
    let contract =
        serde_json::to_vec(&json!({"api_version":"positron.v1","schema_digest":schema})).unwrap();
    let nuspec = format!(
        "<package><metadata><id>Positron.SDK</id><version>{version}</version><license type=\"expression\">MIT</license></metadata></package>"
    );
    let digest = format!("{schema}\n");
    let project = include_str!("../../../positron-api/dotnet/Positron.SDK.csproj")
        .replace("@VERSION@", env!("CARGO_PKG_VERSION"));
    let files: Vec<(&str, &[u8])> = vec![
        ("Positron.SDK.nuspec", nuspec.as_bytes()),
        ("positron/source/Positron.SDK.csproj", project.as_bytes()),
        (
            "positron/pack.py",
            include_bytes!("../../../positron-api/dotnet/pack.py"),
        ),
        (
            "positron/global.json",
            b"{\"sdk\":{\"version\":\"8.0.427\",\"rollForward\":\"disable\"}}\n",
        ),
        ("positron/release.json", &release),
        ("positron/contract.json", &contract),
        ("positron/api/positron.proto", api),
        ("positron/api/schema.sha256", digest.as_bytes()),
        (
            "lib/net8.0/Positron.SDK.dll",
            b"MZ private structural fixture, not a compiled SDK",
        ),
        ("lib/net8.0/Positron.SDK.xml", b"<doc/>"),
        (
            "lib/net8.0/Positron.SDK.pdb",
            b"BSJB private structural fixture",
        ),
        ("positron/LICENSE", b"MIT"),
        (
            "positron/source/Types.cs",
            include_bytes!("../../../../sdk/dotnet/Types.cs"),
        ),
        (
            "positron/source/Codec.cs",
            include_bytes!("../../../positron-api/dotnet/Codec.cs"),
        ),
        (
            "positron/source/Query.cs",
            include_bytes!("../../../positron-api/dotnet/Query.cs"),
        ),
        (
            "positron/source/BatchTracker.cs",
            include_bytes!("../../../positron-api/dotnet/BatchTracker.cs"),
        ),
        (
            "positron/source/PositronException.cs",
            include_bytes!("../../../positron-api/dotnet/PositronException.cs"),
        ),
        (
            "positron/source/Client.cs",
            include_bytes!("../../../../sdk/dotnet/Client.cs"),
        ),
    ];
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(bytes).unwrap();
    }
    package(zip.finish().unwrap().into_inner(), version)
}
