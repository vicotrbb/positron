//! Strict RSA/SHA-256 CMS profile shared by NuGet repository and timestamp signatures.
use crate::ReleaseError;
use cms::{
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier, SignerInfo},
};
use der::{
    Decode, Encode, Sequence, Tagged,
    asn1::{Any, ObjectIdentifier, OctetString},
};
use sha2::{Digest, Sha256};
use sigstore_verify::{
    crypto::{self, SigningScheme},
    types::{DerPublicKey, SignatureBytes},
};
use x509_cert::{
    Certificate,
    attr::Attributes,
    ext::pkix::name::{GeneralName, GeneralNames},
    serial_number::SerialNumber,
    spki::AlgorithmIdentifierOwned,
};

pub(crate) const DATA: &str = "1.2.840.113549.1.7.1";
pub(crate) const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub(crate) fn document(bytes: &[u8]) -> Result<SignedData, ReleaseError> {
    if bytes.len() > 1_048_576 {
        return Err(ReleaseError::LimitExceeded);
    }
    let outer = ContentInfo::from_der(bytes).map_err(|_| ReleaseError::Invalid)?;
    if outer.content_type.to_string() != "1.2.840.113549.1.7.2" {
        return Err(ReleaseError::Unsupported);
    }
    SignedData::from_der(&outer.content.to_der().map_err(|_| ReleaseError::Invalid)?)
        .map_err(|_| ReleaseError::Invalid)
}
pub(crate) fn signer(document: &SignedData) -> Result<&SignerInfo, ReleaseError> {
    if document.signer_infos.0.len() != 1 || document.digest_algorithms.len() != 1 {
        return Err(ReleaseError::Unsupported);
    }
    document.signer_infos.0.get(0).ok_or(ReleaseError::Invalid)
}
pub(crate) fn attributes(signer: &SignerInfo) -> Result<&Attributes, ReleaseError> {
    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(ReleaseError::Authentication)?;
    if attrs.len() > 16 {
        return Err(ReleaseError::LimitExceeded);
    }
    for (index, attribute) in attrs.iter().enumerate() {
        if attribute.values.len() != 1
            || attrs
                .iter()
                .take(index)
                .any(|other| other.oid == attribute.oid)
        {
            return Err(ReleaseError::Invalid);
        }
    }
    Ok(attrs)
}
pub(crate) fn attribute<'a>(attrs: &'a Attributes, oid: &str) -> Result<&'a Any, ReleaseError> {
    let found = attrs
        .iter()
        .find(|attribute| attribute.oid.to_string() == oid)
        .ok_or(ReleaseError::Authentication)?;
    if found.values.len() != 1 {
        return Err(ReleaseError::Invalid);
    }
    found.values.get(0).ok_or(ReleaseError::Invalid)
}
pub(crate) fn content(document: &SignedData) -> Result<&[u8], ReleaseError> {
    document
        .encap_content_info
        .econtent
        .as_ref()
        .map(|value| value.value())
        .ok_or(ReleaseError::Authentication)
}
fn parameters(algorithm: &AlgorithmIdentifierOwned) -> bool {
    algorithm
        .parameters
        .as_ref()
        .is_none_or(|value| value.tag() == der::Tag::Null && value.value().is_empty())
}
pub(crate) fn verify(
    document: &SignedData,
    certificate: &Certificate,
    expected_type: &str,
) -> Result<(), ReleaseError> {
    let signer = signer(document)?;
    if document.encap_content_info.econtent_type.to_string() != expected_type
        || signer.digest_alg.oid.to_string() != SHA256
        || !parameters(&signer.digest_alg)
        || !document
            .digest_algorithms
            .iter()
            .all(|algorithm| algorithm == &signer.digest_alg)
        || !matches!(
            signer.signature_algorithm.oid.to_string().as_str(),
            "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.11"
        )
        || !parameters(&signer.signature_algorithm)
    {
        return Err(ReleaseError::Unsupported);
    }
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(identity)
            if identity.issuer == certificate.tbs_certificate.issuer
                && identity.serial_number == certificate.tbs_certificate.serial_number => {},
        SignerIdentifier::SubjectKeyIdentifier(identity) => {
            let extensions = certificate
                .tbs_certificate
                .extensions
                .as_ref()
                .ok_or(ReleaseError::Authentication)?;
            let matching: Vec<_> = extensions
                .iter()
                .filter(|extension| extension.extn_id.to_string() == "2.5.29.14")
                .collect();
            if matching.len() != 1
                || x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                    matching
                        .first()
                        .ok_or(ReleaseError::Authentication)?
                        .extn_value
                        .as_bytes(),
                )
                .map_err(|_| ReleaseError::Invalid)?
                    != *identity
            {
                return Err(ReleaseError::Authentication);
            }
        },
        _ => return Err(ReleaseError::Authentication),
    }
    let attrs = attributes(signer)?;
    let kind = attribute(attrs, "1.2.840.113549.1.9.3")?
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| ReleaseError::Invalid)?;
    let digest = attribute(attrs, "1.2.840.113549.1.9.4")?
        .decode_as::<OctetString>()
        .map_err(|_| ReleaseError::Invalid)?;
    if kind.to_string() != expected_type
        || digest.as_bytes() != Sha256::digest(content(document)?).as_slice()
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    verify_ess(attrs, certificate)?;
    let public = DerPublicKey::new(
        certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| ReleaseError::Invalid)?,
    );
    crypto::verify_signature(
        &public,
        &attrs.to_der().map_err(|_| ReleaseError::Invalid)?,
        &SignatureBytes::from_bytes(signer.signature.as_bytes()),
        SigningScheme::RsaPkcs1Sha256,
    )
    .map_err(|_| ReleaseError::Authentication)
}
#[derive(Clone, Debug, Sequence)]
struct IssuerSerial {
    issuer: GeneralNames,
    serial_number: SerialNumber,
}
#[derive(Clone, Debug, Sequence)]
struct CertId {
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    issuer_serial: Option<IssuerSerial>,
}
#[derive(Clone, Debug, Sequence)]
struct SigningCertificate {
    certs: Vec<CertId>,
    policies: Option<Vec<Any>>,
}
fn verify_ess(attrs: &Attributes, certificate: &Certificate) -> Result<(), ReleaseError> {
    let value = attribute(attrs, "1.2.840.113549.1.9.16.2.47")?;
    let ids = value
        .decode_as::<SigningCertificate>()
        .map_err(|_| ReleaseError::Invalid)?;
    if ids.certs.len() != 1 || ids.policies.is_some() {
        return Err(ReleaseError::Unsupported);
    }
    let identity = ids.certs.first().ok_or(ReleaseError::Invalid)?;
    if identity
        .hash_algorithm
        .as_ref()
        .is_some_and(|algorithm| algorithm.oid.to_string() != SHA256 || !parameters(algorithm))
        || identity.cert_hash.as_bytes()
            != Sha256::digest(certificate.to_der().map_err(|_| ReleaseError::Invalid)?).as_slice()
    {
        return Err(ReleaseError::Authentication);
    }
    if let Some(issuer) = &identity.issuer_serial
        && (issuer.serial_number != certificate.tbs_certificate.serial_number
            || issuer.issuer.len() != 1
            || !issuer.issuer.iter().any(|name| matches!(name, GeneralName::DirectoryName(name) if *name == certificate.tbs_certificate.issuer)))
    {
        return Err(ReleaseError::Authentication);
    }
    Ok(())
}
pub(crate) fn valid_at(
    certificate: &Certificate,
    first: u64,
    last: u64,
) -> Result<(), ReleaseError> {
    if certificate
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs()
        > first
        || certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            < last
    {
        return Err(ReleaseError::Authentication);
    }
    Ok(())
}
pub(crate) fn signing_time(attrs: &Attributes) -> Result<u64, ReleaseError> {
    let value = attribute(attrs, "1.2.840.113549.1.9.5")?;
    let time = x509_cert::time::Time::from_der(&value.to_der().map_err(|_| ReleaseError::Invalid)?)
        .map_err(|_| ReleaseError::Invalid)?;
    Ok(time.to_unix_duration().as_secs())
}
