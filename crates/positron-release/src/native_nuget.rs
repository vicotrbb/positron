//! Native NuGet repository-primary signatures with explicitly installed certificate and TSA trust.
use crate::{ReleaseError, native_cms as cms_profile};
mod timestamp;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use der::{
    Decode, Encode, Sequence,
    asn1::{Any, Ia5String, ObjectIdentifier},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sigstore_verify::crypto::WEBPKI_VERIFICATION_ALGS;
use x509_cert::Certificate;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trust {
    signer: String,
    intermediates: Vec<String>,
    root: String,
    timestamp: TimestampTrust,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimestampTrust {
    leaf: String,
    intermediates: Vec<String>,
    root: String,
    not_before_unix: u64,
    expires_unix: u64,
    policy_oid: String,
}
#[derive(Clone, Debug, Sequence)]
struct Commitment {
    commitment_type_id: ObjectIdentifier,
    qualifiers: Option<Vec<Any>>,
}
fn certificate(value: &str) -> Result<Vec<u8>, ReleaseError> {
    if value.len() > 16_384 {
        return Err(ReleaseError::LimitExceeded);
    }
    B64.decode(value).map_err(|_| ReleaseError::Invalid)
}
const CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
fn chain(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    root: &[u8],
    first: u64,
    last: u64,
    eku: &'static [u8],
) -> Result<(), ReleaseError> {
    use rustls_pki_types::{CertificateDer, UnixTime};
    let leaf_der = CertificateDer::from(leaf);
    let end =
        webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| ReleaseError::Authentication)?;
    let root_der = CertificateDer::from(root);
    let anchors = [
        webpki::anchor_from_trusted_cert(&root_der).map_err(|_| ReleaseError::Authentication)?
    ];
    let intermediates: Vec<_> = intermediates
        .iter()
        .map(|value| CertificateDer::from(value.as_slice()))
        .collect();
    for time in [first, last] {
        end.verify_for_usage(
            WEBPKI_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(time)),
            webpki::KeyUsage::required(eku),
            None,
            None,
        )
        .map_err(|_| ReleaseError::Authentication)?;
    }
    Ok(())
}
fn purpose(certificate: &Certificate, required: &str, timestamp: bool) -> Result<(), ReleaseError> {
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(ReleaseError::Authentication)?;
    let matching: Vec<_> = extensions
        .iter()
        .filter(|extension| extension.extn_id.to_string() == "2.5.29.37")
        .collect();
    if matching.len() != 1 {
        return Err(ReleaseError::Authentication);
    }
    let extension = matching.first().ok_or(ReleaseError::Authentication)?;
    let usage = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(extension.extn_value.as_bytes())
        .map_err(|_| ReleaseError::Invalid)?;
    if !usage.0.iter().any(|oid| oid.to_string() == required)
        || usage
            .0
            .iter()
            .any(|oid| oid.to_string() == "1.3.6.1.4.1.311.10.3.13")
        || (timestamp && (!extension.critical || usage.0.len() != 1))
    {
        return Err(ReleaseError::Authentication);
    }
    Ok(())
}
pub(crate) fn verify(
    root: &Value,
    bytes: &[u8],
    name: &str,
    version: &str,
    registry: &str,
    now: u64,
) -> Result<Vec<[u8; 32]>, ReleaseError> {
    let trust: Trust = serde_json::from_value(root.clone()).map_err(|_| ReleaseError::Invalid)?;
    if trust.intermediates.len() > 8 || trust.timestamp.intermediates.len() > 8 {
        return Err(ReleaseError::LimitExceeded);
    }
    let package = crate::nuget_zip::package(bytes)?;
    let metadata = crate::native_xml::document(&package.nuspec)?;
    let top = metadata.root_element();
    if top.tag_name().name() != "package"
        || !matches!(
            top.tag_name().namespace(),
            None | Some("http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd")
        )
    {
        return Err(ReleaseError::Unsupported);
    }
    let info = crate::native_xml::child(top, "metadata")?;
    let actual_name = crate::native_xml::text(crate::native_xml::child(info, "id")?)?;
    if !actual_name.eq_ignore_ascii_case(name)
        || !package
            .nuspec_name
            .eq_ignore_ascii_case(&format!("{name}.nuspec"))
        || crate::native_xml::text(crate::native_xml::child(info, "version")?)? != version
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    let document = cms_profile::document(&package.signature)?;
    let signer_der = certificate(&trust.signer)?;
    let signer_cert = Certificate::from_der(&signer_der).map_err(|_| ReleaseError::Invalid)?;
    purpose(&signer_cert, "1.3.6.1.5.5.7.3.3", false)?;
    cms_profile::verify(&document, &signer_cert, cms_profile::DATA)?;
    let expected = format!(
        "Version:1\n\n2.16.840.1.101.3.4.2.1-Hash:{}\n\n",
        B64.encode(Sha256::digest(&package.unsigned))
    );
    if cms_profile::content(&document)? != expected.as_bytes() {
        return Err(ReleaseError::IdentityMismatch);
    }
    let signer = cms_profile::signer(&document)?;
    let attrs = cms_profile::attributes(signer)?;
    let commitment = cms_profile::attribute(attrs, "1.2.840.113549.1.9.16.2.16")?
        .decode_as::<Commitment>()
        .map_err(|_| ReleaseError::Invalid)?;
    if commitment.commitment_type_id.to_string() != "1.2.840.113549.1.9.16.6.2"
        || commitment.qualifiers.is_some()
        || cms_profile::attribute(attrs, "1.3.6.1.4.1.311.84.2.1.1.1")?
            .decode_as::<Ia5String>()
            .map_err(|_| ReleaseError::Invalid)?
            .as_str()
            != registry
    {
        return Err(ReleaseError::IdentityMismatch);
    }
    if let Some(owners) = attrs
        .iter()
        .find(|attribute| attribute.oid.to_string() == "1.3.6.1.4.1.311.84.2.1.1.2")
    {
        let owners = owners
            .values
            .get(0)
            .ok_or(ReleaseError::Invalid)?
            .decode_as::<Vec<String>>()
            .map_err(|_| ReleaseError::Invalid)?;
        if owners.is_empty()
            || owners.len() > 64
            || owners
                .iter()
                .any(|owner| owner.as_str().trim().is_empty() || owner.as_str().len() > 256)
        {
            return Err(ReleaseError::Invalid);
        }
    }
    let unsigned = signer
        .unsigned_attrs
        .as_ref()
        .ok_or(ReleaseError::Authentication)?;
    if unsigned.len() != 1 {
        return Err(ReleaseError::Unsupported);
    }
    let token = cms_profile::attribute(unsigned, "1.2.840.113549.1.9.16.2.14")?
        .to_der()
        .map_err(|_| ReleaseError::Invalid)?;
    let (first, last, mut identities) =
        timestamp::verify(&trust.timestamp, &token, signer.signature.as_bytes(), now)?;
    let signed_at = cms_profile::signing_time(attrs)?;
    if signed_at < first || signed_at > last {
        return Err(ReleaseError::Authentication);
    }
    cms_profile::valid_at(&signer_cert, first, last)?;
    let intermediates = trust
        .intermediates
        .iter()
        .map(|value| certificate(value))
        .collect::<Result<Vec<_>, _>>()?;
    let root = certificate(&trust.root)?;
    chain(
        &signer_der,
        &intermediates,
        &root,
        first,
        last,
        CODE_SIGNING.as_bytes(),
    )?;
    identities.extend(
        std::iter::once(&signer_der)
            .chain(intermediates.iter())
            .chain(std::iter::once(&root))
            .map(|certificate| <[u8; 32]>::from(Sha256::digest(certificate))),
    );
    Ok(identities)
}
#[cfg(test)]
mod tests;
