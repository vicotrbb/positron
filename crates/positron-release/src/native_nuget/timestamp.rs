//! Strict native timestamp interval and installed authority checks.
use super::*;
use sigstore_verify::types::{DerCertificate, SignatureBytes, TimestampToken, TsaAuthority};
pub(super) fn verify(
    trust: &TimestampTrust,
    token: &[u8],
    signature: &[u8],
    now: u64,
) -> Result<(u64, u64, Vec<[u8; 32]>), ReleaseError> {
    if trust.not_before_unix >= trust.expires_unix {
        return Err(ReleaseError::Invalid);
    }
    let leaf = certificate(&trust.leaf)?;
    let cert = Certificate::from_der(&leaf).map_err(|_| ReleaseError::Invalid)?;
    purpose(&cert, "1.3.6.1.5.5.7.3.8", true)?;
    let document = cms_profile::document(token)?;
    let signer = cms_profile::signer(&document)?;
    if signer
        .unsigned_attrs
        .as_ref()
        .is_some_and(|attributes| !attributes.is_empty())
    {
        return Err(ReleaseError::Unsupported);
    }
    cms_profile::verify(&document, &cert, cms_profile::TST_INFO)?;
    let info = sigstore_verify::tsa::asn1::TstInfo::from_der(cms_profile::content(&document)?)
        .map_err(|_| ReleaseError::Invalid)?;
    if info.version != 1 || info.policy.to_string() != trust.policy_oid || info.extensions.is_some()
    {
        return Err(ReleaseError::Unsupported);
    }
    let time = info.gen_time.to_unix_duration().as_secs();
    let mut accuracy = if trust.policy_oid == "0.4.0.2023.1.1" {
        1_u64
    } else {
        0
    };
    if let Some(value) = &info.accuracy {
        if value.seconds.is_some_and(|value| value > 3600)
            || value
                .millis
                .is_some_and(|value| !(1..=999).contains(&value))
            || value
                .micros
                .is_some_and(|value| !(1..=999).contains(&value))
        {
            return Err(ReleaseError::Unsupported);
        }
        accuracy = value
            .seconds
            .unwrap_or(0)
            .checked_add(u64::from(value.millis.is_some() || value.micros.is_some()))
            .ok_or(ReleaseError::Invalid)?;
    }
    let first = time
        .checked_sub(accuracy)
        .ok_or(ReleaseError::Authentication)?;
    let last = time
        .checked_add(accuracy)
        .ok_or(ReleaseError::Authentication)?;
    if first < trust.not_before_unix || last >= trust.expires_unix || last > now {
        return Err(ReleaseError::Authentication);
    }
    cms_profile::valid_at(&cert, first, last)?;
    let signed_at = cms_profile::signing_time(cms_profile::attributes(signer)?)?;
    if signed_at < first || signed_at > last {
        return Err(ReleaseError::Authentication);
    }
    let intermediates = trust
        .intermediates
        .iter()
        .map(|value| certificate(value))
        .collect::<Result<Vec<_>, _>>()?;
    let root = certificate(&trust.root)?;
    let authority = TsaAuthority::new(
        DerCertificate::new(leaf.clone()),
        intermediates
            .iter()
            .cloned()
            .map(DerCertificate::new)
            .collect(),
        DerCertificate::new(root.clone()),
        None,
    );
    let verified = sigstore_verify::tsa::verify_timestamp_for_authority(
        &TimestampToken::from_bytes(token),
        &SignatureBytes::from_bytes(signature),
        &authority,
    )
    .map_err(|_| ReleaseError::Authentication)?;
    if verified.as_second() < 0 || verified.as_second() as u64 != time {
        return Err(ReleaseError::Authentication);
    }
    Ok((
        first,
        last,
        std::iter::once(&leaf)
            .chain(intermediates.iter())
            .chain(std::iter::once(&root))
            .map(|certificate| <[u8; 32]>::from(Sha256::digest(certificate)))
            .collect(),
    ))
}
