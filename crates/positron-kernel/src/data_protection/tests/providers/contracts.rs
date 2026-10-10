use super::*;

#[test]
fn credential_models_and_failure_diagnostics_keep_secret_canaries_out()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{
        CredentialFileReference, ProviderCredentialModel, TransitAuthentication,
    };
    let canary = "provider-secret-canary-137";
    let path = std::path::Path::new("/external/provider-secret-canary-137");
    let reference = CredentialFileReference::new(path)?;
    let token = ProviderCredentialModel::Transit(TransitAuthentication::ProtectedTokenFile(
        reference.clone(),
    ));
    assert!(!format!("{reference:?}{token:?}").contains(canary));
    assert!(token.validate(ProviderFamily::VaultTransit).is_ok());
    assert!(token.validate(ProviderFamily::OpenBaoTransit).is_ok());
    assert_eq!(
        token.validate(ProviderFamily::AwsKms),
        Err(KeyProviderFailure::InvalidConfiguration)
    );
    for (family, model) in [
        (
            ProviderFamily::LocalFile,
            ProviderCredentialModel::LocalFile,
        ),
        (
            ProviderFamily::AwsKms,
            ProviderCredentialModel::AwsStandardChain,
        ),
        (
            ProviderFamily::GoogleCloudKms,
            ProviderCredentialModel::GoogleApplicationDefault,
        ),
        (
            ProviderFamily::AzureKeyVault,
            ProviderCredentialModel::AzureManagedIdentity,
        ),
        (
            ProviderFamily::AzureManagedHsm,
            ProviderCredentialModel::AzureWorkloadIdentity,
        ),
        (
            ProviderFamily::Kmip21,
            ProviderCredentialModel::KmipMutualTls {
                certificate: reference.clone(),
                private_key: reference.clone(),
                trust_roots: reference.clone(),
            },
        ),
    ] {
        model.validate(family)?;
    }
    assert!(CredentialFileReference::new(std::path::Path::new("relative")).is_err());
    assert!(CredentialFileReference::new(std::path::Path::new("/external/../secret")).is_err());
    let invalid_role = ProviderCredentialModel::Transit(TransitAuthentication::Jwt {
        role: "token has spaces".to_owned(),
        jwt_file: reference,
    });
    assert!(invalid_role.validate(ProviderFamily::VaultTransit).is_err());
    for failure in [
        KeyProviderFailure::InvalidConfiguration,
        KeyProviderFailure::Unavailable,
        KeyProviderFailure::PermissionDenied,
        KeyProviderFailure::WrongKey,
        KeyProviderFailure::ContextMismatch,
        KeyProviderFailure::Ambiguous,
        KeyProviderFailure::LimitExceeded,
        KeyProviderFailure::MemoryProtection,
    ] {
        assert!(!format!("{failure:?}{failure}").contains(canary));
    }
    Ok(())
}

#[test]
fn ambiguous_and_permanent_wrap_results_propagate_without_automatic_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = ControlledLocal {
        inner: LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
            &root.path,
        )?)?,
        failure: std::cell::Cell::new(None),
        calls: std::cell::Cell::new(0),
        probe_failure: std::cell::Cell::new(None),
        wrap_failure: std::cell::Cell::new(None),
    };
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    for failure in [
        KeyProviderFailure::Ambiguous,
        KeyProviderFailure::PermissionDenied,
        KeyProviderFailure::Unavailable,
    ] {
        provider.wrap_failure.set(Some(failure));
        assert_eq!(
            ready(KeyProviderSession::new(&provider).wrap(SecretKek::generate()?, context)).err(),
            Some(failure)
        );
    }
    Ok(())
}
#[test]
fn provider_identity_requires_an_exact_key_and_version() {
    assert_eq!(
        ProviderKeyUri::new(
            ProviderFamily::AwsKms,
            "arn:aws:kms:us-east-1:123456789012:alias/current",
            "1"
        ),
        Err(KeyProviderFailure::InvalidConfiguration)
    );
    assert!(ProviderKeyUri::new(ProviderFamily::LocalFile, "local-root", "1").is_ok());
}

#[test]
fn provider_outcomes_never_turn_ambiguous_or_denied_into_retryable() {
    use protection::key_provider::ProviderFailureDisposition;
    assert_eq!(
        KeyProviderFailure::Unavailable.disposition(),
        ProviderFailureDisposition::Retryable
    );
    assert_eq!(
        KeyProviderFailure::Ambiguous.disposition(),
        ProviderFailureDisposition::Ambiguous
    );
    assert_eq!(
        KeyProviderFailure::PermissionDenied.disposition(),
        ProviderFailureDisposition::Permanent
    );
}

#[test]
fn provider_envelope_codec_rejects_truncation_trailing_and_changed_routing()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyEnvelope, WrappingAlgorithm};
    let identity = ProviderKeyUri::new(ProviderFamily::LocalFile, "local-root", "1")?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = KeyEnvelope::from_provider_response(
        identity,
        context,
        WrappingAlgorithm::Aes256Kwp,
        vec![9; 48],
    )?;
    let encoded = envelope.encode();
    assert_eq!(KeyEnvelope::decode(&encoded)?, envelope);
    for length in 0..encoded.len() {
        assert!(KeyEnvelope::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(KeyEnvelope::decode(&trailing).is_err());
    let mut altered = encoded;
    altered[10] ^= 1;
    assert!(KeyEnvelope::decode(&altered).is_err());
    Ok(())
}

#[test]
fn provider_session_requires_live_capabilities_even_for_valid_ciphertext()
-> Result<(), Box<dyn std::error::Error>> {
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider = ControlledLocal {
        inner: LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
            &root.path,
        )?)?,
        failure: std::cell::Cell::new(None),
        calls: std::cell::Cell::new(0),
        probe_failure: std::cell::Cell::new(None),
        wrap_failure: std::cell::Cell::new(None),
    };
    let session = KeyProviderSession::new(&provider);
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(session.wrap(SecretKek::generate()?, context))?;
    provider
        .probe_failure
        .set(Some(KeyProviderFailure::PermissionDenied));
    assert_eq!(
        ready(session.verify(&envelope, context)),
        Err(KeyProviderFailure::PermissionDenied)
    );
    Ok(())
}

#[test]
fn provider_uri_cannot_name_an_empty_version_or_disagree_with_a_native_version() {
    for (family, locator, version) in [
        (
            ProviderFamily::GoogleCloudKms,
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/",
            "1",
        ),
        (
            ProviderFamily::GoogleCloudKms,
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2",
            "1",
        ),
        (
            ProviderFamily::AzureKeyVault,
            "https://example.vault.azure.net/keys/root/",
            "1",
        ),
        (
            ProviderFamily::AwsKms,
            "arn:aws:kms:us-east-1:123456789012:key/",
            "immutable",
        ),
        (
            ProviderFamily::VaultTransit,
            "https://vault.test/v1/transit/keys/root",
            "latest",
        ),
    ] {
        assert_eq!(
            ProviderKeyUri::new(family, locator, version),
            Err(KeyProviderFailure::InvalidConfiguration)
        );
    }
}

#[test]
fn external_key_envelope_preserves_its_actual_wrapping_algorithm()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = ProviderKeyUri::new(
        ProviderFamily::Kmip21,
        "kmip://hsm.test/objects/immutable-id",
        "immutable",
    )?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = protection::key_provider::KeyEnvelope::from_provider_response(
        identity,
        context,
        protection::key_provider::WrappingAlgorithm::Aes256Kwp,
        vec![1; 40],
    )?;
    assert_eq!(
        protection::key_provider::KeyEnvelope::decode(&envelope.encode())?,
        envelope
    );
    Ok(())
}

#[test]
fn opaque_provider_envelopes_do_not_contain_the_plaintext_secret_canary()
-> Result<(), Box<dyn std::error::Error>> {
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let provider =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(&root.path)?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let envelope = ready(
        KeyProviderSession::new(&provider)
            .wrap(SecretKek::from_owned(Box::new([0xa7; 32])), context),
    )?;
    assert!(
        !envelope
            .encode()
            .windows(32)
            .any(|window| window == [0xa7; 32])
    );
    Ok(())
}
