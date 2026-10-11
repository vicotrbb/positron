//! Fresh authenticated TLS identity on every operation; no credential persistence.
use super::*;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
pub(super) fn identity(
    runtime: &super::super::google::native::NativeRuntime,
    model: &ProviderCredentialModel,
) -> Result<Arc<rustls::ClientConfig>, KeyProviderFailure> {
    let ProviderCredentialModel::KmipMutualTls {
        certificate,
        private_key,
        trust_roots,
    } = model
    else {
        return Err(KeyProviderFailure::InvalidConfiguration);
    };
    let pem = runtime.read_protected(certificate.path(), true)?;
    let chain = CertificateDer::pem_slice_iter(&pem)
        .take(17)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    if chain.is_empty() || chain.len() > 16 {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    let pem = runtime.read_protected(private_key.path(), true)?;
    let key = PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    let pem = runtime.read_trust_roots(trust_roots.path())?;
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .take(17)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    if certificates.is_empty() || certificates.len() > 16 {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    }
    let mut crypto = rustls::crypto::ring::default_provider();
    crypto.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384];
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?;
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
