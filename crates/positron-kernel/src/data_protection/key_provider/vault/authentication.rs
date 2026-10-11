use super::*;
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

pub(super) struct Token {
    pub(super) value: Zeroizing<String>,
    pub(super) renew_at: tokio::time::Instant,
    pub(super) expires_at: tokio::time::Instant,
}
pub(super) fn validate_mount(
    model: &ProviderCredentialModel,
    mount: &str,
) -> Result<(), KeyProviderFailure> {
    let protected = matches!(
        model,
        ProviderCredentialModel::Transit(TransitAuthentication::ProtectedTokenFile(_))
    );
    let valid = !mount.is_empty()
        && mount.len() <= 128
        && mount.split('/').all(|p| {
            !p.is_empty()
                && !matches!(p, "." | "..")
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        });
    if (protected && mount.is_empty()) || (!protected && valid) {
        Ok(())
    } else {
        Err(KeyProviderFailure::InvalidConfiguration)
    }
}
pub(super) fn read_credential(
    model: &ProviderCredentialModel,
) -> Result<Zeroizing<String>, KeyProviderFailure> {
    let reference = match model {
        ProviderCredentialModel::Transit(
            TransitAuthentication::ProtectedTokenFile(reference)
            | TransitAuthentication::Kubernetes {
                jwt_file: reference,
                ..
            }
            | TransitAuthentication::Jwt {
                jwt_file: reference,
                ..
            },
        ) => reference,
        _ => return Err(KeyProviderFailure::InvalidConfiguration),
    };
    // Kubernetes AtomicWriter rotates projected JWTs through ..data symlinks.
    // Their opened target must meet the same bounded regular-file custody checks.
    // A protected Vault token file retains the stricter no-follow requirement.
    let no_follow = if matches!(
        model,
        ProviderCredentialModel::Transit(TransitAuthentication::ProtectedTokenFile(_))
    ) {
        rustix::fs::OFlags::NOFOLLOW
    } else {
        rustix::fs::OFlags::empty()
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((no_follow | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(reference.path())
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => KeyProviderFailure::PermissionDenied,
            std::io::ErrorKind::NotFound => KeyProviderFailure::InvalidConfiguration,
            _ => KeyProviderFailure::InvalidConfiguration,
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| KeyProviderFailure::Unavailable)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(KeyProviderFailure::PermissionDenied);
    }
    if metadata.len() > 8192 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(8193));
    file.take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| KeyProviderFailure::Unavailable)?;
    if bytes.len() > 8192 {
        return Err(KeyProviderFailure::LimitExceeded);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| KeyProviderFailure::InvalidConfiguration)?
        .trim_end_matches(['\r', '\n']);
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(KeyProviderFailure::InvalidConfiguration);
    }
    Ok(Zeroizing::new(text.to_owned()))
}
impl VaultTransitKeyProvider {
    pub(super) async fn authenticate(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Zeroizing<String>, KeyProviderFailure> {
        let previous = self
            .token
            .lock()
            .map_err(|_| KeyProviderFailure::Unavailable)?
            .take();
        let now = tokio::time::Instant::now();
        let token = if let Some(previous) = previous.filter(|t| t.expires_at > now) {
            if previous.renew_at > now {
                previous
            } else {
                let issued_at = tokio::time::Instant::now();
                let reply = self
                    .request(
                        protocol::Operation::Renew,
                        Some(&previous.value),
                        Zeroizing::new(b"{}".to_vec()),
                        deadline,
                    )
                    .await?;
                let renewed = protocol::authentication_response(&reply, issued_at)?;
                if renewed.value.as_str() != previous.value.as_str() {
                    return Err(KeyProviderFailure::PermissionDenied);
                }
                renewed
            }
        } else {
            let credential = read_credential(&self.credential_model)?;
            let issued_at = tokio::time::Instant::now();
            match &self.credential_model {
                ProviderCredentialModel::Transit(TransitAuthentication::ProtectedTokenFile(_)) => {
                    let reply = self
                        .request(
                            protocol::Operation::Lookup,
                            Some(&credential),
                            Zeroizing::new(Vec::new()),
                            deadline,
                        )
                        .await?;
                    protocol::lookup_response(&reply, credential, issued_at)?
                },
                ProviderCredentialModel::Transit(
                    TransitAuthentication::Kubernetes { role, .. }
                    | TransitAuthentication::Jwt { role, .. },
                ) => {
                    let request = protocol::login_request(role, &credential)?;
                    drop(credential);
                    let reply = self
                        .request(protocol::Operation::Login, None, request, deadline)
                        .await?;
                    protocol::authentication_response(&reply, issued_at)?
                },
                _ => return Err(KeyProviderFailure::InvalidConfiguration),
            }
        };
        let value = Zeroizing::new(token.value.to_string());
        *self
            .token
            .lock()
            .map_err(|_| KeyProviderFailure::Unavailable)? = Some(token);
        Ok(value)
    }
}
