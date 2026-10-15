//! Private native Repository session capability custody.
use super::DataProtection;
use super::control_token::{
    ControlTokenAuthentication, ControlTokenFailure, ControlTokenProtector,
};
use crate::catalog::CatalogSecret;
use std::fmt::Formatter;
use std::sync::Mutex;
use zeroize::Zeroizing;
/// Narrow owned authentication for private native Repository upload recovery.
/// Provider sessions are bearer capabilities; a checksum alone cannot authorize
/// a recovered session. Key material stays within the existing Catalog custody.
pub struct RepositoryUploadAuthenticator {
    secret: Mutex<CatalogSecret>,
    instance: crate::InstanceId,
}
impl RepositoryUploadAuthenticator {
    pub fn new(secret: CatalogSecret, instance: crate::InstanceId) -> Self {
        Self {
            secret: Mutex::new(secret),
            instance,
        }
    }
    pub fn authenticate(
        &self,
        digest: [u8; 32],
    ) -> Result<ControlTokenAuthentication, ControlTokenFailure> {
        ControlTokenProtector::new(&self.secret)
            .authenticate(b"repository-native-upload-v1", &digest)
    }
    pub fn verify(
        &self,
        digest: [u8; 32],
        authentication: ControlTokenAuthentication,
    ) -> Result<(), ControlTokenFailure> {
        ControlTokenProtector::new(&self.secret).verify(
            b"repository-native-upload-v1",
            &digest,
            authentication,
        )
    }
    pub const fn instance_id(&self) -> [u8; 16] {
        self.instance.to_bytes()
    }
    fn context(
        &self,
        object_id: [u8; 16],
        epoch: u64,
    ) -> Result<(super::FrameObjectContext, super::WrappedKeyContext), ControlTokenFailure> {
        let object = super::FrameObjectContext::system(
            super::SystemObjectKind::BackupMetadata,
            super::FrameObjectId::new(object_id).map_err(|_| ControlTokenFailure::InvalidInput)?,
            super::KeyEpoch::new(epoch),
            super::FrameFormatEpoch::new(1).map_err(|_| ControlTokenFailure::InvalidInput)?,
        );
        let key_id =
            DataProtection::hash(&object_id).map_err(|_| ControlTokenFailure::Authentication)?;
        let digest = DataProtection::hash(b"positron-repository-session-v1")
            .map_err(|_| ControlTokenFailure::Authentication)?;
        let wrapping = super::WrappedKeyContext::system(
            self.instance.to_bytes(),
            super::SystemObjectKind::BackupMetadata,
            key_id,
            epoch,
            digest,
        )
        .map_err(|_| ControlTokenFailure::InvalidInput)?;
        Ok((object, wrapping))
    }
    /// One fresh system-object DEK and frame sequence per persisted capability.
    pub fn seal_session(&self, plaintext: &[u8]) -> Result<Vec<u8>, ControlTokenFailure> {
        use super::{CryptoBackend, RustCryptoBackend};
        if plaintext.is_empty() || plaintext.len() > 3072 {
            return Err(ControlTokenFailure::InvalidInput);
        }
        let secret = self
            .secret
            .lock()
            .map_err(|_| ControlTokenFailure::Custody)?;
        let mut id = [0; 16];
        RustCryptoBackend
            .fill_random(&mut id)
            .map_err(|_| ControlTokenFailure::Authentication)?;
        let (object, wrapping) = self.context(id, secret.wrapping.key_epoch)?;
        let key =
            DataProtection::random_key(object).map_err(|_| ControlTokenFailure::Authentication)?;
        let wrapped = DataProtection::wrap_key_payload(&secret.wrapping.key, &key, wrapping)
            .map_err(|_| ControlTokenFailure::Authentication)?;
        let frame = DataProtection::protect_frame(
            &key,
            object
                .system_frame(super::FrameSequence::new(1))
                .map_err(|_| ControlTokenFailure::InvalidInput)?,
            plaintext,
            super::FrameLimits::new(4096).map_err(|_| ControlTokenFailure::InvalidInput)?,
        )
        .map_err(|_| ControlTokenFailure::Authentication)?;
        let mut bytes = Vec::with_capacity(36 + wrapped.len() + frame.as_bytes().len());
        bytes.extend_from_slice(b"POSGCS01");
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&secret.wrapping.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&(wrapped.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&wrapped);
        bytes.extend_from_slice(frame.as_bytes());
        Ok(bytes)
    }
    pub fn open_session(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ControlTokenFailure> {
        if bytes.len() < 100 || bytes.len() > 4096 || bytes.get(..8) != Some(b"POSGCS01") {
            return Err(ControlTokenFailure::InvalidInput);
        }
        fn field<const N: usize>(
            bytes: &[u8],
            start: usize,
        ) -> Result<[u8; N], ControlTokenFailure> {
            bytes
                .get(start..start + N)
                .and_then(|s| s.try_into().ok())
                .ok_or(ControlTokenFailure::InvalidInput)
        }
        let id = field(bytes, 8)?;
        let epoch = u64::from_be_bytes(field(bytes, 24)?);
        let length = u32::from_be_bytes(field(bytes, 32)?) as usize;
        if length > 512 {
            return Err(ControlTokenFailure::InvalidInput);
        }
        let wrapped = bytes
            .get(36..36 + length)
            .ok_or(ControlTokenFailure::InvalidInput)?;
        let frame = bytes
            .get(36 + length..)
            .ok_or(ControlTokenFailure::InvalidInput)?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| ControlTokenFailure::Custody)?;
        if epoch != secret.wrapping.key_epoch {
            return Err(ControlTokenFailure::Authentication);
        }
        let (object, wrapping) = self.context(id, epoch)?;
        let key =
            DataProtection::unwrap_key_payload(&secret.wrapping.key, wrapped, wrapping, object)
                .map_err(|_| ControlTokenFailure::Authentication)?;
        let plaintext = DataProtection::open_frame(
            &key,
            object
                .system_frame(super::FrameSequence::new(1))
                .map_err(|_| ControlTokenFailure::InvalidInput)?,
            frame,
            super::FrameLimits::new(4096).map_err(|_| ControlTokenFailure::InvalidInput)?,
        )
        .map_err(|_| ControlTokenFailure::Authentication)?;
        if plaintext.as_plaintext().len() > 3072 {
            return Err(ControlTokenFailure::InvalidInput);
        }
        Ok(Zeroizing::new(plaintext.as_plaintext().to_vec()))
    }
}
impl std::fmt::Debug for RepositoryUploadAuthenticator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepositoryUploadAuthenticator { <redacted> }")
    }
}
