//! Owner-controlled age v1 recovery. Plaintext root material never leaves custody.
use super::{BootstrapIntegrityIdentity, BootstrapKeyCustody, BootstrapKeyIdentity};
use crate::data_protection::backend::{
    RecoveryCryptoPurpose, RecoveryDecryption, RecoveryEncryption,
};
use crate::data_protection::{CryptoBackend, CryptoBackendFailure, RustCryptoBackend};
use crate::{
    InstanceId, ResourceAmounts, ResourceReservation, StorageKernelResourceAuthority, WorkClaim,
};
use age::secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

#[cfg(test)]
mod fault_tests;
#[cfg(any(test, fuzzing))]
mod fuzzing;
#[cfg(fuzzing)]
pub fn fuzz_recovery_bundle_payload(data: &[u8]) {
    let _outcome = fuzzing::exercise(data);
}
mod files;
mod payload;
use payload::{decode, encode, encode_with_system, signed, verify_signed};
const MAX_BUNDLE: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFailure {
    InvalidInput,
    Admission,
    Authentication,
    LimitExceeded,
    Custody,
    Storage,
    Missing,
    AlreadyExists,
}
impl std::fmt::Display for RecoveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("recovery bundle operation failed")
    }
}
impl std::error::Error for RecoveryFailure {}

/// Externally pinned trust, never derived from an untrusted bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryIdentity {
    instance: InstanceId,
    root: BootstrapKeyIdentity,
    integrity: BootstrapIntegrityIdentity,
}
impl RecoveryIdentity {
    pub fn new(
        instance: InstanceId,
        root: BootstrapKeyIdentity,
        integrity: BootstrapIntegrityIdentity,
    ) -> Result<Self, RecoveryFailure> {
        BootstrapIntegrityIdentity::from_pinned(integrity.public_key(), integrity.fingerprint())
            .map_err(|_| RecoveryFailure::InvalidInput)?;
        Ok(Self {
            instance,
            root,
            integrity,
        })
    }
    #[must_use]
    pub const fn instance(self) -> InstanceId {
        self.instance
    }
    #[must_use]
    pub const fn root(self) -> BootstrapKeyIdentity {
        self.root
    }
    #[must_use]
    pub const fn integrity(self) -> BootstrapIntegrityIdentity {
        self.integrity
    }
}

/// A canonical bounded set of native age X25519 recipients.
pub struct RecoveryRecipients {
    identities: Vec<String>,
}
impl RecoveryRecipients {
    pub fn parse(identities: &[String]) -> Result<Self, RecoveryFailure> {
        if identities.is_empty() || identities.len() > 16 {
            return Err(RecoveryFailure::InvalidInput);
        }
        let mut canonical = Vec::with_capacity(identities.len());
        for value in identities {
            if value.len() != 62 {
                return Err(RecoveryFailure::InvalidInput);
            }
            let recipient: age::x25519::Recipient =
                value.parse().map_err(|_| RecoveryFailure::InvalidInput)?;
            if recipient.to_string() != *value {
                return Err(RecoveryFailure::InvalidInput);
            }
            canonical.push(value.clone());
        }
        canonical.sort();
        if canonical.windows(2).any(|pair| pair.first() == pair.get(1)) {
            return Err(RecoveryFailure::InvalidInput);
        }
        Ok(Self {
            identities: canonical,
        })
    }
}
/// Move-only passphrase, supplied only by a protected interactive terminal.
pub struct RecoveryPassphrase(SecretString);
impl RecoveryPassphrase {
    pub fn from_interactive(value: String) -> Result<Self, RecoveryFailure> {
        let secret = Self(SecretString::from(value));
        if secret.0.expose_secret().len() < 12 || secret.0.expose_secret().len() > 1024 {
            return Err(RecoveryFailure::InvalidInput);
        }
        Ok(secret)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryProtection {
    Recipients,
    Passphrase,
}
pub enum RecoveryUnlock<'a> {
    IdentityFile(&'a std::path::Path),
    Identity(&'a age::x25519::Identity),
    Passphrase(&'a RecoveryPassphrase),
    InteractivePassphrase(&'a mut dyn FnMut() -> Result<RecoveryPassphrase, RecoveryFailure>),
}

/// Only non-secret authenticated inner metadata is inspectable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryMetadata {
    payload_version: u8,
    identity: RecoveryIdentity,
    created: u64,
    recipients: Vec<String>,
}
impl RecoveryMetadata {
    #[must_use]
    pub const fn payload_version(&self) -> u8 {
        self.payload_version
    }
    #[must_use]
    pub const fn identity(&self) -> RecoveryIdentity {
        self.identity
    }
    #[must_use]
    pub const fn created_at_unix_seconds(&self) -> u64 {
        self.created
    }
    #[must_use]
    pub fn recipients(&self) -> &[String] {
        &self.recipients
    }
}

/// Held admission for the complete cryptography, file publication, and Catalog acknowledgement.
pub struct RecoverySession<'a> {
    _reservation: ResourceReservation<'a>,
    mode: RecoveryProtection,
}
impl<'a> RecoverySession<'a> {
    /// Hashes a bounded encrypted recovery artifact under the held recovery grant.
    pub fn bundle_digest(&self, ciphertext: &[u8]) -> Result<[u8; 32], RecoveryFailure> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_BUNDLE {
            return Err(RecoveryFailure::LimitExceeded);
        }
        RustCryptoBackend
            .sha256(ciphertext)
            .map_err(|_| RecoveryFailure::Authentication)
    }

    /// Exercises the existing durable directory I/O failure seam in cross-crate tests.
    #[cfg(feature = "test-support")]
    pub fn with_directory_sync_failure<T>(operation: impl FnOnce() -> T) -> T {
        super::initialization_io::with_initialization_fault(
            super::initialization_io::InitializationFault::SynchronizeSecurityDirectory,
            operation,
        )
    }

    pub fn admit(
        authority: &'a StorageKernelResourceAuthority,
        mode: RecoveryProtection,
    ) -> Result<Self, RecoveryFailure> {
        // scrypt N=2^18, r=8 needs 256 MiB; include its scratch, age buffers and bounded file work.
        let memory = if mode == RecoveryProtection::Passphrase {
            332_000_000
        } else {
            32_000_000
        };
        let claim = WorkClaim::system_security(ResourceAmounts::new([
            memory, 1, 1, 0, 16, 0, 0, 1, 1, 4, 16_384,
        ]))
        .map_err(|_| RecoveryFailure::Admission)?;
        let reservation = authority
            .governor()
            .reserve(claim)
            .map_err(|_| RecoveryFailure::Admission)?;
        Ok(Self {
            _reservation: reservation,
            mode,
        })
    }
    pub fn create(
        &self,
        custody: &BootstrapKeyCustody,
        pin: RecoveryIdentity,
        protected_integrity: &[u8],
        recipients: &RecoveryRecipients,
        created: u64,
    ) -> Result<Vec<u8>, RecoveryFailure> {
        if self.mode != RecoveryProtection::Recipients {
            return Err(RecoveryFailure::InvalidInput);
        }
        let payload = self.payload(
            custody,
            pin,
            protected_integrity,
            &recipients.identities,
            created,
        )?;
        RustCryptoBackend
            .seal_recovery(
                RecoveryCryptoPurpose::LocalRootPayloadV1,
                RecoveryEncryption::Recipients(&recipients.identities),
                &payload,
            )
            .map_err(|_| RecoveryFailure::Authentication)
    }
    pub fn create_passphrase(
        &self,
        custody: &BootstrapKeyCustody,
        pin: RecoveryIdentity,
        protected_integrity: &[u8],
        passphrase: &RecoveryPassphrase,
        created: u64,
    ) -> Result<Vec<u8>, RecoveryFailure> {
        if self.mode != RecoveryProtection::Passphrase {
            return Err(RecoveryFailure::InvalidInput);
        }
        let payload = self.payload(
            custody,
            pin,
            protected_integrity,
            &["scrypt".to_owned()],
            created,
        )?;
        RustCryptoBackend
            .seal_recovery(
                RecoveryCryptoPurpose::LocalRootPayloadV1,
                RecoveryEncryption::Passphrase(&passphrase.0),
                &payload,
            )
            .map_err(|_| RecoveryFailure::Authentication)
    }
    fn payload(
        &self,
        custody: &BootstrapKeyCustody,
        pin: RecoveryIdentity,
        protected_integrity: &[u8],
        recipients: &[String],
        created: u64,
    ) -> Result<Zeroizing<Vec<u8>>, RecoveryFailure> {
        if custody
            .active_root_identity()
            .map_err(|_| RecoveryFailure::Authentication)?
            != pin.root
            || created == 0
        {
            return Err(RecoveryFailure::Authentication);
        }
        let seed = custody
            .open_object(
                pin.instance,
                super::BootstrapObjectPurpose::Initialized,
                protected_integrity,
            )
            .map_err(|_| RecoveryFailure::Authentication)?;
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| RecoveryFailure::Authentication)?,
        );
        if custody
            .integrity_identity(&seed)
            .map_err(|_| RecoveryFailure::Authentication)?
            != pin.integrity
        {
            return Err(RecoveryFailure::Authentication);
        }
        let metadata = RecoveryMetadata {
            payload_version: if custody.has_system_route() { 2 } else { 1 },
            identity: pin,
            created,
            recipients: recipients.to_vec(),
        };
        let envelope = if custody.has_system_route() {
            Some(
                super::root_rewrap::wrap_system(custody, pin.instance)
                    .map_err(|_| RecoveryFailure::Authentication)?,
            )
        } else {
            None
        };
        let epoch = custody
            .active_root_epoch()
            .map_err(|_| RecoveryFailure::Authentication)?;
        let system = envelope
            .as_deref()
            .map(|value| (custody.bootstrap_identity(), epoch, value));
        let payload = custody
            .with_root_key(|root| match system {
                Some(system) => {
                    encode_with_system(&metadata, root.expose_to_backend(), Some(system))
                },
                None => encode(&metadata, root.expose_to_backend()),
            })
            .map_err(|_| RecoveryFailure::Authentication)?;
        signed(&payload, &seed)
    }
    /// Recovers into opaque custody, validates the complete owning instance, then exclusively publishes its root.
    pub fn import(
        &self,
        ciphertext: &[u8],
        unlock: RecoveryUnlock<'_>,
        pin: RecoveryIdentity,
        access: &crate::BootstrapArtifactAccess,
        validate: impl FnOnce(&BootstrapKeyCustody) -> Result<(), RecoveryFailure>,
    ) -> Result<BootstrapKeyCustody, RecoveryFailure> {
        let (_, custody) = self.recover(ciphertext, unlock, pin)?;
        access
            .require_recovery_target_absent(&custody)
            .map_err(|_| RecoveryFailure::AlreadyExists)?;
        validate(&custody)?;
        access
            .publish_recovered_key(&custody)
            .map_err(|_| RecoveryFailure::Custody)?;
        Ok(custody)
    }
    pub fn inspect(
        &self,
        ciphertext: &[u8],
        unlock: RecoveryUnlock<'_>,
        pin: RecoveryIdentity,
    ) -> Result<RecoveryMetadata, RecoveryFailure> {
        self.recover(ciphertext, unlock, pin)
            .map(|(metadata, _)| metadata)
    }
    pub fn verify(
        &self,
        custody: &BootstrapKeyCustody,
        ciphertext: &[u8],
        unlock: RecoveryUnlock<'_>,
        pin: RecoveryIdentity,
    ) -> Result<RecoveryMetadata, RecoveryFailure> {
        if custody
            .active_root_identity()
            .map_err(|_| RecoveryFailure::Authentication)?
            != pin.root
        {
            return Err(RecoveryFailure::Authentication);
        }
        let (metadata, recovered) = self.recover(ciphertext, unlock, pin)?;
        use subtle::ConstantTimeEq;
        let equal = custody
            .with_root_key(|root| {
                recovered.with_root_key(|other| {
                    bool::from(root.expose_to_backend().ct_eq(other.expose_to_backend()))
                })
            })
            .map_err(|_| RecoveryFailure::Custody)?
            .map_err(|_| RecoveryFailure::Custody)?;
        if !equal {
            return Err(RecoveryFailure::Authentication);
        }
        Ok(metadata)
    }
    fn recover(
        &self,
        ciphertext: &[u8],
        unlock: RecoveryUnlock<'_>,
        pin: RecoveryIdentity,
    ) -> Result<(RecoveryMetadata, BootstrapKeyCustody), RecoveryFailure> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_BUNDLE {
            return Err(RecoveryFailure::LimitExceeded);
        }
        let purpose = RecoveryCryptoPurpose::LocalRootPayloadV1;
        let plaintext = match unlock {
            RecoveryUnlock::IdentityFile(path) if self.mode == RecoveryProtection::Recipients => {
                let identity = files::read_identity(path)?;
                RustCryptoBackend.open_recovery(
                    purpose,
                    RecoveryDecryption::Identity(&identity),
                    ciphertext,
                )
            },
            RecoveryUnlock::Identity(identity) if self.mode == RecoveryProtection::Recipients => {
                RustCryptoBackend.open_recovery(
                    purpose,
                    RecoveryDecryption::Identity(identity),
                    ciphertext,
                )
            },
            RecoveryUnlock::Passphrase(passphrase)
                if self.mode == RecoveryProtection::Passphrase =>
            {
                RustCryptoBackend.open_recovery(
                    purpose,
                    RecoveryDecryption::Passphrase(&mut || Ok(passphrase.0.clone())),
                    ciphertext,
                )
            },
            RecoveryUnlock::InteractivePassphrase(read)
                if self.mode == RecoveryProtection::Passphrase =>
            {
                // Preserve the operator-input failure without exposing its secret to the backend.
                let mut input_failure = None;
                let result = RustCryptoBackend.open_recovery(
                    purpose,
                    RecoveryDecryption::Passphrase(&mut || match read() {
                        Ok(passphrase) => Ok(passphrase.0),
                        Err(failure) => {
                            input_failure = Some(failure);
                            Err(CryptoBackendFailure::InvalidKey)
                        },
                    }),
                    ciphertext,
                );
                if let Some(failure) = input_failure {
                    return Err(failure);
                }
                result
            },
            _ => return Err(RecoveryFailure::InvalidInput),
        }
        .map_err(|failure| match failure {
            CryptoBackendFailure::InvalidKey => RecoveryFailure::InvalidInput,
            CryptoBackendFailure::RecoveryLimitExceeded => RecoveryFailure::LimitExceeded,
            _ => RecoveryFailure::Authentication,
        })?;
        let payload = verify_signed(&plaintext, pin.integrity)?;
        decode(payload, pin)
    }
}
