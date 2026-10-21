//! Root-signed, versioned offline signing-key authorization and revocation.
use crate::ReleaseError;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"positron.release-trust.v1\0";
pub const MAX_TRUST_BYTES: usize = 65_536;
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledProjectTrustRoot {
    pub public_key: [u8; 32],
    /// Independently installed rollback floor, never taken from the bundle.
    pub minimum_sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyPurpose {
    Release,
    /// Authenticate an already installed historical source, never a new target.
    InstalledSource,
    Publisher,
    Transparency,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningIdentity {
    pub public_key: [u8; 32],
    pub purpose: KeyPurpose,
    pub not_before_unix: u64,
    pub expires_unix: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NativePublicationKind {
    GithubActions,
    HomebrewTap,
    PyPi,
    Npm,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKeylessPublisher {
    pub kind: NativePublicationKind,
    pub trusted_root_sha256: [u8; 32],
    pub identity: String,
    pub issuer: String,
    pub repository: String,
    pub source_ref: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NativePublisherPolicy {
    Keyless(NativeKeylessPublisher),
    NugetRepository { trusted_root_sha256: [u8; 32] },
    Maven { trusted_root_sha256: [u8; 32] },
    Rpm { trusted_root_sha256: [u8; 32] },
    GoChecksum { trusted_root_sha256: [u8; 32] },
    CratesIo { repository: String },
    NixCache { key_name: String, key_hint: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePublisher {
    pub registry: String,
    pub policy: NativePublisherPolicy,
}
impl NativePublisherPolicy {
    pub fn trusted_root_sha256(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Keyless(policy) => Some(&policy.trusted_root_sha256),
            Self::NugetRepository {
                trusted_root_sha256,
            }
            | Self::Maven {
                trusted_root_sha256,
            }
            | Self::Rpm {
                trusted_root_sha256,
            }
            | Self::GoChecksum {
                trusted_root_sha256,
            } => Some(trusted_root_sha256),
            Self::CratesIo { .. } | Self::NixCache { .. } => None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustSnapshot {
    pub format: u32,
    pub sequence: u64,
    pub current_version: positron_kernel::release_manifest::ProductVersion,
    pub issued_unix: u64,
    pub expires_unix: u64,
    pub identities: Vec<SigningIdentity>,
    pub native_publishers: Vec<NativePublisher>,
    pub revoked_keys: Vec<[u8; 32]>,
    pub revoked_manifests: Vec<[u8; 32]>,
    pub revoked_artifacts: Vec<[u8; 32]>,
}
#[derive(Clone, Debug)]
pub struct VerifiedTrust {
    snapshot: TrustSnapshot,
    now: u64,
}
impl TrustSnapshot {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReleaseError> {
        decode(bytes, MAX_TRUST_BYTES)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReleaseError> {
        if self.format != 1
            || self.sequence == 0
            || self.issued_unix >= self.expires_unix
            || self.expires_unix - self.issued_unix > 2_592_000
            || self.identities.is_empty()
            || self.identities.len() > 64
            || self.native_publishers.len() > 64
            || self.revoked_keys.len() > 128
            || self.revoked_manifests.len() > 128
            || self.revoked_artifacts.len() > 512
        {
            return Err(ReleaseError::Invalid);
        }
        for (index, publisher) in self.native_publishers.iter().enumerate() {
            let invalid_text = |value: &str| {
                value.is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            };
            let invalid_policy = match &publisher.policy {
                NativePublisherPolicy::Keyless(policy) => [
                    &policy.identity,
                    &policy.issuer,
                    &policy.repository,
                    &policy.source_ref,
                ]
                .into_iter()
                .any(|value| invalid_text(value)),
                NativePublisherPolicy::CratesIo { repository } => {
                    invalid_text(repository) || repository.split('/').count() != 2
                },
                NativePublisherPolicy::NixCache { key_name, key_hint } => {
                    key_name.is_empty()
                        || key_name.len() > 128
                        || !key_name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
                        || key_hint.len() != 64
                        || !key_hint
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                },
                _ => false,
            };
            if publisher
                .policy
                .trusted_root_sha256()
                .is_some_and(|hash| *hash == [0; 32])
                || invalid_text(&publisher.registry)
                || invalid_policy
                || self
                    .native_publishers
                    .iter()
                    .take(index)
                    .any(|other| other.registry == publisher.registry)
            {
                return Err(ReleaseError::Invalid);
            }
        }
        for (index, identity) in self.identities.iter().enumerate() {
            if identity.public_key == [0; 32]
                || identity.not_before_unix >= identity.expires_unix
                || self.identities.iter().take(index).any(|other| {
                    other.public_key == identity.public_key && other.purpose == identity.purpose
                })
            {
                return Err(ReleaseError::Invalid);
            }
        }
        encode(self, MAX_TRUST_BYTES)
    }
    pub fn signing_message(&self) -> Result<Vec<u8>, ReleaseError> {
        let mut message = DOMAIN.to_vec();
        message.extend(self.canonical_bytes()?);
        Ok(message)
    }
    pub fn sign(&self, pair: &Ed25519KeyPair) -> Result<Vec<u8>, ReleaseError> {
        Ok(sign(DOMAIN, &self.canonical_bytes()?, pair))
    }
}
impl InstalledProjectTrustRoot {
    pub fn verify(&self, bytes: &[u8], now: u64) -> Result<VerifiedTrust, ReleaseError> {
        if self.public_key == [0; 32] || self.minimum_sequence == 0 {
            return Err(ReleaseError::Invalid);
        }
        let payload = authenticate(DOMAIN, bytes, &self.public_key, MAX_TRUST_BYTES)?;
        let snapshot = TrustSnapshot::from_bytes(payload)?;
        if snapshot.canonical_bytes()? != payload {
            return Err(ReleaseError::Invalid);
        }
        if snapshot.sequence < self.minimum_sequence
            || now < snapshot.issued_unix
            || now >= snapshot.expires_unix
        {
            return Err(ReleaseError::StaleTrust);
        }
        Ok(VerifiedTrust { snapshot, now })
    }
}
impl VerifiedTrust {
    pub(crate) fn at_time(&self, now: u64) -> Result<Self, ReleaseError> {
        if now < self.snapshot.issued_unix || now >= self.snapshot.expires_unix {
            return Err(ReleaseError::StaleTrust);
        }
        Ok(Self {
            snapshot: self.snapshot.clone(),
            now,
        })
    }

    pub(crate) fn native_publisher(
        &self,
        registry: &str,
    ) -> Result<&NativePublisher, ReleaseError> {
        self.snapshot
            .native_publishers
            .iter()
            .find(|publisher| publisher.registry == registry)
            .ok_or(ReleaseError::Authentication)
    }
    pub fn sequence(&self) -> u64 {
        self.snapshot.sequence
    }
    pub fn require_supported_version(
        &self,
        version: positron_kernel::release_manifest::ProductVersion,
    ) -> Result<(), ReleaseError> {
        let current = self.snapshot.current_version;
        if version > current
            || version.major != current.major
            || !(version.minor == current.minor
                || version.minor.checked_add(1) == Some(current.minor))
        {
            return Err(ReleaseError::Unsupported);
        }
        Ok(())
    }
    pub(crate) fn authorize_at(
        &self,
        key: &[u8; 32],
        purpose: KeyPurpose,
        at: u64,
    ) -> Result<(), ReleaseError> {
        self.authorize(key, purpose)?;
        if !self.snapshot.identities.iter().any(|identity| {
            identity.public_key == *key
                && identity.purpose == purpose
                && identity.not_before_unix <= at
                && at < identity.expires_unix
        }) {
            return Err(ReleaseError::Authentication);
        }
        Ok(())
    }
    pub(crate) fn authorize(
        &self,
        key: &[u8; 32],
        purpose: KeyPurpose,
    ) -> Result<(), ReleaseError> {
        if self.snapshot.revoked_keys.contains(key) {
            return Err(ReleaseError::Revoked);
        }
        if !self.snapshot.identities.iter().any(|identity| {
            identity.public_key == *key
                && identity.purpose == purpose
                && identity.not_before_unix <= self.now
                && self.now < identity.expires_unix
        }) {
            return Err(ReleaseError::Authentication);
        }
        Ok(())
    }
    pub(crate) fn installed_source_keys(&self) -> Vec<[u8; 32]> {
        let mut keys = Vec::new();
        for identity in &self.snapshot.identities {
            if matches!(
                identity.purpose,
                KeyPurpose::Release | KeyPurpose::InstalledSource
            ) && self
                .authorize(&identity.public_key, identity.purpose)
                .is_ok()
                && !keys.contains(&identity.public_key)
            {
                keys.push(identity.public_key);
            }
        }
        keys
    }
    pub(crate) fn check_manifest(&self, digest: &[u8; 32]) -> Result<(), ReleaseError> {
        if self.snapshot.revoked_manifests.contains(digest) {
            return Err(ReleaseError::Revoked);
        }
        Ok(())
    }
    pub(crate) fn check_artifact(&self, digest: &[u8; 32]) -> Result<(), ReleaseError> {
        if self.snapshot.revoked_artifacts.contains(digest) {
            return Err(ReleaseError::Revoked);
        }
        Ok(())
    }
    pub(crate) fn publisher_key(&self, hint: &str) -> Result<[u8; 32], ReleaseError> {
        let key = self
            .snapshot
            .identities
            .iter()
            .find(|identity| {
                identity.purpose == KeyPurpose::Publisher
                    && crate::publication::key_hint(&identity.public_key) == hint
            })
            .ok_or(ReleaseError::Authentication)?
            .public_key;
        self.authorize(&key, KeyPurpose::Publisher)?;
        Ok(key)
    }
    pub(crate) fn log_key(&self, id: &[u8]) -> Result<[u8; 32], ReleaseError> {
        let key = self
            .snapshot
            .identities
            .iter()
            .find(|identity| {
                identity.purpose == KeyPurpose::Transparency
                    && crate::construction::sha256(&crate::publication::spki(&identity.public_key))
                        .as_slice()
                        == id
            })
            .ok_or(ReleaseError::Authentication)?
            .public_key;
        self.authorize(&key, KeyPurpose::Transparency)?;
        Ok(key)
    }
    pub(crate) fn now(&self) -> u64 {
        self.now
    }
}
pub(crate) fn sign(domain: &[u8], payload: &[u8], pair: &Ed25519KeyPair) -> Vec<u8> {
    let mut message = domain.to_vec();
    message.extend(payload);
    let mut bytes = pair.sign(&message).as_ref().to_vec();
    bytes.extend(payload);
    bytes
}
pub(crate) fn authenticate<'a>(
    domain: &[u8],
    bytes: &'a [u8],
    key: &[u8; 32],
    maximum: usize,
) -> Result<&'a [u8], ReleaseError> {
    if bytes.len() > maximum + 64 {
        return Err(ReleaseError::LimitExceeded);
    }
    let signature = bytes.get(..64).ok_or(ReleaseError::Invalid)?;
    let payload = bytes.get(64..).ok_or(ReleaseError::Invalid)?;
    let mut message = domain.to_vec();
    message.extend(payload);
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&message, signature)
        .map_err(|_| ReleaseError::Authentication)?;
    Ok(payload)
}
pub(crate) fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, ReleaseError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ReleaseError::Invalid)?;
    if bytes.len() > maximum {
        return Err(ReleaseError::LimitExceeded);
    }
    Ok(bytes)
}
pub(crate) fn decode<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
    maximum: usize,
) -> Result<T, ReleaseError> {
    if bytes.len() > maximum {
        return Err(ReleaseError::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| ReleaseError::Invalid)
}

pub const MAX_INSTALLED_TRUST_BYTES: usize = 524_288;
/// Explicitly installed policy. The bundle cannot replace the root, selected signer, or rollback floor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledReleaseTrust {
    pub format: u32,
    pub root: InstalledProjectTrustRoot,
    pub release_signer: [u8; 32],
    pub signed_snapshot: Vec<u8>,
}
impl InstalledReleaseTrust {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReleaseError> {
        let value: Self = decode(bytes, MAX_INSTALLED_TRUST_BYTES)?;
        value.canonical_bytes()?;
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReleaseError> {
        if self.format != 1
            || self.root.public_key == [0; 32]
            || self.root.minimum_sequence == 0
            || self.release_signer == [0; 32]
            || self.signed_snapshot.len() > MAX_TRUST_BYTES + 64
            || self.signed_snapshot.len() < 65
        {
            return Err(ReleaseError::Invalid);
        }
        encode(self, MAX_INSTALLED_TRUST_BYTES)
    }
    pub fn verify(&self, now: u64) -> Result<VerifiedTrust, ReleaseError> {
        self.canonical_bytes()?;
        let trust = self.root.verify(&self.signed_snapshot, now)?;
        trust.authorize(&self.release_signer, KeyPurpose::Release)?;
        Ok(trust)
    }
    pub fn verify_installed_manifest(
        &self,
        bytes: &[u8],
        now: u64,
    ) -> Result<positron_kernel::release_manifest::VerifiedReleaseManifest, ReleaseError> {
        crate::verify_installed_source_manifest(bytes, &self.verify(now)?)
    }
    pub fn verify_manifest(
        &self,
        bytes: &[u8],
        now: u64,
    ) -> Result<positron_kernel::release_manifest::VerifiedReleaseManifest, ReleaseError> {
        crate::verify_manifest(bytes, self.release_signer, &self.verify(now)?)
    }
}
