//! Bounded release identity authenticated by an independently installed Project Trust Root.
//!
//! This upgrade preflight payload binds native executable and release metadata
//! records. Its inventory does not establish publication completeness across the
//! full distribution and SDK matrix; release publication owns that later proof.

use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"positron.release-manifest.v1\0";
pub const MAX_RELEASE_MANIFEST_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}
impl ProductVersion {
    pub fn parse_exact(value: &str) -> Result<Self, ReleaseManifestError> {
        let mut parts = value.split('.');
        let mut next = || {
            let part = parts.next().ok_or(ReleaseManifestError::Invalid)?;
            if part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(ReleaseManifestError::Invalid);
            }
            part.parse().map_err(|_| ReleaseManifestError::Invalid)
        };
        let result = Self {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return Err(ReleaseManifestError::Invalid);
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArtifactRole {
    NativeExecutable,
    Schema,
    CompatibilityManifest,
    Sbom,
    Provenance,
    /// Full distribution inventory authenticated by this canonical manifest.
    ReleaseInventory,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub role: ArtifactRole,
    pub platform: String,
    pub sha256: [u8; 32],
    pub size: u64,
    pub complete: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationEdge {
    pub from: u32,
    pub to: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatCompatibility {
    pub readable_epochs: Vec<u32>,
    pub writable_epoch: u32,
    pub migrations: Vec<MigrationEdge>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCompatibility {
    pub config_schema: u32,
    pub previous_config_schema: Option<u32>,
    pub persistent: FormatCompatibility,
    pub backup: FormatCompatibility,
    pub receiver: [u8; 32],
    pub api: [u8; 32],
    pub query: [u8; 32],
    pub schema: [u8; 32],
    pub crd: [u8; 32],
    pub operator: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub version: ProductVersion,
    pub upgrade_from: Vec<ProductVersion>,
    /// Exact lowercase Git object ID: 40 hex SHA-1 or 64 hex SHA-256.
    pub source_commit: String,
    pub artifacts: Vec<ReleaseArtifact>,
    pub compatibility: ReleaseCompatibility,
}
#[derive(Clone, Copy, Debug)]
pub struct ProjectTrustRoot([u8; 32]);
impl ProjectTrustRoot {
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
}
/// A signature verification key, with no claim that it is a Project Trust Root.
/// Release Trust owns delegated authorization, expiry, and revocation before use.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseSigningPublicKey([u8; 32]);
impl ReleaseSigningPublicKey {
    pub const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }
}
#[derive(Clone, Debug)]
pub struct SignedReleaseManifest {
    manifest: ReleaseManifest,
    signature: [u8; 64],
}
#[derive(Clone, Debug)]
pub struct VerifiedReleaseManifest {
    manifest: ReleaseManifest,
    digest: [u8; 32],
    signed_bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseManifestError {
    Invalid,
    LimitExceeded,
    AuthenticationFailed,
}
impl std::fmt::Display for ReleaseManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "release manifest rejected: {self:?}")
    }
}
impl std::error::Error for ReleaseManifestError {}
impl ReleaseManifest {
    /// Exact domain-separated message for detached Ed25519 signing.
    pub fn signing_message(&self) -> Result<Vec<u8>, ReleaseManifestError> {
        let mut message = DOMAIN.to_vec();
        message.extend(self.canonical_bytes()?);
        Ok(message)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReleaseManifestError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ReleaseManifestError::Invalid)?;
        if bytes.len() > MAX_RELEASE_MANIFEST_BYTES {
            return Err(ReleaseManifestError::LimitExceeded);
        }
        Ok(bytes)
    }
    fn validate(&self) -> Result<(), ReleaseManifestError> {
        if self.upgrade_from.len() > 32 {
            return Err(ReleaseManifestError::LimitExceeded);
        }
        if self
            .upgrade_from
            .iter()
            .enumerate()
            .any(|(index, version)| {
                self.upgrade_from
                    .iter()
                    .take(index)
                    .any(|previous| previous == version)
            })
        {
            return Err(ReleaseManifestError::Invalid);
        }

        if self.artifacts.is_empty() || self.artifacts.len() > 64 {
            return Err(ReleaseManifestError::LimitExceeded);
        }
        for (index, artifact) in self.artifacts.iter().enumerate() {
            if artifact.platform.is_empty()
                || artifact.platform.len() > 64
                || !artifact
                    .platform
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                || artifact.size == 0
                || !artifact.complete
                || artifact.sha256 == [0; 32]
            {
                return Err(ReleaseManifestError::Invalid);
            }
            if self.artifacts.iter().take(index).any(|previous| {
                previous.role == artifact.role && previous.platform == artifact.platform
            }) {
                return Err(ReleaseManifestError::Invalid);
            }
        }
        for role in [
            ArtifactRole::NativeExecutable,
            ArtifactRole::Schema,
            ArtifactRole::CompatibilityManifest,
            ArtifactRole::Sbom,
            ArtifactRole::Provenance,
        ] {
            if !self.artifacts.iter().any(|artifact| artifact.role == role) {
                return Err(ReleaseManifestError::Invalid);
            }
        }
        for format in [&self.compatibility.persistent, &self.compatibility.backup] {
            if format.readable_epochs.len() > 32 || format.migrations.len() > 64 {
                return Err(ReleaseManifestError::LimitExceeded);
            }
            if format.writable_epoch == 0
                || !format.readable_epochs.contains(&format.writable_epoch)
                || format
                    .readable_epochs
                    .iter()
                    .enumerate()
                    .any(|(index, epoch)| {
                        *epoch == 0
                            || format
                                .readable_epochs
                                .iter()
                                .take(index)
                                .any(|other| other == epoch)
                    })
                || format.migrations.iter().enumerate().any(|(index, edge)| {
                    edge.from == 0
                        || edge.to == 0
                        || edge.from == edge.to
                        || format
                            .migrations
                            .iter()
                            .take(index)
                            .any(|other| other == edge)
                })
            {
                return Err(ReleaseManifestError::Invalid);
            }
        }
        if [
            self.compatibility.receiver,
            self.compatibility.api,
            self.compatibility.query,
            self.compatibility.schema,
            self.compatibility.crd,
            self.compatibility.operator,
        ]
        .contains(&[0; 32])
        {
            return Err(ReleaseManifestError::Invalid);
        }
        if !matches!(self.source_commit.len(), 40 | 64)
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.source_commit.bytes().all(|byte| byte == b'0')
            || self.compatibility.config_schema == 0
            || self
                .compatibility
                .previous_config_schema
                .is_some_and(|previous| {
                    previous.checked_add(1) != Some(self.compatibility.config_schema)
                })
        {
            return Err(ReleaseManifestError::Invalid);
        }
        Ok(())
    }
}
impl SignedReleaseManifest {
    pub fn new(
        manifest: ReleaseManifest,
        signature: [u8; 64],
    ) -> Result<Self, ReleaseManifestError> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            signature,
        })
    }
    /// Wire format: 64 signature bytes followed by the exact canonical JSON payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReleaseManifestError> {
        if bytes.len() > MAX_RELEASE_MANIFEST_BYTES + 64 {
            return Err(ReleaseManifestError::LimitExceeded);
        }
        let signature = bytes
            .get(..64)
            .ok_or(ReleaseManifestError::Invalid)?
            .try_into()
            .map_err(|_| ReleaseManifestError::Invalid)?;
        let payload = bytes.get(64..).ok_or(ReleaseManifestError::Invalid)?;
        let manifest: ReleaseManifest =
            serde_json::from_slice(payload).map_err(|_| ReleaseManifestError::Invalid)?;
        if manifest.canonical_bytes()? != payload {
            return Err(ReleaseManifestError::Invalid);
        }
        Self::new(manifest, signature)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, ReleaseManifestError> {
        let mut bytes = self.signature.to_vec();
        bytes.extend(self.manifest.canonical_bytes()?);
        Ok(bytes)
    }
    pub fn verify(
        &self,
        root: &ProjectTrustRoot,
    ) -> Result<VerifiedReleaseManifest, ReleaseManifestError> {
        self.verify_signature(&ReleaseSigningPublicKey::new(root.0))
    }
    /// Verify the canonical signature only. The caller must first authorize this signing identity.
    pub fn verify_signature(
        &self,
        signer: &ReleaseSigningPublicKey,
    ) -> Result<VerifiedReleaseManifest, ReleaseManifestError> {
        let payload = self.manifest.canonical_bytes()?;
        let message = self.manifest.signing_message()?;
        UnparsedPublicKey::new(&ED25519, signer.0)
            .verify(&message, &self.signature)
            .map_err(|_| ReleaseManifestError::AuthenticationFailed)?;
        Ok(VerifiedReleaseManifest {
            manifest: self.manifest.clone(),
            digest: Sha256::digest(&payload).into(),
            signed_bytes: self.to_bytes()?,
        })
    }
}
impl VerifiedReleaseManifest {
    pub fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }
}

#[cfg(test)]
#[path = "release_manifest_tests.rs"]
mod tests;
