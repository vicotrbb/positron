use crate::ReleaseError;
use positron_kernel::release_manifest::{ProductVersion, ReleaseCompatibility};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_INVENTORY_BYTES: usize = 1_048_576;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub sha256: [u8; 32],
    pub size: u64,
}
impl FileIdentity {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            sha256: Sha256::digest(bytes).into(),
            size: bytes.len() as u64,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryFile {
    /// One portable filename, never a path or URL.
    pub id: String,
    pub identity: FileIdentity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Surface {
    NativeExecutable,
    NativeArchive,
    Debian,
    Rpm,
    Homebrew,
    Nix,
    OciImage,
    OciIndex,
    Compose,
    Helm,
    Grafana,
    SdkRust,
    SdkTypeScript,
    SdkPython,
    SdkGo,
    SdkJava,
    SdkDotNet,
    Source,
    Api,
    Documentation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub file: String,
    pub surface: Surface,
    pub target: String,
    /// Unsigned functional bytes. Required for reproducible Release 1 payloads.
    pub payload: Option<String>,
    pub spdx: String,
    pub cyclonedx: String,
    pub provenance: String,
    pub license_notices: String,
    pub evidence: String,
    pub publication: Publication,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub registry: String,
    pub immutable_identity: String,
    /// Exact native subject identity, such as a package URL or distribution filename.
    pub native_subject: String,
    /// Distribution repository revision, distinct from the upstream product source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_revision: Option<String>,
    pub state: PublicationState,
    /// Detached receipt filename, deliberately excluded from hashed inventory files.
    pub proof: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PublicationState {
    Staged,
    Published,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInput {
    pub name: String,
    pub version: String,
    pub file: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecuritySupport {
    pub expires_unix: u64,
    /// Signed manifest digests of supported upgrade destinations.
    pub upgrade_paths: Vec<[u8; 32]>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInventory {
    pub format: u32,
    pub version: ProductVersion,
    pub source_commit: String,
    pub build_identity: String,
    pub api_version: String,
    pub compatibility: ReleaseCompatibility,
    pub inputs: Vec<BuildInput>,
    pub files: Vec<InventoryFile>,
    pub artifacts: Vec<Artifact>,
    pub security_support: SecuritySupport,
}
impl ReleaseInventory {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReleaseError> {
        if bytes.len() > MAX_INVENTORY_BYTES {
            return Err(ReleaseError::LimitExceeded);
        }
        let inventory: Self = serde_json::from_slice(bytes).map_err(|_| ReleaseError::Invalid)?;
        inventory.validate()?;
        Ok(inventory)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReleaseError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ReleaseError::Invalid)?;
        if bytes.len() > MAX_INVENTORY_BYTES {
            return Err(ReleaseError::LimitExceeded);
        }
        Ok(bytes)
    }
    pub fn file(&self, id: &str) -> Result<&InventoryFile, ReleaseError> {
        self.files
            .iter()
            .find(|file| file.id == id)
            .ok_or(ReleaseError::PartialSet)
    }
    fn validate(&self) -> Result<(), ReleaseError> {
        if self.format != 1
            || self.api_version != "positron.v1"
            || !token(&self.build_identity)
            || !matches!(self.source_commit.len(), 40 | 64)
            || !self
                .source_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.source_commit.bytes().all(|b| b == b'0')
        {
            return Err(ReleaseError::Invalid);
        }
        if self.files.len() > 1024
            || self.artifacts.len() > 128
            || self.inputs.len() > 64
            || self.security_support.upgrade_paths.len() > 32
        {
            return Err(ReleaseError::LimitExceeded);
        }
        for (index, file) in self.files.iter().enumerate() {
            if !token(&file.id)
                || file.identity.size == 0
                || file.identity.sha256 == [0; 32]
                || self
                    .files
                    .iter()
                    .take(index)
                    .any(|other| other.id == file.id)
            {
                return Err(ReleaseError::Invalid);
            }
        }
        if self.artifacts.is_empty() {
            return Err(ReleaseError::PartialSet);
        }
        for (index, artifact) in self.artifacts.iter().enumerate() {
            if !token(&artifact.target)
                || self.artifacts.iter().take(index).any(|other| {
                    other.file == artifact.file
                        || other.publication.proof == artifact.publication.proof
                        || (other.publication.registry == artifact.publication.registry
                            && other.publication.native_subject
                                == artifact.publication.native_subject)
                })
            {
                return Err(ReleaseError::Invalid);
            }
            for id in [
                &artifact.file,
                &artifact.spdx,
                &artifact.cyclonedx,
                &artifact.provenance,
                &artifact.license_notices,
                &artifact.evidence,
            ] {
                self.file(id)?;
            }
            if !token(&artifact.publication.proof)
                || self
                    .files
                    .iter()
                    .any(|file| file.id == artifact.publication.proof)
            {
                return Err(ReleaseError::Invalid);
            }
            if let Some(payload) = &artifact.payload {
                self.file(payload)?;
            }
        }
        Ok(())
    }
}
pub(crate) fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && value != "."
        && value != ".."
}

/// Every named Release 1 surface is required; deployment optionality does not reduce this set.
pub fn required_release_one() -> &'static [(Surface, &'static str)] {
    use Surface::*;
    &[
        (NativeExecutable, "linux-x86_64"),
        (NativeExecutable, "linux-aarch64"),
        (NativeExecutable, "macos-x86_64"),
        (NativeExecutable, "macos-aarch64"),
        (NativeExecutable, "nix-linux-x86_64"),
        (NativeExecutable, "nix-linux-aarch64"),
        (NativeExecutable, "nix-macos-x86_64"),
        (NativeExecutable, "nix-macos-aarch64"),
        (NativeArchive, "linux-x86_64"),
        (NativeArchive, "linux-aarch64"),
        (NativeArchive, "macos-x86_64"),
        (NativeArchive, "macos-aarch64"),
        (Nix, "linux-x86_64"),
        (Nix, "linux-aarch64"),
        (Nix, "macos-x86_64"),
        (Nix, "macos-aarch64"),
        (Debian, "linux-x86_64"),
        (Debian, "linux-aarch64"),
        (Rpm, "linux-x86_64"),
        (Rpm, "linux-aarch64"),
        (OciImage, "linux-x86_64"),
        (OciImage, "linux-aarch64"),
        (Homebrew, "any"),
        (OciIndex, "any"),
        (Compose, "any"),
        (Helm, "any"),
        (Grafana, "any"),
        (SdkRust, "any"),
        (SdkTypeScript, "any"),
        (SdkPython, "any"),
        (SdkGo, "any"),
        (SdkJava, "any"),
        (SdkDotNet, "any"),
        (Source, "any"),
        (Api, "any"),
        (Documentation, "any"),
    ]
}
impl ReleaseInventory {
    pub fn validate_complete(&self) -> Result<(), ReleaseError> {
        self.validate()?;
        for (surface, target) in required_release_one() {
            if !self
                .artifacts
                .iter()
                .any(|artifact| artifact.surface == *surface && artifact.target == *target)
            {
                return Err(ReleaseError::PartialSet);
            }
        }
        if self.artifacts.iter().any(|artifact| {
            !required_release_one().contains(&(artifact.surface, artifact.target.as_str()))
        }) {
            return Err(ReleaseError::Unsupported);
        }
        for surface in [
            Surface::SdkRust,
            Surface::SdkTypeScript,
            Surface::SdkPython,
            Surface::SdkGo,
            Surface::SdkJava,
            Surface::SdkDotNet,
        ] {
            if !self
                .artifacts
                .iter()
                .any(|artifact| artifact.surface == surface && artifact.payload.is_some())
            {
                return Err(ReleaseError::Unreproducible);
            }
        }
        for name in [
            "rust",
            "linker",
            "protobuf",
            "openapi",
            "sdk",
            "frontend",
            "packaging",
            "documentation",
            "lockfile",
        ] {
            if !self.inputs.iter().any(|input| input.name == name) {
                return Err(ReleaseError::PartialSet);
            }
        }
        for (index, input) in self.inputs.iter().enumerate() {
            if !token(&input.name)
                || !token(&input.version)
                || self
                    .inputs
                    .iter()
                    .take(index)
                    .any(|other| other.name == input.name)
            {
                return Err(ReleaseError::Invalid);
            }
            self.file(&input.file)?;
        }
        for artifact in &self.artifacts {
            use Surface::*;
            if (matches!(
                artifact.surface,
                Api | OciImage | Homebrew | Nix | Compose | Helm
            ) || (artifact.surface == NativeExecutable
                && (artifact.target.starts_with("linux-") || artifact.target.starts_with("nix-"))))
                && artifact.payload.is_none()
            {
                return Err(ReleaseError::Unreproducible);
            }
            let publication = &artifact.publication;
            if publication
                .native_revision
                .as_ref()
                .is_some_and(|revision| {
                    artifact.surface != Surface::Homebrew
                        || revision.len() != 40
                        || !revision
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            {
                return Err(ReleaseError::Invalid);
            }
            if publication.native_subject.is_empty()
                || publication.native_subject.len() > 512
                || publication.native_subject.chars().any(char::is_control)
                || publication.registry.len() > 512
                || !publication.registry.starts_with("https://")
                || publication
                    .registry
                    .bytes()
                    .any(|b| b.is_ascii_control() || b == b'@')
                || publication.registry.contains(['?', '#'])
                || publication.immutable_identity
                    != format!(
                        "sha256:{}",
                        hex(&self.file(&artifact.file)?.identity.sha256)
                    )
            {
                return Err(ReleaseError::IdentityMismatch);
            }
        }
        for artifact in &self.artifacts {
            crate::native_packages::verify_registry_metadata(artifact, self)?;
        }
        crate::native_maven_package::verify_metadata(self)?;
        Ok(())
    }
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
