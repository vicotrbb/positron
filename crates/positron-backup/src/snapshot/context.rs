//! Private capture context and discoverable managed Repository ownership.
use super::*;
use sha2::{Digest, Sha256};
const MAX_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
/// Exact envelopes and retention captured before online copying begins.
/// Kernel encrypts this checkpoint; it is never an immutable Backup object.
pub struct BackupCaptureContext {
    repository: RepositoryIdentity,
    retention: BackupRetention,
    keys: Vec<BackupKeyEnvelope>,
}
impl BackupCaptureContext {
    /// Heap retained outside the Publisher, including encrypted envelope buffers.
    pub fn retained_memory_bytes(&self) -> Result<u64, RepositoryFailure> {
        let inventory = self
            .keys
            .capacity()
            .checked_mul(std::mem::size_of::<BackupKeyEnvelope>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(RepositoryFailure::LimitExceeded)?;
        self.keys.iter().try_fold(inventory, |bytes, key| {
            bytes
                .checked_add(key.retained_memory_bytes())
                .ok_or(RepositoryFailure::LimitExceeded)
        })
    }

    pub fn new(
        repository: RepositoryIdentity,
        retention: BackupRetention,
        keys: Vec<BackupKeyEnvelope>,
    ) -> Result<Self, RepositoryFailure> {
        BackupPublisher::key_context(&keys)?;
        let context = Self {
            repository,
            retention,
            keys,
        };
        context.encode()?;
        Ok(context)
    }
    pub fn keys(&self) -> &[BackupKeyEnvelope] {
        &self.keys
    }
    pub const fn retention(&self) -> BackupRetention {
        self.retention
    }
    pub fn key_context(&self) -> Result<[u8; 32], RepositoryFailure> {
        BackupPublisher::key_context(&self.keys)
    }
    pub fn encode(&self) -> Result<Vec<u8>, RepositoryFailure> {
        let mut bytes = b"POSBCC01".to_vec();
        bytes.extend_from_slice(&self.repository.encode());
        bytes.extend_from_slice(&self.retention.created.to_be_bytes());
        bytes.extend_from_slice(&self.retention.retain_until.to_be_bytes());
        bytes.extend_from_slice(&(self.keys.len() as u32).to_be_bytes());
        for key in &self.keys {
            let object = key.object()?;
            let needed = bytes
                .len()
                .checked_add(4 + object.bytes().len())
                .ok_or(RepositoryFailure::LimitExceeded)?;
            if needed > MAX_CONTEXT_BYTES {
                return Err(RepositoryFailure::LimitExceeded);
            }
            bytes.extend_from_slice(&(object.bytes().len() as u32).to_be_bytes());
            bytes.extend_from_slice(object.bytes());
        }
        Ok(bytes)
    }
    pub fn decode(
        bytes: &[u8],
        repository: &RepositoryIdentity,
    ) -> Result<Self, RepositoryFailure> {
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut decoder = super::codec::Decoder::new(bytes);
        if decoder.take(8)? != b"POSBCC01" {
            return Err(RepositoryFailure::CorruptState);
        }
        let identity = RepositoryIdentity::decode(decoder.take(108)?)?;
        if identity != *repository {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let retention = BackupRetention::new(decoder.u64()?, decoder.u64()?)?;
        let count = decoder.u32()? as usize;
        if count > 4096 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(count)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for _ in 0..count {
            let length = decoder.u32()? as usize;
            keys.push(BackupKeyEnvelope::decode_object(decoder.take(length)?)?);
        }
        decoder.finish()?;
        Self::new(identity, retention, keys)
    }
}
/// Authenticated Catalog inventory remains after capture cleanup and operation
/// lookup expiry. Credentials are resolved exclusively by native providers.
pub struct BackupRepositoryRegistration {
    identity: RepositoryIdentity,
    locator: String,
    registry: Option<[u8; 32]>,
}
impl BackupRepositoryRegistration {
    pub fn find(
        snapshot: &positron_kernel::CatalogSnapshot,
        instance: [u8; 16],
        repository: [u8; 16],
    ) -> Result<Option<(positron_kernel::CatalogObjectId, Self)>, RepositoryFailure> {
        let mut found = None;
        for address in snapshot.object_identities() {
            let bytes = snapshot
                .object(address)
                .map_err(|_| RepositoryFailure::CorruptState)?
                .ok_or(RepositoryFailure::CorruptState)?;
            let Some(registration) = Self::decode(bytes)? else {
                continue;
            };
            if registration.identity.repository_id() != repository {
                continue;
            }
            if registration.identity.instance_id() != instance {
                return Err(RepositoryFailure::IdentityMismatch);
            }
            if found.is_some() {
                return Err(RepositoryFailure::CorruptState);
            }
            found = Some((address, registration));
        }
        Ok(found)
    }
    pub fn new(identity: RepositoryIdentity, locator: &str) -> Result<Self, RepositoryFailure> {
        let locator = if identity.provider_kind() == "localFilesystem" {
            std::path::Path::new(locator)
                .canonicalize()
                .map_err(|_| RepositoryFailure::StorageUnavailable)?
                .to_str()
                .ok_or(RepositoryFailure::InvalidInput)?
                .to_owned()
        } else {
            locator.to_owned()
        };
        let value = Self {
            identity,
            locator,
            registry: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn binding_identity(&self) -> Result<[u8; 32], RepositoryFailure> {
        let mut bytes = self.encode()?;
        // The initial unanchored Catalog object is the stable accepted binding.
        // Later anchors change its storage address without changing that intent.
        let offset = bytes
            .len()
            .checked_sub(33)
            .ok_or(RepositoryFailure::CorruptState)?;
        bytes
            .get_mut(offset..)
            .ok_or(RepositoryFailure::CorruptState)?
            .fill(0);
        Ok(Sha256::digest(bytes).into())
    }
    pub const fn registry_generation(&self) -> Option<[u8; 32]> {
        self.registry
    }
    pub fn with_registry_generation(
        mut self,
        generation: [u8; 32],
    ) -> Result<Self, RepositoryFailure> {
        if generation == [0; 32] {
            return Err(RepositoryFailure::InvalidInput);
        }
        self.registry = Some(generation);
        Ok(self)
    }
    pub fn identity(&self) -> &RepositoryIdentity {
        &self.identity
    }
    pub fn locator(&self) -> &str {
        &self.locator
    }
    fn validate(&self) -> Result<(), RepositoryFailure> {
        if self.locator.is_empty() || self.locator.len() > 2048 {
            return Err(RepositoryFailure::InvalidInput);
        }
        let commitment = match self.identity.provider_kind() {
            "localFilesystem" => {
                if self.locator.chars().any(char::is_control)
                    || !self.locator.starts_with('/')
                    || self
                        .locator
                        .split('/')
                        .any(|part| matches!(part, "." | ".."))
                {
                    return Err(RepositoryFailure::InvalidInput);
                }
                Sha256::digest(self.locator.as_bytes()).into()
            },
            "awsS3" => {
                let target = crate::AwsS3Target::decode_locator(&self.locator)?;
                if target.encode_locator() != self.locator {
                    return Err(RepositoryFailure::InvalidInput);
                }
                target.commitment()
            },
            "googleCloudStorage" => {
                let target = crate::GoogleCloudStorageTarget::decode_locator(&self.locator)?;
                if target.encode_locator() != self.locator {
                    return Err(RepositoryFailure::InvalidInput);
                }
                target.commitment()
            },
            "azureBlob" => {
                let target = crate::AzureBlobTarget::decode_locator(&self.locator)?;
                if target.encode_locator() != self.locator {
                    return Err(RepositoryFailure::InvalidInput);
                }
                target.commitment()
            },
            _ => return Err(RepositoryFailure::InvalidInput),
        };
        if commitment != self.identity.prefix_commitment() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, RepositoryFailure> {
        self.validate()?;
        let mut bytes = b"POSBPR02".to_vec();
        bytes.extend_from_slice(&self.identity.encode());
        bytes.extend_from_slice(&(self.locator.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.locator.as_bytes());
        bytes.push(u8::from(self.registry.is_some()));
        bytes.extend_from_slice(&self.registry.unwrap_or([0; 32]));
        Ok(bytes)
    }
    pub fn catalog_object(&self) -> Result<positron_kernel::CatalogObject, RepositoryFailure> {
        positron_kernel::CatalogObject::new(self.encode()?)
            .map_err(|_| RepositoryFailure::CorruptState)
    }
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, RepositoryFailure> {
        if !bytes.starts_with(b"POSBPR") {
            return Ok(None);
        }
        if bytes.len() > 2201 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut decoder = super::codec::Decoder::new(bytes);
        if decoder.take(8)? != b"POSBPR02" {
            return Err(RepositoryFailure::CorruptState);
        }
        let identity = RepositoryIdentity::decode(decoder.take(108)?)?;
        let length = decoder.u32()? as usize;
        let locator = std::str::from_utf8(decoder.take(length)?)
            .map_err(|_| RepositoryFailure::CorruptState)?
            .to_owned();
        let flag = decoder.take(1)?;
        let registry = decoder.array::<32>()?;
        let registry = match flag {
            [0] if registry == [0; 32] => None,
            [1] if registry != [0; 32] => Some(registry),
            _ => return Err(RepositoryFailure::CorruptState),
        };
        decoder.finish()?;
        let value = Self {
            identity,
            locator,
            registry,
        };
        value.validate()?;
        Ok(Some(value))
    }
}
