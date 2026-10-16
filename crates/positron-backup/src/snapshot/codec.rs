use super::*;
use positron_kernel::BackupControlSignature;
use sha2::{Digest, Sha256};
const MAX_CONTROL_BYTES: usize = 8 * 1024 * 1024;
/// Sign the complete canonical frame's digest so large object inventories stay bounded.
pub(super) fn sign(
    mut bytes: Vec<u8>,
    signer: &BackupControlSigner,
) -> Result<Vec<u8>, RepositoryFailure> {
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let signature = signer
        .sign(&Sha256::digest(&bytes))
        .map_err(|_| RepositoryFailure::CorruptState)?;
    bytes.extend_from_slice(&signature.bytes());
    Ok(bytes)
}
pub(super) fn verify(
    bytes: &[u8],
    identity: BootstrapIntegrityIdentity,
) -> Result<&[u8], RepositoryFailure> {
    if bytes.len() > MAX_CONTROL_BYTES + 64 {
        return Err(RepositoryFailure::LimitExceeded);
    }
    let split = bytes
        .len()
        .checked_sub(64)
        .ok_or(RepositoryFailure::CorruptState)?;
    let (payload, signature) = bytes.split_at(split);
    BackupControlSignature::new(
        identity,
        signature
            .try_into()
            .map_err(|_| RepositoryFailure::CorruptState)?,
    )
    .and_then(|signature| signature.verify(identity, &Sha256::digest(payload)))
    .map_err(|_| RepositoryFailure::CorruptState)?;
    Ok(payload)
}
pub(super) struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], RepositoryFailure> {
        let (field, rest) = self
            .0
            .split_at_checked(n)
            .ok_or(RepositoryFailure::CorruptState)?;
        self.0 = rest;
        Ok(field)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], RepositoryFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| RepositoryFailure::CorruptState)
    }
    pub(super) fn u64(&mut self) -> Result<u64, RepositoryFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, RepositoryFailure> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(super) fn finish(self) -> Result<(), RepositoryFailure> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(RepositoryFailure::CorruptState)
        }
    }
}
impl BackupManifest {
    pub(super) fn encode(&self) -> Result<Vec<u8>, RepositoryFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(256 + 88 * self.objects.len())
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        bytes.extend_from_slice(if self.capture_binding.is_some() {
            b"POSBKM02"
        } else {
            b"POSBKM01"
        });
        bytes.extend_from_slice(&self.snapshot);
        bytes.extend_from_slice(&self.repository.encode());
        bytes.extend_from_slice(&self.catalog_generation.to_be_bytes());
        bytes.extend_from_slice(&self.catalog_identity);
        bytes.extend_from_slice(&self.format_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.audit_frontier.to_be_bytes());
        bytes.extend_from_slice(&self.capture_index);
        if let Some((operation, request)) = self.capture_binding {
            bytes.extend_from_slice(&operation);
            bytes.extend_from_slice(&request);
        }
        bytes.extend_from_slice(&self.created.to_be_bytes());
        bytes.extend_from_slice(&self.retain_until.to_be_bytes());
        bytes.extend_from_slice(&self.key_context);
        bytes.extend_from_slice(&(self.objects.len() as u32).to_be_bytes());
        for object in &self.objects {
            bytes.extend_from_slice(&object.file);
            bytes.extend_from_slice(&object.file_size.to_be_bytes());
            bytes.extend_from_slice(&object.offset.to_be_bytes());
            bytes.extend_from_slice(&object.checksum);
            bytes.extend_from_slice(&object.length.to_be_bytes());
        }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, RepositoryFailure> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.take(8)?;
        if version != b"POSBKM01" && version != b"POSBKM02" {
            return Err(RepositoryFailure::CorruptState);
        }
        let snapshot = decoder.array()?;
        let repository = RepositoryIdentity::decode(decoder.take(108)?)?;
        let generation = decoder.u64()?;
        let catalog = decoder.array()?;
        let epoch = decoder.u32()?;
        let audit = decoder.u64()?;
        let index = decoder.array()?;
        let binding = if version == b"POSBKM02" {
            Some((decoder.array()?, decoder.array()?))
        } else {
            None
        };
        let created = decoder.u64()?;
        let retain = decoder.u64()?;
        let keys = decoder.array()?;
        let count = decoder.u32()? as usize;
        if count > MAX_BACKUP_OBJECTS {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(count)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        for _ in 0..count {
            objects.push(BackupObject::new(
                decoder.array()?,
                decoder.u64()?,
                decoder.u64()?,
                decoder.array()?,
                decoder.u64()?,
            )?);
        }
        decoder.finish()?;
        let mut catalog_identity =
            BackupCatalogIdentity::new(generation, catalog, epoch, audit, index)?;
        if let Some((operation, request)) = binding {
            catalog_identity = catalog_identity.with_capture_binding(operation, request)?;
        }
        Self::new(
            snapshot,
            repository,
            catalog_identity,
            BackupRetention::new(created, retain)?,
            keys,
            objects,
        )
        .map_err(|_| RepositoryFailure::CorruptState)
    }
}
