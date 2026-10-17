//! A permanent nonsecret value occupying the former tenant envelope object name.
use super::*;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantKeyPurgeFence {
    object: ObjectId,
    tombstone: BackupPurgeTombstone,
    bytes: Vec<u8>,
}
impl TenantKeyPurgeFence {
    pub const MAX_BYTES: usize = 428;
    pub fn new(
        object: ObjectId,
        tombstone: &BackupPurgeTombstone,
        repository: &RepositoryIdentity,
        signer: &BackupControlSigner,
    ) -> Result<Self, RepositoryFailure> {
        let tombstone_bytes = tombstone.signed_bytes(repository, signer)?;
        let mut bytes = b"POSBKF01".to_vec();
        bytes.extend_from_slice(&signer.identity().public_key());
        bytes.extend_from_slice(&object.checksum());
        bytes.extend_from_slice(&(tombstone_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&tombstone_bytes);
        let bytes = super::super::codec::sign(bytes, signer)?;
        Ok(Self {
            object,
            tombstone: tombstone.clone(),
            bytes,
        })
    }
    pub fn verify(
        bytes: &[u8],
        repository: &RepositoryIdentity,
        object: ObjectId,
    ) -> Result<Self, RepositoryFailure> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut header = super::super::codec::Decoder::new(bytes);
        if header.take(8)? != b"POSBKF01" {
            return Err(RepositoryFailure::CorruptState);
        }
        let integrity = BootstrapIntegrityIdentity::from_pinned(
            header.array()?,
            repository.integrity_fingerprint(),
        )
        .map_err(|_| RepositoryFailure::IdentityMismatch)?;
        let mut decoder =
            super::super::codec::Decoder::new(super::super::codec::verify(bytes, integrity)?);
        decoder.take(40)?;
        if decoder.array::<32>()? != object.checksum() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let length = decoder.u32()? as usize;
        let tombstone = BackupPurgeTombstone::verify(decoder.take(length)?, repository, integrity)?;
        decoder.finish()?;
        Ok(Self {
            object,
            tombstone,
            bytes: bytes.to_vec(),
        })
    }
    pub const fn object(&self) -> ObjectId {
        self.object
    }
    pub fn tombstone(&self) -> &BackupPurgeTombstone {
        &self.tombstone
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn is_frame(bytes: &[u8]) -> bool {
        bytes.starts_with(b"POSBKF01")
    }
}
