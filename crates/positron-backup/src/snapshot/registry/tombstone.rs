//! Permanent signed tenant identities applied before restore visibility.
use super::*;
use positron_domain::identity::{TenantId, TenantSlug};
pub(super) const MAX_TOMBSTONES: usize = 4096;
pub(super) const MAX_SIGNED_BYTES: usize = 288;

/// An authenticated purge intent, not a claim that managed key destruction finished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupPurgeTombstone {
    tenant: [u8; 16],
    slug: TenantSlug,
    operation: [u8; 16],
    created: u64,
}
impl BackupPurgeTombstone {
    pub fn new(
        tenant: [u8; 16],
        slug: &str,
        operation: [u8; 16],
        created: u64,
    ) -> Result<Self, RepositoryFailure> {
        TenantId::from_bytes(tenant).map_err(|_| RepositoryFailure::InvalidInput)?;
        let slug =
            TenantSlug::parse_canonical(slug).map_err(|_| RepositoryFailure::InvalidInput)?;
        if operation == [0; 16] || created == 0 {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            tenant,
            slug,
            operation,
            created,
        })
    }
    pub const fn tenant(&self) -> [u8; 16] {
        self.tenant
    }
    pub fn slug(&self) -> &str {
        self.slug.as_str()
    }
    pub const fn operation(&self) -> [u8; 16] {
        self.operation
    }
    pub const fn created_at(&self) -> u64 {
        self.created
    }
    pub fn signed_bytes(
        &self,
        repository: &RepositoryIdentity,
        signer: &BackupControlSigner,
    ) -> Result<Vec<u8>, RepositoryFailure> {
        if repository.integrity_fingerprint() != signer.identity().fingerprint() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let mut bytes = b"POSBPT01".to_vec();
        bytes.extend_from_slice(&repository.encode());
        bytes.extend_from_slice(&self.tenant);
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.created.to_be_bytes());
        bytes.push(self.slug.as_str().len() as u8);
        bytes.extend_from_slice(self.slug.as_str().as_bytes());
        super::super::codec::sign(bytes, signer)
    }
    pub fn verify(
        bytes: &[u8],
        repository: &RepositoryIdentity,
        integrity: BootstrapIntegrityIdentity,
    ) -> Result<Self, RepositoryFailure> {
        if bytes.len() > MAX_SIGNED_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if repository.integrity_fingerprint() != integrity.fingerprint() {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let mut decoder =
            super::super::codec::Decoder::new(super::super::codec::verify(bytes, integrity)?);
        if decoder.take(8)? != b"POSBPT01"
            || RepositoryIdentity::decode(decoder.take(108)?)? != *repository
        {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let tenant = decoder.array()?;
        let operation = decoder.array()?;
        let created = decoder.u64()?;
        let length = usize::from(
            *decoder
                .take(1)?
                .first()
                .ok_or(RepositoryFailure::CorruptState)?,
        );
        let slug = std::str::from_utf8(decoder.take(length)?)
            .map_err(|_| RepositoryFailure::CorruptState)?;
        let value = Self::new(tenant, slug, operation, created)?;
        decoder.finish()?;
        Ok(value)
    }
}
impl BackupPublisher<'_> {
    /// Publishes the tombstone before destructive purge work. Existing envelope
    /// reachability remains the purge handler's responsibility until completion.
    pub async fn record_purge_tombstone(
        &self,
        tombstone: &BackupPurgeTombstone,
    ) -> Result<[u8; 32], RepositoryFailure> {
        self.require_identity().await?;
        let (version, current, id) = self.current().await?;
        let mut successor = current.unwrap_or(Generation {
            number: 0,
            previous: [0; 32],
            repository: self.identity.clone(),
            snapshots: Vec::new(),
            reservations: Vec::new(),
            claims: Vec::new(),
            keys: Vec::new(),
            overlays: Vec::new(),
            tombstones: Vec::new(),
        });
        if let Some(existing) = successor
            .tombstones
            .iter()
            .find(|existing| existing.tenant == tombstone.tenant || existing.slug == tombstone.slug)
        {
            return if existing == tombstone {
                id.ok_or(RepositoryFailure::CorruptState)
            } else {
                Err(RepositoryFailure::PreconditionFailed)
            };
        }
        if successor.tombstones.len() >= MAX_TOMBSTONES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        successor
            .tombstones
            .try_reserve_exact(1)
            .map_err(|_| RepositoryFailure::LimitExceeded)?;
        successor.tombstones.push(tombstone.clone());
        successor
            .tombstones
            .sort_by_key(BackupPurgeTombstone::tenant);
        successor.number = successor
            .number
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        successor.previous = id.unwrap_or([0; 32]);
        let checksum = Sha256::digest(successor.signed_bytes(self.signer)?).into();
        self.publish_generation(version, &successor).await?;
        Ok(checksum)
    }
    /// Removes every reachable tenant KEK envelope, including historical provider
    /// versions. Callers must drain tenant key uploads before entering this
    /// irreversible workflow. An error leaves the signed exclusion in force and
    /// must keep the tenant purge pending. System-root overlays remain available
    /// for other tenants; they contain no tenant KEK envelope.
    pub async fn purge_tenant(
        &self,
        tombstone: &BackupPurgeTombstone,
    ) -> Result<[u8; 32], RepositoryFailure> {
        let request = Sha256::digest(tombstone.signed_bytes(self.identity, self.signer)?).into();
        let mut state = self
            .begin_tenant_purge(tombstone, tombstone.operation(), request)
            .await?;
        while !self.tenant_purge_step(&mut state).await? {}
        state
            .registry_generation()
            .ok_or(RepositoryFailure::CorruptState)
    }

    /// Reads only the authoritative head's permanent purge inventory.
    pub async fn purge_tombstones(&self) -> Result<Vec<BackupPurgeTombstone>, RepositoryFailure> {
        self.require_identity().await?;
        let (head, generation, _) = self.current().await?;
        let tombstones = generation.map_or_else(Vec::new, |generation| generation.tombstones);
        if self
            .repository
            .registry_head_at(HeadSlot::registry())
            .await?
            .map(|value| value.version())
            != head
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(tombstones)
    }
}
