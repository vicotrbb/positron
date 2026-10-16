use super::{
    AzureBlobRepository,
    deletion::{HeadFence, Proof},
};
use crate::*;
impl AzureBlobRepository {
    async fn read_head(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<(RegistryHead, String)>, RepositoryFailure> {
        match self
            .read_key(&self.key(&slot.name()), "", MAX_REGISTRY_HEAD_BYTES + 40)
            .await
        {
            Ok((bytes, meta)) => Ok(Some((RegistryHead::decode_frame(&bytes)?, meta.etag))),
            Err(RepositoryFailure::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub async fn registry_head_at(
        &self,
        slot: HeadSlot,
    ) -> Result<Option<RegistryHead>, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        self.read_head(slot).await.map(|v| v.map(|(h, _)| h))
    }
    pub async fn compare_and_swap_head_at(
        &self,
        slot: HeadSlot,
        change: RegistryHeadChange,
    ) -> Result<CasOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        let current = self.read_head(slot).await?;
        let version = current.as_ref().map(|(h, _)| h.version());
        if version != change.expected {
            return Ok(CasOutcome::Conflict(version));
        }
        let etag = current.map(|(_, etag)| etag);
        match self
            .write_key(
                &self.key(&slot.name()),
                change.successor.encode_frame(),
                etag.as_deref(),
            )
            .await
        {
            Ok(_) => Ok(CasOutcome::Published(change.successor.version())),
            Err(RepositoryFailure::PreconditionFailed) => Ok(CasOutcome::Conflict(
                self.read_head(slot).await?.map(|(h, _)| h.version()),
            )),
            Err(RepositoryFailure::OutcomeUnknown) => match self.read_head(slot).await? {
                Some((h, _)) if h == change.successor => Ok(CasOutcome::Published(h.version())),
                _ => Err(RepositoryFailure::OutcomeUnknown),
            },
            Err(e) => Err(e),
        }
    }
    pub async fn delete_head_if_version(
        &self,
        slot: HeadSlot,
        expected: ObjectVersion,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        let current = self.read_head(slot).await?;
        if current
            .as_ref()
            .is_some_and(|(head, _)| head.version() != expected)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        self.purge_key(
            &self.key(&slot.name()),
            Proof::Head(match current {
                Some((_, etag)) => HeadFence::Present {
                    version: expected,
                    etag,
                },
                None => HeadFence::Absent { expected },
            }),
        )
        .await
    }
}
