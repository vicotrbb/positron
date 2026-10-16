use super::Record;
use crate::google_cloud_storage::GoogleCloudStorageRepository;
use crate::*;
use sha2::{Digest, Sha256};
impl GoogleCloudStorageRepository {
    pub(super) fn encode_record(&self, record: &Record) -> Result<Vec<u8>, RepositoryFailure> {
        let mut bytes = record.encode(self.target.commitment());
        let digest: [u8; 32] = bytes
            .get(bytes.len() - 32..)
            .and_then(|s| s.try_into().ok())
            .ok_or(RepositoryFailure::CorruptState)?;
        let authentication = self
            .upload_authenticator()?
            .authenticate(digest)
            .map_err(|_| RepositoryFailure::StorageUnavailable)?;
        bytes.extend_from_slice(&authentication.epoch().to_be_bytes());
        bytes.extend_from_slice(&authentication.tag());
        Ok(bytes)
    }
    pub(in crate::google_cloud_storage) fn decode_record(
        &self,
        mut bytes: Vec<u8>,
        id: UploadId,
    ) -> Result<Record, RepositoryFailure> {
        let end = bytes
            .len()
            .checked_sub(40)
            .ok_or(RepositoryFailure::CorruptState)?;
        let epoch = u64::from_be_bytes(
            bytes
                .get(end..end + 8)
                .and_then(|s| s.try_into().ok())
                .ok_or(RepositoryFailure::CorruptState)?,
        );
        let tag = bytes
            .get(end + 8..)
            .and_then(|s| s.try_into().ok())
            .ok_or(RepositoryFailure::CorruptState)?;
        let digest = bytes
            .get(end.checked_sub(32).ok_or(RepositoryFailure::CorruptState)?..end)
            .and_then(|s| s.try_into().ok())
            .ok_or(RepositoryFailure::CorruptState)?;
        let authentication = positron_kernel::ControlTokenAuthentication::new(epoch, tag)
            .map_err(|_| RepositoryFailure::CorruptState)?;
        self.upload_authenticator()?
            .verify(digest, authentication)
            .map_err(|_| RepositoryFailure::ChecksumMismatch)?;
        bytes.truncate(end);
        Record::decode(bytes, self.target.commitment(), id)
    }
    pub(super) async fn read_record(
        &self,
        id: UploadId,
    ) -> Result<Option<(Record, u64)>, RepositoryFailure> {
        match self
            .read_key(
                &self.key(&id.name()),
                None,
                MAX_OBJECT_BYTES as usize + 65536,
            )
            .await
        {
            Ok((bytes, meta)) => Ok(Some((self.decode_record(bytes, id)?, meta.generation))),
            Err(RepositoryFailure::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub(super) async fn write_record(
        &self,
        record: &Record,
        generation: u64,
    ) -> Result<u64, RepositoryFailure> {
        self.write_key(
            &self.key(&record.plan.id().name()),
            self.encode_record(record)?,
            generation,
        )
        .await
        .map(|meta| meta.generation)
    }
    async fn finish(
        &self,
        mut record: Record,
        mut generation: u64,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let id = record.plan.object;
        match self.read_object(id).await {
            Ok((bytes, _)) => {
                if bytes.len() as u64 != record.plan.size {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                drop(bytes);
                drop(record.bytes);
                self.cleanup_upload(record.plan.id()).await?;
                return Ok(PutOutcome::AlreadyPresent);
            },
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        self.native_upload(&mut record, &mut generation).await?;
        let bytes = std::mem::take(&mut record.bytes);
        self.faults.at(
            crate::google_cloud_storage::GoogleCloudStorageFaultPoint::BeforeFinalPublication,
        )?;
        let result = self.write_key(&self.key(&id.name()), bytes, 0).await;
        match result {
            Ok(_) => {},
            Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed) => {
                self.read_object(id).await?;
            },
            Err(e) => return Err(e),
        }
        self.cleanup_upload(record.plan.id()).await?;
        Ok(PutOutcome::Created)
    }
    pub async fn begin_upload(&self, plan: UploadPlan) -> Result<UploadState, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        match self.read_object(plan.object).await {
            Ok((bytes, _)) => {
                if bytes.len() as u64 != plan.size {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
                drop(bytes);
                self.cleanup_upload(plan.id()).await?;
                return Ok(UploadState {
                    plan,
                    written: plan.size,
                    checksum: plan.object.checksum(),
                });
            },
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        if let Some((record, generation)) = self.read_record(plan.id()).await? {
            let state = record.state();
            if state.complete() {
                self.finish(record, generation).await?;
            }
            return Ok(state);
        }
        let mut selector = [0; 16];
        getrandom::fill(&mut selector).map_err(|_| RepositoryFailure::StorageUnavailable)?;
        if selector == [0; 16] {
            return Err(RepositoryFailure::StorageUnavailable);
        }
        let record = Record::new(plan, selector);
        match self.write_record(&record, 0).await {
            Ok(_) => Ok(record.state()),
            Err(RepositoryFailure::OutcomeUnknown | RepositoryFailure::PreconditionFailed) => self
                .read_record(plan.id())
                .await?
                .map(|(r, _)| r.state())
                .ok_or(RepositoryFailure::OutcomeUnknown),
            Err(e) => Err(e),
        }
    }
    pub async fn inspect_upload(
        &self,
        id: UploadId,
    ) -> Result<Option<UploadState>, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        self.read_record(id)
            .await
            .map(|v| v.map(|(r, _)| r.state()))
    }
    pub async fn resume_upload(
        &self,
        part: UploadPart,
    ) -> Result<UploadOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        let Some((mut record, mut generation)) = self.read_record(part.state.id()).await? else {
            let (bytes, _) = self.read_object(part.state.object()).await?;
            if bytes.len() as u64 != part.state.total_size() {
                return Err(RepositoryFailure::ChecksumMismatch);
            }
            return Ok(UploadOutcome::Complete(PutOutcome::AlreadyPresent));
        };
        if record.plan != part.state.plan {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let start = part.state.written as usize;
        let end = start
            .checked_add(part.bytes.len())
            .ok_or(RepositoryFailure::LimitExceeded)?;
        let prefix = record
            .bytes
            .get(..start)
            .ok_or(RepositoryFailure::PreconditionFailed)?;
        if <[u8; 32]>::from(Sha256::digest(prefix)) != part.state.checksum {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        if end <= record.bytes.len() {
            if record.bytes.get(start..end) != Some(part.bytes.as_slice()) {
                return Err(RepositoryFailure::PreconditionFailed);
            }
        } else {
            if start != record.bytes.len() || record.requested {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            record.bytes.reserve_exact(part.bytes.len());
            record.bytes.extend_from_slice(&part.bytes);
            if record.state().complete() && record.state().checksum != record.plan.object.checksum()
            {
                return Err(RepositoryFailure::ChecksumMismatch);
            }
            generation = self.write_record(&record, generation).await?;
        }
        drop(part);
        let state = record.state();
        if state.complete() {
            return self
                .finish(record, generation)
                .await
                .map(UploadOutcome::Complete);
        }
        Ok(UploadOutcome::Pending(state))
    }
    pub async fn abort_upload(&self, id: UploadId) -> Result<DeleteOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        self.cleanup_upload(id).await
    }
}
