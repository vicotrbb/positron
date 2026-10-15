use super::{GoogleCloudStorageRepository, protocol};
use crate::*;
use http::{HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
impl GoogleCloudStorageRepository {
    pub(super) fn key(&self, name: &str) -> String {
        format!("{}{name}", self.target.prefix())
    }
    pub(super) async fn metadata(
        &self,
        key: &str,
        generation: Option<u64>,
    ) -> Result<protocol::Metadata, RepositoryFailure> {
        let mut url = self.object_url(key);
        if let Some(generation) = generation {
            url.push_str(&format!("?generation={generation}"));
        }
        let reply = self
            .checked(Method::GET, url, HeaderMap::new(), Vec::new(), 131072)
            .await?;
        protocol::metadata(&reply.body, key)
    }
    pub(super) async fn read_key(
        &self,
        key: &str,
        generation: Option<u64>,
        maximum: usize,
    ) -> Result<(Vec<u8>, protocol::Metadata), RepositoryFailure> {
        let metadata = self.metadata(key, generation).await?;
        if metadata.size > maximum as u64 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let url = format!(
            "{}?alt=media&generation={}&ifGenerationMatch={}&ifMetagenerationMatch={}",
            self.object_url(key),
            metadata.generation,
            metadata.generation,
            metadata.metageneration
        );
        let mut reply = self
            .checked(Method::GET, url, HeaderMap::new(), Vec::new(), maximum)
            .await?;
        metadata.verify(&reply.body)?;
        Ok((std::mem::take(&mut *reply.body), metadata))
    }
    pub(super) async fn read_object(
        &self,
        id: ObjectId,
    ) -> Result<(Vec<u8>, protocol::Metadata), RepositoryFailure> {
        let result = self
            .read_key(&self.key(&id.name()), None, MAX_OBJECT_BYTES as usize)
            .await?;
        if <[u8; 32]>::from(Sha256::digest(&result.0)) != id.checksum() {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(result)
    }
    pub(super) async fn write_key(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected: u64,
    ) -> Result<protocol::Metadata, RepositoryFailure> {
        let crc = crc32c::crc32c(&bytes);
        let size = bytes.len() as u64;
        let reply = self
            .checked(
                Method::POST,
                self.upload_url(key, expected),
                Self::data_headers(),
                bytes,
                131072,
            )
            .await?;
        let metadata = protocol::metadata(&reply.body, key)?;
        if metadata.size != size || metadata.crc32c != crc {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(metadata)
    }
    pub async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        let id = object.id();
        let result = self
            .write_key(&self.key(&id.name()), object.bytes().to_vec(), 0)
            .await;
        drop(object);
        match result {
            Ok(_) => Ok(PutOutcome::Created),
            Err(RepositoryFailure::PreconditionFailed | RepositoryFailure::OutcomeUnknown) => self
                .read_object(id)
                .await
                .map(|_| PutOutcome::AlreadyPresent)
                .map_err(|e| {
                    if e == RepositoryFailure::NotFound {
                        RepositoryFailure::OutcomeUnknown
                    } else {
                        e
                    }
                }),
            Err(e) => Err(e),
        }
    }
    /// Metadata-only observation; content and version remain untrusted.
    pub async fn object_size_hint(&self, id: ObjectId) -> Result<u64, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        self.metadata(&self.key(&id.name()), None)
            .await
            .map(|metadata| metadata.size)
    }
    pub async fn head(&self, id: ObjectId) -> Result<ObjectMetadata, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        let (_, meta) = self.read_object(id).await?;
        Ok(ObjectMetadata {
            size: meta.size,
            checksum: id.checksum(),
            protection: meta.protection,
        })
    }
    pub async fn read_range(
        &self,
        range: ObjectRange,
    ) -> Result<ChecksummedBytes, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        let key = self.key(&range.object.name());
        let metadata = self.metadata(&key, None).await?;
        if range
            .expected_size
            .is_some_and(|expected| expected != metadata.size)
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        if metadata.size > MAX_OBJECT_BYTES
            || range
                .offset
                .checked_add(range.length)
                .is_none_or(|end| end > metadata.size)
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        if range.length == 0 {
            return Ok(ChecksummedBytes {
                bytes: Vec::new(),
                checksum: Sha256::digest([]).into(),
            });
        }
        let end = range.offset + range.length - 1;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::RANGE,
            HeaderValue::from_str(&format!("bytes={}-{end}", range.offset))
                .map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        let reply = self
            .checked(
                Method::GET,
                format!(
                    "{}?alt=media&generation={}&ifGenerationMatch={}&ifMetagenerationMatch={}",
                    self.object_url(&key),
                    metadata.generation,
                    metadata.generation,
                    metadata.metageneration
                ),
                headers,
                Vec::new(),
                range.length as usize,
            )
            .await?;
        if reply.status.as_u16() != 206 {
            return Err(RepositoryFailure::CorruptState);
        }
        protocol::range(
            reply
                .headers
                .get(http::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            range.offset,
            range.length,
            metadata.size,
            reply.body.len(),
        )?;
        Ok(ChecksummedBytes {
            checksum: Sha256::digest(&reply.body).into(),
            bytes: reply.body.to_vec(),
        })
    }
}
