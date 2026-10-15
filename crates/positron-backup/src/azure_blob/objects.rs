use super::{AzureBlobRepository, protocol};
use crate::*;
use http::{HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
impl AzureBlobRepository {
    pub async fn put_if_absent(
        &self,
        object: ImmutableObject,
    ) -> Result<PutOutcome, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        let id = object.id();
        match self
            .write_key(&self.key(&id.name()), object.bytes().to_vec(), None)
            .await
        {
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
        let meta = self.metadata(&key, "").await?;
        if meta.size > MAX_OBJECT_BYTES
            || range
                .offset
                .checked_add(range.length)
                .is_none_or(|end| end > meta.size)
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
            http::header::IF_MATCH,
            HeaderValue::from_str(&meta.etag).map_err(|_| RepositoryFailure::CorruptState)?,
        );
        headers.insert(
            http::header::RANGE,
            HeaderValue::from_str(&format!("bytes={}-{end}", range.offset))
                .map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        headers.insert(
            "x-ms-range-get-content-md5",
            HeaderValue::from_static("true"),
        );
        let reply = self
            .checked(
                Method::GET,
                self.url(&key),
                headers,
                Vec::new(),
                range.length as usize,
            )
            .await?;
        if reply.status.as_u16() != 206
            || protocol::header(&reply.headers, "content-range")?
                != format!("bytes {}-{end}/{}", range.offset, meta.size)
            || protocol::etag(&reply.headers)? != meta.etag
            || reply.body.len() as u64 != range.length
        {
            return Err(RepositoryFailure::CorruptState);
        }
        if protocol::md5(&reply.body) != protocol::header(&reply.headers, "content-md5")? {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(ChecksummedBytes {
            checksum: Sha256::digest(&reply.body).into(),
            bytes: reply.body.to_vec(),
        })
    }
    pub async fn storage_policy(&self) -> Result<RepositoryPolicy, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        let headers = self.container().await?;
        let mut policy = RepositoryPolicy::local();
        if let (Some(immutable), Some(hold)) = (
            headers.get("x-ms-has-immutability-policy"),
            headers.get("x-ms-has-legal-hold"),
        ) {
            let flag = |value: &HeaderValue| match value.to_str() {
                Ok("true") => Ok(true),
                Ok("false") => Ok(false),
                _ => Err(RepositoryFailure::CorruptState),
            };
            policy.object_lock = PolicyObservation::Observed(if flag(immutable)? || flag(hold)? {
                ObjectLockPolicy::Enabled {
                    default_retention: None,
                }
            } else {
                ObjectLockPolicy::Disabled
            });
        }
        let service_url = format!(
            "https://{}.blob.core.windows.net/?restype=service&comp=properties",
            self.target.account()
        );
        policy.soft_delete = Some(
            match self
                .checked(
                    Method::GET,
                    service_url,
                    HeaderMap::new(),
                    Vec::new(),
                    131072,
                )
                .await
            {
                Ok(reply) => {
                    let root = protocol::xml(&reply.body)?;
                    if root.name != "StorageServiceProperties" {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    match root.child("DeleteRetentionPolicy")? {
                        None => PolicyObservation::Unobservable,
                        Some(retention) => {
                            let enabled = &retention.required("Enabled")?.text;
                            PolicyObservation::Observed(match enabled.as_str() {
                                "false" => 0,
                                "true" => {
                                    let days = retention
                                        .required("Days")?
                                        .text
                                        .parse::<u64>()
                                        .map_err(|_| RepositoryFailure::CorruptState)?;
                                    if days == 0 || days > 365 {
                                        return Err(RepositoryFailure::CorruptState);
                                    }
                                    days * 86400
                                },
                                _ => return Err(RepositoryFailure::CorruptState),
                            })
                        },
                    }
                },
                Err(failure) => PolicyObservation::Unavailable(failure),
            },
        );
        Ok(policy)
    }
}
