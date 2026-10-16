use super::AzureBlobRepository;
use crate::*;
use http::{HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
pub(super) enum Proof {
    Object(ObjectId),
    Head(HeadFence),
    Upload(UploadId),
}
pub(super) enum HeadFence {
    Present {
        version: ObjectVersion,
        etag: String,
    },
    Absent {
        expected: ObjectVersion,
    },
}
impl AzureBlobRepository {
    pub(super) fn validate_owned(
        &self,
        bytes: Vec<u8>,
        proof: &Proof,
    ) -> Result<(), RepositoryFailure> {
        match proof {
            Proof::Object(id) => {
                if <[u8; 32]>::from(Sha256::digest(&bytes)) != id.checksum() {
                    return Err(RepositoryFailure::ChecksumMismatch);
                }
            },
            Proof::Head(fence) => {
                let head = RegistryHead::decode_frame(&bytes)?;
                if let HeadFence::Absent { expected } = fence
                    && head.version() != *expected
                {
                    return Err(RepositoryFailure::PreconditionFailed);
                }
            },
            Proof::Upload(id) => {
                self.decode_record(bytes, *id)?;
            },
        }
        Ok(())
    }
    pub(super) async fn purge_key(
        &self,
        key: &str,
        proof: Proof,
    ) -> Result<DeleteOutcome, RepositoryFailure> {
        let mut marker = None;
        let mut items = Vec::new();
        for _ in 0..4 {
            let page = self.inventory(key, marker.as_deref(), 64, true).await?;
            items.extend(page.items.into_iter().filter(|v| v.name == key));
            marker = page.next;
            if marker.is_none() {
                break;
            }
        }
        if marker.is_some() {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if items.iter().any(|v| v.deleted) {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        // Snapshot the owned historical set before any live-head fence. Native ETags
        // prevent a concurrent successor from joining the removal set.
        let current = match self
            .read_key(key, "", MAX_OBJECT_BYTES as usize + 65536)
            .await
        {
            Ok((bytes, meta)) => {
                if let Proof::Head(fence) = &proof {
                    match fence {
                        HeadFence::Absent { .. } => {
                            return Err(RepositoryFailure::PreconditionFailed);
                        },
                        HeadFence::Present { version, etag } => {
                            if &meta.etag != etag
                                || RegistryHead::decode_frame(&bytes)?.version() != *version
                            {
                                return Err(RepositoryFailure::PreconditionFailed);
                            }
                        },
                    }
                }
                self.validate_owned(bytes, &proof)?;
                Some(meta.etag)
            },
            Err(RepositoryFailure::NotFound) => {
                if matches!(&proof, Proof::Head(HeadFence::Present { .. })) {
                    return Err(RepositoryFailure::PreconditionFailed);
                }
                None
            },
            Err(e) => return Err(e),
        };
        let mut existed = false;
        for item in items.iter().filter(|v| !v.selector.is_empty()) {
            let (bytes, meta) = match self
                .read_key(key, &item.selector, MAX_OBJECT_BYTES as usize + 65536)
                .await
            {
                Ok(v) => v,
                Err(RepositoryFailure::NotFound) => continue,
                Err(e) => return Err(e),
            };
            self.validate_owned(bytes, &proof)?;
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::IF_MATCH,
                HeaderValue::from_str(&meta.etag).map_err(|_| RepositoryFailure::CorruptState)?,
            );
            match self
                .checked(
                    Method::DELETE,
                    format!("{}{}", self.url(key), item.selector),
                    headers,
                    Vec::new(),
                    131072,
                )
                .await
            {
                Ok(_) => existed = true,
                Err(RepositoryFailure::NotFound) => {},
                Err(e) => return Err(e),
            }
            match self.metadata(key, &item.selector).await {
                Err(RepositoryFailure::NotFound) => {},
                Ok(_) => return Err(RepositoryFailure::OutcomeUnknown),
                Err(e) => return Err(e),
            }
        }
        if let Some(etag) = current {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::IF_MATCH,
                HeaderValue::from_str(&etag).map_err(|_| RepositoryFailure::CorruptState)?,
            );
            match self
                .checked(Method::DELETE, self.url(key), headers, Vec::new(), 131072)
                .await
            {
                Ok(_) => existed = true,
                Err(RepositoryFailure::NotFound) => {},
                Err(e) => return Err(e),
            }
        }
        match self.metadata(key, "").await {
            Err(RepositoryFailure::NotFound) => {},
            Ok(_) => return Err(RepositoryFailure::PreconditionFailed),
            Err(e) => return Err(e),
        }
        let page = self.inventory(key, None, 64, true).await?;
        if page.next.is_some() || page.items.iter().any(|v| v.name == key) {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        Ok(if existed {
            DeleteOutcome::Deleted
        } else {
            DeleteOutcome::AlreadyAbsent
        })
    }
    pub async fn delete(&self, id: ObjectId) -> Result<DeleteOutcome, RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        self.read_identity().await?;
        self.purge_key(&self.key(&id.name()), Proof::Object(id))
            .await
    }
}
