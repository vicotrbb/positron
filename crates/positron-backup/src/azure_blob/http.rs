use super::{AzureBlobRepository, protocol};
use crate::*;
use google_cloud_auth::native;
use http::{HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
pub(super) struct Metadata {
    pub size: u64,
    pub etag: String,
    pub md5: String,
    pub protection: ObjectProtection,
}
impl AzureBlobRepository {
    pub(super) fn key(&self, name: &str) -> String {
        format!("{}{name}", self.target.prefix())
    }
    pub(super) fn url(&self, key: &str) -> String {
        format!(
            "https://{}.blob.core.windows.net/{}/{}",
            self.target.account(),
            self.target.container(),
            key
        )
    }
    pub(super) async fn request(
        &self,
        method: Method,
        url: String,
        mut headers: HeaderMap,
        body: Vec<u8>,
        maximum: usize,
    ) -> Result<native::Response, RepositoryFailure> {
        headers.insert("x-ms-version", HeaderValue::from_static("2023-11-03"));
        let date = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc2822)
            .map_err(|_| RepositoryFailure::StorageUnavailable)?
            .replace("+0000", "GMT");
        headers.insert(
            "x-ms-date",
            HeaderValue::from_str(&date).map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        let mutation = !matches!(method, Method::GET | Method::HEAD);
        let request = native::Request {
            method,
            url,
            headers,
            body: Zeroizing::new(body),
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.runtime.request(request, maximum),
        )
        .await
        .map_err(|_| {
            if mutation {
                RepositoryFailure::OutcomeUnknown
            } else {
                RepositoryFailure::StorageUnavailable
            }
        })?
        .map_err(|e| match e {
            native::Error::LimitExceeded => RepositoryFailure::LimitExceeded,
            native::Error::PermissionDenied => RepositoryFailure::PermissionDenied,
            native::Error::InvalidConfiguration => RepositoryFailure::InvalidInput,
            native::Error::NotFound => RepositoryFailure::NotFound,
            native::Error::Unavailable if mutation => RepositoryFailure::OutcomeUnknown,
            native::Error::Unavailable => RepositoryFailure::StorageUnavailable,
        })
    }
    pub(super) async fn checked(
        &self,
        method: Method,
        url: String,
        headers: HeaderMap,
        body: Vec<u8>,
        maximum: usize,
    ) -> Result<native::Response, RepositoryFailure> {
        let mutation = !matches!(method, Method::GET | Method::HEAD);
        let reply = self.request(method, url, headers, body, maximum).await?;
        if !reply.status.is_success() {
            return Err(protocol::failure(&reply, mutation));
        }
        Ok(reply)
    }
    pub(super) fn condition(expected: Option<&str>) -> Result<HeaderMap, RepositoryFailure> {
        let mut headers = HeaderMap::new();
        headers.insert(
            if expected.is_some() {
                http::header::IF_MATCH
            } else {
                http::header::IF_NONE_MATCH
            },
            HeaderValue::from_str(expected.unwrap_or("*"))
                .map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        Ok(headers)
    }
    pub(super) async fn metadata(
        &self,
        key: &str,
        selector: &str,
    ) -> Result<Metadata, RepositoryFailure> {
        let reply = self
            .checked(
                Method::HEAD,
                format!("{}{selector}", self.url(key)),
                HeaderMap::new(),
                Vec::new(),
                0,
            )
            .await?;
        Ok(Metadata {
            size: protocol::header(&reply.headers, "content-length")?
                .parse()
                .map_err(|_| RepositoryFailure::CorruptState)?,
            etag: protocol::etag(&reply.headers)?,
            md5: protocol::header(&reply.headers, "content-md5")?.into(),
            protection: protocol::protection(&reply.headers)?,
        })
    }
    pub(super) async fn read_key(
        &self,
        key: &str,
        selector: &str,
        maximum: usize,
    ) -> Result<(Vec<u8>, Metadata), RepositoryFailure> {
        let meta = self.metadata(key, selector).await?;
        if meta.size > maximum as u64 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::IF_MATCH,
            HeaderValue::from_str(&meta.etag).map_err(|_| RepositoryFailure::CorruptState)?,
        );
        let reply = self
            .checked(
                Method::GET,
                format!("{}{selector}", self.url(key)),
                headers,
                Vec::new(),
                maximum,
            )
            .await?;
        if protocol::etag(&reply.headers)? != meta.etag
            || reply.body.len() as u64 != meta.size
            || protocol::md5(&reply.body) != meta.md5
        {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok((reply.body.to_vec(), meta))
    }
    pub(super) async fn write_key(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected: Option<&str>,
    ) -> Result<String, RepositoryFailure> {
        let mut headers = Self::condition(expected)?;
        headers.insert("x-ms-blob-type", HeaderValue::from_static("BlockBlob"));
        headers.insert(
            "content-md5",
            HeaderValue::from_str(&protocol::md5(&bytes))
                .map_err(|_| RepositoryFailure::InvalidInput)?,
        );
        let reply = self
            .checked(Method::PUT, self.url(key), headers, bytes, 131072)
            .await?;
        protocol::etag(&reply.headers)
    }
    pub(super) fn check_purge_fence(
        &self,
        id: ObjectId,
        bytes: &[u8],
    ) -> Result<(), RepositoryFailure> {
        if <[u8; 32]>::from(Sha256::digest(bytes)) != id.checksum()
            && TenantKeyPurgeFence::is_frame(bytes)
        {
            TenantKeyPurgeFence::verify(bytes, &self.identity, id)
                .map_err(|_| RepositoryFailure::CorruptState)?;
            return Err(RepositoryFailure::NotFound);
        }
        Ok(())
    }
    pub(super) async fn read_object(
        &self,
        id: ObjectId,
    ) -> Result<(Vec<u8>, Metadata), RepositoryFailure> {
        let value = self
            .read_key(&self.key(&id.name()), "", MAX_OBJECT_BYTES as usize)
            .await?;
        self.check_purge_fence(id, &value.0)?;
        if <[u8; 32]>::from(Sha256::digest(&value.0)) != id.checksum() {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        Ok(value)
    }
    pub(super) async fn read_identity(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        self.container().await?;
        let (bytes, _) = self.read_key(&self.key("identity"), "", 108).await?;
        let identity = RepositoryIdentity::decode(&bytes)?;
        if identity != self.identity {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        Ok(identity)
    }
    pub(super) async fn container(&self) -> Result<HeaderMap, RepositoryFailure> {
        let account = self
            .checked(
                Method::GET,
                format!("{}?restype=account&comp=properties", self.url("")),
                HeaderMap::new(),
                Vec::new(),
                0,
            )
            .await?;
        if protocol::header(&account.headers, "x-ms-account-kind")? != "StorageV2"
            || protocol::header(&account.headers, "x-ms-is-hns-enabled")? != "false"
        {
            return Err(RepositoryFailure::InvalidInput);
        }

        let reply = self
            .checked(
                Method::HEAD,
                format!("{}?restype=container", self.url("")),
                HeaderMap::new(),
                Vec::new(),
                0,
            )
            .await?;
        Ok(reply.headers)
    }
    pub async fn attach(&self) -> Result<RepositoryIdentity, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await
    }
    pub async fn initialize(&self) -> Result<(), RepositoryFailure> {
        self.upload_authenticator()?;
        let _guard = self.enter()?;
        match self.read_identity().await {
            Ok(_) => return Ok(()),
            Err(RepositoryFailure::NotFound) => {},
            Err(e) => return Err(e),
        }
        let page = self.inventory(self.target.prefix(), None, 1, true).await?;
        if !page.items.is_empty() {
            return Err(RepositoryFailure::ForeignPrefix);
        }
        if page.next.is_some() {
            return Err(RepositoryFailure::OutcomeUnknown);
        }
        match self
            .write_key(&self.key("identity"), self.identity.encode(), None)
            .await
        {
            Ok(_)
            | Err(RepositoryFailure::PreconditionFailed | RepositoryFailure::OutcomeUnknown) => {},
            Err(e) => return Err(e),
        }
        self.read_identity().await.map(|_| ()).map_err(|e| {
            if e == RepositoryFailure::NotFound {
                RepositoryFailure::OutcomeUnknown
            } else {
                e
            }
        })
    }
}

impl AzureBlobRepository {
    pub(super) async fn verify_control_inventory(
        &self,
        allowed: &[crate::ObjectId],
        head: &[u8],
    ) -> Result<(), RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        let mut inventory = crate::control_inventory::ControlInventory::new(allowed)?;
        let page = self.inventory(self.target.prefix(), None, 4, true).await?;
        if page.next.is_some() {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        for item in &page.items {
            if item.deleted {
                return Err(RepositoryFailure::PreconditionFailed);
            }
            let name = item
                .name
                .strip_prefix(self.target.prefix())
                .ok_or(RepositoryFailure::PreconditionFailed)?;
            inventory.observe(name)?;
            // Prefix inventory can merge a committed blob with unfinished
            // blocks under that same name. Those blocks are also reachable.
            let blocks = self
                .checked(
                    Method::GET,
                    format!("{}?comp=blocklist&blocklisttype=all", self.url(&item.name)),
                    HeaderMap::new(),
                    Vec::new(),
                    131072,
                )
                .await?;
            let blocks = protocol::xml(&blocks.body)?;
            if blocks.name != "BlockList"
                || blocks
                    .child("UncommittedBlocks")?
                    .is_none_or(|group| !group.children.is_empty())
                || blocks.children.iter().any(|group| {
                    !matches!(group.name.as_str(), "CommittedBlocks" | "UncommittedBlocks")
                        || group.name == "UncommittedBlocks" && !group.children.is_empty()
                })
            {
                return Err(RepositoryFailure::PreconditionFailed);
            }
        }
        inventory.finish()?;
        for id in allowed {
            if inventory.has_object(*id) {
                self.read_object(*id).await?;
            }
        }
        let actual = self
            .read_head(crate::HeadSlot::registry())
            .await?
            .map(|(head, _)| head);
        if actual.as_ref().is_some_and(|value| value.bytes() != head)
            || inventory.has_head() && actual.is_none()
        {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        Ok(())
    }
}
