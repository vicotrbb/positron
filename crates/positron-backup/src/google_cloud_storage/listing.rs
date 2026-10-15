use super::{GoogleCloudStorageRepository, protocol};
use crate::*;
use http::{HeaderMap, Method};
pub(super) struct Inventory {
    pub items: Vec<serde_json::Value>,
    pub next: Option<String>,
}
impl GoogleCloudStorageRepository {
    pub(super) async fn inventory(
        &self,
        prefix: &str,
        token: Option<&str>,
        limit: u16,
        versions: bool,
        soft: bool,
    ) -> Result<Inventory, RepositoryFailure> {
        let mut url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o?prefix={}&maxResults={limit}&versions={versions}&softDeleted={soft}",
            self.target.bucket(),
            protocol::escape(prefix)
        );
        if let Some(token) = token {
            url.push_str(&format!("&pageToken={}", protocol::escape(token)));
        }
        let reply = self
            .checked(Method::GET, url, HeaderMap::new(), Vec::new(), 131072)
            .await?;
        let value = protocol::json(&reply.body)?;
        if value
            .get("prefixes")
            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let items = match value.get("items") {
            None => Vec::new(),
            Some(v) => v.as_array().ok_or(RepositoryFailure::CorruptState)?.clone(),
        };
        if items.len() > usize::from(limit) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        for item in &items {
            if !protocol::string(item, "name")?.starts_with(prefix) {
                return Err(RepositoryFailure::IdentityMismatch);
            }
        }
        let next = match value.get("nextPageToken") {
            None => None,
            Some(_) => Some(protocol::string(&value, "nextPageToken")?.to_owned()),
        };
        if token.is_some() && next.as_deref() == token {
            return Err(RepositoryFailure::CorruptState);
        }
        Ok(Inventory { items, next })
    }
    pub async fn list(&self, request: ListRequest) -> Result<ListPage, RepositoryFailure> {
        let _guard = self.enter()?;
        self.read_identity().await?;
        let token = self
            .listing
            .try_lock()
            .map_err(|_| RepositoryFailure::Busy)?
            .take(self.identity.repository_id(), &request)?;
        let prefix = self.key(match request.kind {
            ListKind::Objects => "o-",
            ListKind::Uploads => "u-",
        });
        let page = self
            .inventory(&prefix, token.as_deref(), request.limit, false, false)
            .await?;
        let mut entries = Vec::with_capacity(page.items.len());
        for item in page.items {
            let suffix = protocol::string(&item, "name")?
                .strip_prefix(&prefix)
                .ok_or(RepositoryFailure::CorruptState)?;
            let checksum = crate::listing::native_cursor::checksum_name(suffix)?;
            entries.push(match request.kind {
                ListKind::Objects => ListEntry::Object(ObjectId::from_checksum(checksum)),
                ListKind::Uploads => ListEntry::Upload(UploadId(checksum)),
            });
        }
        let mut state = self
            .listing
            .try_lock()
            .map_err(|_| RepositoryFailure::Busy)?;
        state.consume(self.identity.repository_id(), &request)?;
        let next = page
            .next
            .map(|token| state.store(self.identity.repository_id(), request.kind, token))
            .transpose()?;
        Ok(ListPage { entries, next })
    }
}
