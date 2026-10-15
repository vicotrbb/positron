use super::{AzureBlobRepository, protocol};
use crate::*;
use http::{HeaderMap, Method};
pub(super) struct Item {
    pub name: String,
    pub selector: String,
    pub deleted: bool,
}
pub(super) struct Inventory {
    pub items: Vec<Item>,
    pub next: Option<String>,
}
impl AzureBlobRepository {
    pub(super) async fn inventory(
        &self,
        prefix: &str,
        marker: Option<&str>,
        limit: u16,
        history: bool,
    ) -> Result<Inventory, RepositoryFailure> {
        let mut url = format!(
            "{}?restype=container&comp=list&prefix={}&maxresults={limit}",
            self.url(""),
            protocol::escape(prefix)
        );
        if history {
            url.push_str(
                "&include=versions%2Csnapshots%2Cdeleted%2Cdeletedwithversions%2Cuncommittedblobs",
            )
        }
        if let Some(marker) = marker {
            url.push_str(&format!("&marker={}", protocol::escape(marker)))
        }
        let reply = self
            .checked(Method::GET, url, HeaderMap::new(), Vec::new(), 131072)
            .await?;
        let root = protocol::xml(&reply.body)?;
        if root.name != "EnumerationResults" {
            return Err(RepositoryFailure::CorruptState);
        }
        let blobs = root.required("Blobs")?;
        if blobs.children.len() > usize::from(limit) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut items = Vec::new();
        for blob in &blobs.children {
            if blob.name != "Blob" {
                return Err(RepositoryFailure::CorruptState);
            }
            let name = blob.required("Name")?.text.clone();
            if !name.starts_with(prefix) || name.len() > 1024 {
                return Err(RepositoryFailure::IdentityMismatch);
            }
            let mut selector = String::new();
            for (field, param) in [("Snapshot", "snapshot"), ("VersionId", "versionid")] {
                if let Some(value) = blob.child(field)?.filter(|n| !n.text.is_empty()) {
                    if !selector.is_empty() || value.text.len() > 256 {
                        return Err(RepositoryFailure::CorruptState);
                    }
                    selector = format!("?{param}={}", protocol::escape(&value.text));
                }
            }
            let deleted = match blob.child("Deleted")?.or(blob.child("HasVersionsOnly")?) {
                None => false,
                Some(value) => match value.text.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(RepositoryFailure::CorruptState),
                },
            };
            items.push(Item {
                name,
                selector,
                deleted,
            });
        }
        let next = root
            .child("NextMarker")?
            .map(|n| n.text.clone())
            .filter(|v| !v.is_empty());
        if next.as_ref().is_some_and(|n| n.len() > 2048)
            || marker.is_some() && next.as_deref() == marker
        {
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
            .inventory(&prefix, token.as_deref(), request.limit, false)
            .await?;
        let mut entries = Vec::with_capacity(page.items.len());
        for item in page.items {
            let suffix = item
                .name
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
