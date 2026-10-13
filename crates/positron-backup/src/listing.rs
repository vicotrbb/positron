use crate::{ObjectId, RepositoryFailure, UploadId};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListKind {
    Objects,
    Uploads,
}
/// Provider-owned pagination state; listing may be stale and is never proof of
/// object absence, registry currency, or purge completion.
#[derive(Clone, Eq, PartialEq)]
pub struct ListCursor(pub(crate) Vec<u8>);
impl std::fmt::Debug for ListCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ListCursor([opaque])")
    }
}
impl ListCursor {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, RepositoryFailure> {
        if bytes.is_empty() || bytes.len() > 256 {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self(bytes))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListRequest {
    pub(crate) kind: ListKind,
    pub(crate) cursor: Option<ListCursor>,
    pub(crate) limit: u16,
}
impl ListRequest {
    pub fn new(
        kind: ListKind,
        cursor: Option<ListCursor>,
        limit: u16,
    ) -> Result<Self, RepositoryFailure> {
        if limit == 0 {
            return Err(RepositoryFailure::InvalidInput);
        }
        if limit > 128 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        Ok(Self {
            kind,
            cursor,
            limit,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListEntry {
    Object(ObjectId),
    Upload(UploadId),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPage {
    pub(crate) entries: Vec<ListEntry>,
    pub(crate) next: Option<ListCursor>,
}
impl ListPage {
    pub fn entries(&self) -> &[ListEntry] {
        &self.entries
    }
    pub fn next_cursor(&self) -> Option<&ListCursor> {
        self.next.as_ref()
    }
}
