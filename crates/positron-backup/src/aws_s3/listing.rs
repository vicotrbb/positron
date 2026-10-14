use super::{AwsS3Repository, failure};
use crate::{
    ListCursor, ListEntry, ListKind, ListPage, ListRequest, ObjectId, RepositoryFailure, UploadId,
};
use std::time::{Duration, Instant};
use tracing::instrument::WithSubscriber;
struct Lease {
    id: u64,
    kind: ListKind,
    token: String,
    expires: Instant,
}
pub(super) struct State {
    owner: [u8; 16],
    next: u64,
    leases: Vec<Lease>,
}
impl State {
    pub(super) fn new() -> Result<Self, RepositoryFailure> {
        let mut owner = [0; 16];
        getrandom::fill(&mut owner).map_err(|_| RepositoryFailure::StorageUnavailable)?;
        if owner == [0; 16] {
            return Err(RepositoryFailure::StorageUnavailable);
        }
        Ok(Self {
            owner,
            next: 0,
            leases: Vec::new(),
        })
    }
    pub(super) fn take(
        &mut self,
        repository: [u8; 16],
        request: &ListRequest,
    ) -> Result<Option<String>, RepositoryFailure> {
        self.leases.retain(|lease| lease.expires > Instant::now());
        let Some(cursor) = &request.cursor else {
            return Ok(None);
        };
        let kind = match request.kind {
            ListKind::Objects => 1,
            ListKind::Uploads => 2,
        };
        if cursor.bytes().len() != 41
            || cursor.bytes().get(..16) != Some(repository.as_slice())
            || cursor.bytes().get(16..32) != Some(self.owner.as_slice())
            || cursor.bytes().get(40) != Some(&kind)
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        let id = u64::from_be_bytes(
            cursor
                .bytes()
                .get(32..40)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(RepositoryFailure::InvalidInput)?,
        );
        let lease = self
            .leases
            .iter()
            .find(|lease| lease.id == id && lease.kind == request.kind)
            .ok_or(RepositoryFailure::InvalidInput)?;
        Ok(Some(lease.token.clone()))
    }
    pub(super) fn consume(
        &mut self,
        repository: [u8; 16],
        request: &ListRequest,
    ) -> Result<(), RepositoryFailure> {
        self.take(repository, request)?;
        if let Some(cursor) = &request.cursor {
            let id = u64::from_be_bytes(
                cursor
                    .bytes()
                    .get(32..40)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(RepositoryFailure::InvalidInput)?,
            );
            self.leases.retain(|lease| lease.id != id);
        }
        Ok(())
    }
    pub(super) fn store(
        &mut self,
        repository: [u8; 16],
        kind: ListKind,
        token: String,
    ) -> Result<ListCursor, RepositoryFailure> {
        self.leases.retain(|lease| lease.expires > Instant::now());
        if token.is_empty() || token.len() > 4096 || self.leases.len() >= 8 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        let mut cursor = Vec::with_capacity(41);
        cursor.extend_from_slice(&repository);
        cursor.extend_from_slice(&self.owner);
        cursor.extend_from_slice(&self.next.to_be_bytes());
        cursor.push(match kind {
            ListKind::Objects => 1,
            ListKind::Uploads => 2,
        });
        self.leases.push(Lease {
            id: self.next,
            kind,
            token,
            expires: Instant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or(RepositoryFailure::LimitExceeded)?,
        });
        ListCursor::from_bytes(cursor)
    }
}
fn checksum_name(name: &str) -> Result<[u8; 32], RepositoryFailure> {
    if name.len() != 64 {
        return Err(RepositoryFailure::CorruptState);
    }
    let mut checksum = [0; 32];
    for (output, pair) in checksum.iter_mut().zip(name.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| RepositoryFailure::CorruptState)?;
        if !pair
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RepositoryFailure::CorruptState);
        }
        *output = u8::from_str_radix(pair, 16).map_err(|_| RepositoryFailure::CorruptState)?;
    }
    Ok(checksum)
}
impl AwsS3Repository {
    pub async fn list(&self, request: ListRequest) -> Result<ListPage, RepositoryFailure> {
        let _operation = self.enter()?;
        self.read_identity().await?;
        let token = self
            .listing
            .try_lock()
            .map_err(|_| RepositoryFailure::Busy)?
            .take(self.identity.repository_id(), &request)?;
        let prefix = format!(
            "{}{}",
            self.target.prefix(),
            match request.kind {
                ListKind::Objects => "o-",
                ListKind::Uploads => "u-",
            }
        );
        let response = self
            .client
            .list_objects_v2()
            .bucket(self.target.bucket())
            .prefix(&prefix)
            .expected_bucket_owner(self.target.expected_owner())
            .max_keys(i32::from(request.limit))
            .set_continuation_token(token)
            .send()
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await
            .map_err(|error| failure::sdk(error, false))?;
        if response.contents().len() > usize::from(request.limit) {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let mut entries = Vec::with_capacity(response.contents().len());
        for object in response.contents() {
            let suffix = object
                .key()
                .and_then(|key| key.strip_prefix(&prefix))
                .ok_or(RepositoryFailure::CorruptState)?;
            let checksum = checksum_name(suffix)?;
            entries.push(match request.kind {
                ListKind::Objects => ListEntry::Object(ObjectId::from_checksum(checksum)),
                ListKind::Uploads => ListEntry::Upload(UploadId(checksum)),
            });
        }
        let next_token = match response.is_truncated() {
            Some(false) => None,
            Some(true) => Some(
                response
                    .next_continuation_token()
                    .filter(|token| !token.is_empty() && token.len() <= 4096)
                    .ok_or(RepositoryFailure::CorruptState)?
                    .to_owned(),
            ),
            None => return Err(RepositoryFailure::CorruptState),
        };
        let mut state = self
            .listing
            .try_lock()
            .map_err(|_| RepositoryFailure::Busy)?;
        state.consume(self.identity.repository_id(), &request)?;
        let next = next_token
            .map(|token| state.store(self.identity.repository_id(), request.kind, token))
            .transpose()?;
        Ok(ListPage { entries, next })
    }
}
