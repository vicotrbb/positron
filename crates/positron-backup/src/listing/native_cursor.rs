use crate::{ListCursor, ListKind, ListRequest, RepositoryFailure};
use std::time::{Duration, Instant};
struct Lease {
    id: u64,
    kind: ListKind,
    token: String,
    expires: Instant,
}
pub(crate) struct State {
    owner: [u8; 16],
    next: u64,
    leases: Vec<Lease>,
}
impl State {
    pub(crate) fn new() -> Result<Self, RepositoryFailure> {
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
    pub(crate) fn take(
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
    pub(crate) fn consume(
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
    pub(crate) fn store(
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
pub(crate) fn checksum_name(name: &str) -> Result<[u8; 32], RepositoryFailure> {
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
