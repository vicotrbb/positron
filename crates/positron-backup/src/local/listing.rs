use super::*;
use crate::{ListCursor, ListEntry, ListKind, ListPage, ListRequest, UploadId};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
pub(super) struct State {
    owner: [u8; 16],
    next: u64,
    streams: BTreeMap<u64, Stream>,
}
impl State {
    pub(super) fn new() -> Result<Self, RepositoryFailure> {
        let mut owner = [0; 16];
        getrandom::fill(&mut owner).map_err(|_| RepositoryFailure::StorageUnavailable)?;
        Ok(Self {
            owner,
            next: 0,
            streams: BTreeMap::new(),
        })
    }
}
struct Stream {
    directory: fs::Dir,
    kind: ListKind,
    sequence: u64,
    expires: Instant,
}
fn decode_hex(bytes: &[u8]) -> Result<[u8; 32], RepositoryFailure> {
    if bytes.len() != 64 {
        return Err(RepositoryFailure::CorruptState);
    }
    let mut result = [0; 32];
    fn digit(byte: u8) -> Result<u8, RepositoryFailure> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(RepositoryFailure::CorruptState),
        }
    }
    for (output, pair) in result.iter_mut().zip(bytes.chunks_exact(2)) {
        let first = pair
            .first()
            .copied()
            .ok_or(RepositoryFailure::CorruptState)?;
        let second = pair
            .get(1)
            .copied()
            .ok_or(RepositoryFailure::CorruptState)?;
        *output = digit(first)? * 16 + digit(second)?;
    }
    Ok(result)
}
pub(super) fn list(
    root: &File,
    identity: &RepositoryIdentity,
    state: &std::sync::Mutex<State>,
    request: ListRequest,
) -> Result<ListPage, RepositoryFailure> {
    verify_identity(root, identity)?;
    let mut state = state.try_lock().map_err(|_| RepositoryFailure::Busy)?;
    let now = Instant::now();
    state.streams.retain(|_, stream| stream.expires > now);
    let kind = match request.kind {
        ListKind::Objects => 1,
        ListKind::Uploads => 2,
    };
    let id = if let Some(cursor) = request.cursor {
        if cursor.bytes().len() != 49
            || cursor.bytes().get(..16) != Some(&identity.repository_id()[..])
            || cursor.bytes().get(16..32) != Some(&state.owner[..])
            || cursor.bytes().get(48) != Some(&kind)
        {
            return Err(RepositoryFailure::InvalidInput);
        }
        let number = |start: usize| -> Result<u64, RepositoryFailure> {
            Ok(u64::from_be_bytes(
                cursor
                    .bytes()
                    .get(start..start + 8)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(RepositoryFailure::InvalidInput)?,
            ))
        };
        let id = number(32)?;
        let sequence = number(40)?;
        let stream = state
            .streams
            .get(&id)
            .ok_or(RepositoryFailure::InvalidInput)?;
        if stream.kind != request.kind || stream.sequence != sequence {
            return Err(RepositoryFailure::InvalidInput);
        }
        id
    } else {
        if state.streams.len() >= 8 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        state.next = state
            .next
            .checked_add(1)
            .ok_or(RepositoryFailure::LimitExceeded)?;
        let id = state.next;
        state.streams.insert(
            id,
            Stream {
                directory: fs::Dir::read_from(root).map_err(storage)?,
                kind: request.kind,
                sequence: 0,
                expires: now + Duration::from_secs(30),
            },
        );
        id
    };
    let owner = state.owner;
    let stream = state
        .streams
        .get_mut(&id)
        .ok_or(RepositoryFailure::InvalidInput)?;
    let mut entries = Vec::with_capacity(usize::from(request.limit));
    let mut ended = false;
    for _ in 0..1024 {
        let Some(entry) = stream.directory.next() else {
            ended = true;
            break;
        };
        let entry = entry.map_err(storage)?;
        let name = entry.file_name().to_bytes();
        let prefix = match request.kind {
            ListKind::Objects => b"o-",
            ListKind::Uploads => b"u-",
        };
        if name.starts_with(prefix) {
            let checksum = decode_hex(name.get(2..).ok_or(RepositoryFailure::CorruptState)?)?;
            entries.push(match request.kind {
                ListKind::Objects => ListEntry::Object(ObjectId::from_checksum(checksum)),
                ListKind::Uploads => ListEntry::Upload(UploadId(checksum)),
            });
        }
        if entries.len() == usize::from(request.limit) {
            break;
        }
    }
    if ended {
        state.streams.remove(&id);
        return Ok(ListPage {
            entries,
            next: None,
        });
    }
    stream.sequence = stream
        .sequence
        .checked_add(1)
        .ok_or(RepositoryFailure::LimitExceeded)?;
    let mut bytes = Vec::with_capacity(49);
    bytes.extend_from_slice(&identity.repository_id());
    bytes.extend_from_slice(&owner);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&stream.sequence.to_be_bytes());
    bytes.push(kind);
    Ok(ListPage {
        entries,
        next: Some(ListCursor::from_bytes(bytes)?),
    })
}
