use crate::*;
mod native;
mod operations;
use sha2::{Digest, Sha256};
const HEADER: usize = 141;
pub(super) struct Record {
    pub plan: UploadPlan,
    pub bytes: Vec<u8>,
    pub selector: [u8; 16],
    /// None before Create; requested with no URI is an uncertain outcome.
    pub requested: bool,
    pub session: Option<Vec<u8>>,
}
impl Record {
    pub fn new(plan: UploadPlan, selector: [u8; 16]) -> Self {
        Self {
            plan,
            bytes: Vec::new(),
            selector,
            requested: false,
            session: None,
        }
    }
    pub fn state(&self) -> UploadState {
        UploadState {
            plan: self.plan,
            written: self.bytes.len() as u64,
            checksum: Sha256::digest(&self.bytes).into(),
        }
    }
    pub fn encode(&self, target: [u8; 32]) -> Vec<u8> {
        let session = self.session.as_deref().unwrap_or(&[]);
        let mut frame = Vec::with_capacity(HEADER + session.len() + self.bytes.len() + 32);
        frame.extend_from_slice(b"POSGCU01");
        frame.extend_from_slice(&target);
        frame.extend_from_slice(&self.plan.object.checksum());
        frame.extend_from_slice(&self.plan.size.to_be_bytes());
        frame.extend_from_slice(&(self.bytes.len() as u64).to_be_bytes());
        frame.extend_from_slice(&self.state().checksum);
        frame.extend_from_slice(&self.selector);
        frame.push(u8::from(self.requested));
        frame.extend_from_slice(&(session.len() as u32).to_be_bytes());
        frame.extend_from_slice(session);
        frame.extend_from_slice(&self.bytes);
        let checksum: [u8; 32] = Sha256::digest(&frame).into();
        frame.extend_from_slice(&checksum);
        frame
    }
    pub fn decode(
        mut frame: Vec<u8>,
        target: [u8; 32],
        id: UploadId,
    ) -> Result<Self, RepositoryFailure> {
        fn field<const N: usize>(frame: &[u8], start: usize) -> Result<[u8; N], RepositoryFailure> {
            frame
                .get(start..start + N)
                .and_then(|s| s.try_into().ok())
                .ok_or(RepositoryFailure::CorruptState)
        }
        if frame.len() < HEADER + 32
            || frame.len() > MAX_OBJECT_BYTES as usize + HEADER + 4096 + 32
            || frame.get(..8) != Some(b"POSGCU01")
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let end = frame.len() - 32;
        if frame.get(end..)
            != Some(
                Sha256::digest(frame.get(..end).ok_or(RepositoryFailure::CorruptState)?).as_slice(),
            )
        {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        if field::<32>(&frame, 8)? != target {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let plan = UploadPlan::new(
            ObjectId::from_checksum(field(&frame, 40)?),
            u64::from_be_bytes(field(&frame, 72)?),
        )?;
        if plan.id() != id {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let written = u64::from_be_bytes(field(&frame, 80)?);
        let checksum: [u8; 32] = field(&frame, 88)?;
        let selector = field(&frame, 120)?;
        let requested = match frame.get(136) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(RepositoryFailure::CorruptState),
        };
        let length = u32::from_be_bytes(field(&frame, 137)?) as usize;
        if length > 4096 {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let start = HEADER
            .checked_add(length)
            .ok_or(RepositoryFailure::CorruptState)?;
        let session = frame
            .get(HEADER..start)
            .ok_or(RepositoryFailure::CorruptState)?;
        let session = if session.is_empty() {
            None
        } else {
            Some(session.to_vec())
        };
        let bytes = frame
            .get(start..end)
            .ok_or(RepositoryFailure::CorruptState)?;
        if bytes.len() as u64 != written
            || written > plan.size
            || selector == [0; 16]
            || <[u8; 32]>::from(Sha256::digest(bytes)) != checksum
            || (!requested && session.is_some())
            || requested && written != plan.size
        {
            return Err(RepositoryFailure::CorruptState);
        }
        if written == plan.size && checksum != plan.object.checksum() {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        let len = end - start;
        frame.copy_within(start..end, 0);
        frame.truncate(len);
        Ok(Self {
            plan,
            bytes: frame,
            selector,
            requested,
            session,
        })
    }
}
