mod frame;
mod io;
mod native;
mod operations;
use crate::{MAX_OBJECT_BYTES, RepositoryFailure, UploadPlan, UploadState};
use sha2::{Digest, Sha256};

const MAX_NATIVE_UPLOAD_ID: usize = 4096;
const HEADER: usize = 157;
/// Native provider recovery state. The Administration operation remains the
/// owner of authorization and workflow progress; this record owns only bytes
/// and the S3 multipart session for one immutable object.
#[derive(Eq, PartialEq)]
pub(super) struct Record {
    plan: UploadPlan,
    bytes: Vec<u8>,
    creation: NativeCreation,
    selector: [u8; 16],
}
#[derive(Eq, PartialEq)]
enum NativeCreation {
    NotStarted,
    Requested([u8; 16]),
    Known { attempt: [u8; 16], id: String },
}
#[derive(Eq, PartialEq)]
pub(in crate::aws_s3) struct OwnedUpload {
    pub(in crate::aws_s3) plan: UploadPlan,
    pub(in crate::aws_s3) native_id: Option<String>,
    pub(in crate::aws_s3) selector: [u8; 16],
    pub(in crate::aws_s3) attempt: [u8; 16],
    pub(in crate::aws_s3) creation_unresolved: bool,
}
impl Record {
    fn native_id(&self) -> Option<&str> {
        match &self.creation {
            NativeCreation::Known { id, .. } => Some(id),
            _ => None,
        }
    }
    fn attempt(&self) -> [u8; 16] {
        match self.creation {
            NativeCreation::NotStarted => [0; 16],
            NativeCreation::Requested(attempt) | NativeCreation::Known { attempt, .. } => attempt,
        }
    }
    fn native_creation_allowed(&self, observed: usize) -> Result<bool, RepositoryFailure> {
        match (&self.creation, observed) {
            (_, 2..) => Err(RepositoryFailure::Busy),
            (NativeCreation::Requested(_), 0) => Err(RepositoryFailure::OutcomeUnknown),
            (NativeCreation::NotStarted, 0) => Ok(true),
            _ => Ok(false),
        }
    }
    fn mark_native_creation_requested(&mut self) -> Result<(), RepositoryFailure> {
        if !matches!(self.creation, NativeCreation::NotStarted) || !self.state().complete() {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let mut attempt = [0; 16];
        getrandom::fill(&mut attempt).map_err(|_| RepositoryFailure::StorageUnavailable)?;
        if attempt == [0; 16] {
            return Err(RepositoryFailure::StorageUnavailable);
        }
        self.creation = NativeCreation::Requested(attempt);
        Ok(())
    }
    fn attach_native_id(&mut self, id: String) -> Result<(), RepositoryFailure> {
        let attempt = self.attempt();
        if attempt == [0; 16]
            || id.is_empty()
            || id.len() > MAX_NATIVE_UPLOAD_ID
            || id.chars().any(char::is_control)
        {
            return Err(RepositoryFailure::CorruptState);
        }
        self.creation = NativeCreation::Known { attempt, id };
        Ok(())
    }
    pub(super) fn apply(
        &self,
        part: &crate::UploadPart,
    ) -> Result<Option<Self>, RepositoryFailure> {
        if self.plan != part.state.plan {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let start =
            usize::try_from(part.state.written).map_err(|_| RepositoryFailure::LimitExceeded)?;
        let end = start
            .checked_add(part.bytes.len())
            .ok_or(RepositoryFailure::LimitExceeded)?;
        let prefix = self
            .bytes
            .get(..start)
            .ok_or(RepositoryFailure::PreconditionFailed)?;
        if <[u8; 32]>::from(Sha256::digest(prefix)) != part.state.checksum {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        if self.bytes.len() >= end {
            return if self.bytes.get(start..end) == Some(part.bytes.as_slice()) {
                Ok(None)
            } else {
                Err(RepositoryFailure::PreconditionFailed)
            };
        }
        if self.bytes.len() != start || self.native_id().is_some() {
            return Err(RepositoryFailure::PreconditionFailed);
        }
        let mut bytes = Vec::with_capacity(end);
        bytes.extend_from_slice(&self.bytes);
        bytes.extend_from_slice(&part.bytes);
        Self::restore(self.plan, bytes, None, self.selector).map(Some)
    }
    pub(super) fn new(
        plan: UploadPlan,
        bytes: Vec<u8>,
        native_id: Option<String>,
    ) -> Result<Self, RepositoryFailure> {
        let mut selector = [0; 16];
        getrandom::fill(&mut selector).map_err(|_| RepositoryFailure::StorageUnavailable)?;
        Self::restore(plan, bytes, native_id, selector)
    }
    fn restore(
        plan: UploadPlan,
        bytes: Vec<u8>,
        native_id: Option<String>,
        selector: [u8; 16],
    ) -> Result<Self, RepositoryFailure> {
        if selector == [0; 16] {
            return Err(RepositoryFailure::CorruptState);
        }
        if native_id.as_ref().is_some_and(|id| {
            id.is_empty() || id.len() > MAX_NATIVE_UPLOAD_ID || id.chars().any(char::is_control)
        }) {
            return Err(RepositoryFailure::CorruptState);
        }
        if bytes.len() as u64 > plan.size || bytes.len() as u64 > MAX_OBJECT_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if bytes.len() as u64 == plan.size
            && <[u8; 32]>::from(Sha256::digest(&bytes)) != plan.object.checksum()
        {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        if native_id.is_some() {
            return Err(RepositoryFailure::InvalidInput);
        }
        Ok(Self {
            plan,
            bytes,
            creation: NativeCreation::NotStarted,
            selector,
        })
    }
    pub(super) fn owned(&self) -> OwnedUpload {
        OwnedUpload {
            plan: self.plan,
            native_id: self.native_id().map(str::to_owned),
            selector: self.selector,
            attempt: self.attempt(),
            creation_unresolved: matches!(self.creation, NativeCreation::Requested(_)),
        }
    }
    pub(super) fn state(&self) -> UploadState {
        UploadState {
            plan: self.plan,
            written: self.bytes.len() as u64,
            checksum: Sha256::digest(&self.bytes).into(),
        }
    }
    pub(super) fn encode(&self, target: [u8; 32]) -> Vec<u8> {
        let native = self.native_id().unwrap_or("").as_bytes();
        let mut frame = Vec::with_capacity(HEADER + native.len() + self.bytes.len() + 32);
        frame.extend_from_slice(b"POSS3U01");
        frame.extend_from_slice(&target);
        frame.extend_from_slice(&self.plan.object.checksum());
        frame.extend_from_slice(&self.plan.size.to_be_bytes());
        frame.extend_from_slice(&(self.bytes.len() as u64).to_be_bytes());
        frame.extend_from_slice(&self.state().checksum);
        frame.extend_from_slice(&(native.len() as u32).to_be_bytes());
        frame.extend_from_slice(&self.selector);
        frame.push(match self.creation {
            NativeCreation::NotStarted => 0,
            NativeCreation::Requested(_) => 1,
            NativeCreation::Known { .. } => 2,
        });
        frame.extend_from_slice(&self.attempt());
        frame.extend_from_slice(native);
        frame.extend_from_slice(&self.bytes);
        let checksum: [u8; 32] = Sha256::digest(&frame).into();
        frame.extend_from_slice(&checksum);
        frame
    }
}

#[cfg(test)]
mod creation_tests {
    use super::*;
    #[test]
    fn ownership_inspection_authenticates_maximum_payload_and_rejects_forged_frames() {
        let object = crate::ImmutableObject::new(vec![37; MAX_OBJECT_BYTES as usize])
            .expect("maximum encrypted object");
        let plan = UploadPlan::new(object.id(), MAX_OBJECT_BYTES).expect("maximum plan");
        let record =
            Record::restore(plan, object.bytes().to_vec(), None, [3; 16]).expect("maximum record");
        let expected = record.owned();
        let mut frame = record.encode([1; 32]);
        drop(record);
        drop(object);
        assert!(
            Record::inspect_owned(&frame, [1; 32], plan.id()).expect("authenticated ownership")
                == expected
        );
        assert!(matches!(
            Record::inspect_owned(&frame, [2; 32], plan.id()),
            Err(RepositoryFailure::IdentityMismatch)
        ));
        frame[HEADER] ^= 1;
        assert!(matches!(
            Record::inspect_owned(&frame, [1; 32], plan.id()),
            Err(RepositoryFailure::ChecksumMismatch)
        ));
        let end = frame.len() - 32;
        let checksum: [u8; 32] = Sha256::digest(&frame[..end]).into();
        frame[end..].copy_from_slice(&checksum);
        assert!(matches!(
            Record::inspect_owned(&frame, [1; 32], plan.id()),
            Err(RepositoryFailure::ChecksumMismatch)
        ));
    }

    #[test]
    fn consumed_record_reconciles_exact_state_and_rejects_invalid_creation_metadata() {
        let object =
            crate::ImmutableObject::new(b"encrypted retry payload".to_vec()).expect("object");
        let plan = UploadPlan::new(object.id(), object.bytes().len() as u64).expect("plan");
        let mut record =
            Record::restore(plan, object.bytes().to_vec(), None, [3; 16]).expect("record");
        record.creation = NativeCreation::Known {
            attempt: [2; 16],
            id: "native-id".into(),
        };
        let restored =
            Record::decode_buffer(record.encode([1; 32]), [1; 32], plan.id()).expect("retry state");
        assert!(restored == record);
        let mut frame = record.encode([1; 32]);
        frame[140] = 1; // Requested state may not carry a native ID.
        let end = frame.len() - 32;
        let checksum: [u8; 32] = Sha256::digest(&frame[..end]).into();
        frame[end..].copy_from_slice(&checksum);
        assert!(matches!(
            Record::inspect_owned(&frame, [1; 32], plan.id()),
            Err(RepositoryFailure::CorruptState)
        ));
        assert!(matches!(
            Record::decode_buffer(frame, [1; 32], plan.id()),
            Err(RepositoryFailure::CorruptState)
        ));
    }
    #[test]
    fn uncertain_native_creation_survives_reopen_and_never_uses_empty_listing_as_disproof() {
        let object =
            crate::ImmutableObject::new(b"encrypted native upload".to_vec()).expect("object");
        let plan = UploadPlan::new(object.id(), object.bytes().len() as u64).expect("plan");
        let mut record = Record::new(plan, object.bytes().to_vec(), None).expect("record");
        assert_eq!(record.native_creation_allowed(0), Ok(true));
        record
            .mark_native_creation_requested()
            .expect("prepare native call");
        let restored = Record::decode(&record.encode([1; 32]), [1; 32], plan.id()).expect("reopen");
        assert_eq!(
            restored.native_creation_allowed(0),
            Err(RepositoryFailure::OutcomeUnknown)
        );
        assert_eq!(restored.native_creation_allowed(1), Ok(false));
        assert_eq!(
            restored.native_creation_allowed(2),
            Err(RepositoryFailure::Busy)
        );
        assert_eq!(restored.state(), record.state());
    }
}

#[cfg(fuzzing)]
pub(super) fn fuzz_record(data: &[u8]) {
    if data.len() > 8192 {
        return;
    }
    let object = crate::ImmutableObject::new(b"opaque encrypted frame fixture".to_vec())
        .expect("bounded object");
    let plan = UploadPlan::new(object.id(), object.bytes().len() as u64).expect("bounded plan");
    let _ = Record::decode(data, [1; 32], plan.id());
    for creation in [
        NativeCreation::NotStarted,
        NativeCreation::Requested([2; 16]),
        NativeCreation::Known {
            attempt: [2; 16],
            id: "native-frame-id".into(),
        },
    ] {
        let mut record =
            Record::restore(plan, object.bytes().to_vec(), None, [3; 16]).expect("bounded fixture");
        record.creation = creation;
        let mut frame = record.encode([1; 32]);
        assert!(
            Record::decode(&frame, [1; 32], plan.id())
                .expect("frame")
                .state()
                == record.state()
        );
        for mutation in data.chunks(4).take(128) {
            let position = usize::from(u16::from_be_bytes([
                mutation.get(1).copied().unwrap_or_default(),
                mutation.get(2).copied().unwrap_or_default(),
            ]));
            let value = mutation.get(3).copied().unwrap_or_default();
            match mutation.first().copied().unwrap_or_default() % 4 {
                0 => {
                    if let Some(byte) = frame.get_mut(position) {
                        *byte ^= value;
                    }
                },
                1 => frame.truncate(position.min(frame.len())),
                2 => {
                    if frame.len() < 8192 {
                        frame.push(value);
                    }
                },
                _ => {
                    if let Some(end) = frame.len().checked_sub(32) {
                        let checksum: [u8; 32] =
                            Sha256::digest(frame.get(..end).expect("bounded prefix")).into();
                        frame
                            .get_mut(end..)
                            .expect("trailer")
                            .copy_from_slice(&checksum);
                    }
                },
            }
            if let Ok(decoded) = Record::decode(&frame, [1; 32], plan.id()) {
                let canonical = Record::decode(&decoded.encode([1; 32]), [1; 32], plan.id())
                    .expect("accepted frame roundtrip");
                assert!(canonical == decoded);
            }
        }
    }
}
