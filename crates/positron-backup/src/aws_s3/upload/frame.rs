use super::{HEADER, MAX_NATIVE_UPLOAD_ID, NativeCreation, OwnedUpload, Record};
use crate::{MAX_OBJECT_BYTES, ObjectId, RepositoryFailure, UploadId, UploadPlan};
use sha2::{Digest, Sha256};
struct ParsedRecord<'a> {
    plan: UploadPlan,
    bytes: &'a [u8],
    creation: NativeCreation,
    selector: [u8; 16],
}
impl Record {
    fn parse(
        frame: &[u8],
        target: [u8; 32],
        expected: UploadId,
    ) -> Result<ParsedRecord<'_>, RepositoryFailure> {
        if frame.len() < HEADER + 32
            || frame.len() as u64 > MAX_OBJECT_BYTES + (HEADER + MAX_NATIVE_UPLOAD_ID + 32) as u64
            || frame.get(..8) != Some(b"POSS3U01")
        {
            return Err(RepositoryFailure::CorruptState);
        }
        let end = frame
            .len()
            .checked_sub(32)
            .ok_or(RepositoryFailure::CorruptState)?;
        let payload = frame.get(..end).ok_or(RepositoryFailure::CorruptState)?;
        if frame.get(end..) != Some(Sha256::digest(payload).as_slice()) {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        fn field<const N: usize>(frame: &[u8], start: usize) -> Result<[u8; N], RepositoryFailure> {
            frame
                .get(start..start + N)
                .and_then(|value| value.try_into().ok())
                .ok_or(RepositoryFailure::CorruptState)
        }
        if field::<32>(frame, 8)? != target {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let plan = UploadPlan::new(
            ObjectId::from_checksum(field(frame, 40)?),
            u64::from_be_bytes(field(frame, 72)?),
        )
        .map_err(|_| RepositoryFailure::CorruptState)?;
        if plan.id() != expected {
            return Err(RepositoryFailure::IdentityMismatch);
        }
        let written = u64::from_be_bytes(field(frame, 80)?);
        let checksum: [u8; 32] = field(frame, 88)?;
        let native_length = u32::from_be_bytes(field(frame, 120)?) as usize;
        if native_length > MAX_NATIVE_UPLOAD_ID {
            return Err(RepositoryFailure::LimitExceeded);
        }
        let body_start = HEADER
            .checked_add(native_length)
            .ok_or(RepositoryFailure::CorruptState)?;
        let native = std::str::from_utf8(
            frame
                .get(HEADER..body_start)
                .ok_or(RepositoryFailure::CorruptState)?,
        )
        .map_err(|_| RepositoryFailure::CorruptState)?;
        let bytes = frame
            .get(body_start..end)
            .ok_or(RepositoryFailure::CorruptState)?;
        if bytes.len() as u64 != written || <[u8; 32]>::from(Sha256::digest(bytes)) != checksum {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        let selector = field::<16>(frame, 124)?;
        if selector == [0; 16] {
            return Err(RepositoryFailure::CorruptState);
        }
        if written > plan.size || written > MAX_OBJECT_BYTES {
            return Err(RepositoryFailure::LimitExceeded);
        }
        if written == plan.size && checksum != plan.object.checksum() {
            return Err(RepositoryFailure::ChecksumMismatch);
        }
        let attempt = field::<16>(frame, 141)?;
        let creation = match (frame.get(140), native.is_empty(), attempt == [0; 16]) {
            (Some(0), true, true) => NativeCreation::NotStarted,
            (Some(1), true, false) if written == plan.size => NativeCreation::Requested(attempt),
            (Some(2), false, false) if written == plan.size => {
                if native.chars().any(char::is_control) {
                    return Err(RepositoryFailure::CorruptState);
                }
                NativeCreation::Known {
                    attempt,
                    id: native.to_owned(),
                }
            },
            _ => return Err(RepositoryFailure::CorruptState),
        };
        Ok(ParsedRecord {
            plan,
            bytes,
            creation,
            selector,
        })
    }
    /// Authentication and ownership inspection never allocate a payload copy.
    pub(in crate::aws_s3) fn inspect_owned(
        frame: &[u8],
        target: [u8; 32],
        expected: UploadId,
    ) -> Result<OwnedUpload, RepositoryFailure> {
        let parsed = Self::parse(frame, target, expected)?;
        let (native_id, attempt, creation_unresolved) = match parsed.creation {
            NativeCreation::NotStarted => (None, [0; 16], false),
            NativeCreation::Requested(attempt) => (None, attempt, true),
            NativeCreation::Known { attempt, id } => (Some(id), attempt, false),
        };
        Ok(OwnedUpload {
            plan: parsed.plan,
            native_id,
            selector: parsed.selector,
            attempt,
            creation_unresolved,
        })
    }
    /// Reuses the authenticated downloaded allocation instead of copying its payload.
    pub(in crate::aws_s3) fn decode_buffer(
        mut frame: Vec<u8>,
        target: [u8; 32],
        expected: UploadId,
    ) -> Result<Self, RepositoryFailure> {
        let parsed = Self::parse(&frame, target, expected)?;
        let length = parsed.bytes.len();
        let start = frame.len() - 32 - length;
        let plan = parsed.plan;
        let selector = parsed.selector;
        let creation = parsed.creation;
        frame.copy_within(start..start + length, 0);
        frame.truncate(length);
        Ok(Self {
            plan,
            bytes: frame,
            creation,
            selector,
        })
    }
    #[cfg(any(test, fuzzing))]
    pub(in crate::aws_s3) fn decode(
        frame: &[u8],
        target: [u8; 32],
        expected: UploadId,
    ) -> Result<Self, RepositoryFailure> {
        Self::decode_buffer(frame.to_vec(), target, expected)
    }
}
