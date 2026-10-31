//! Canonical bounded native state; encryption and publication remain with Capture.
use super::*;

const MAGIC: &[u8; 8] = b"POSBVN01";
pub(super) const MAX_SERVICE_PROGRESS: usize = 64 * 1024;
pub(super) const MAX_STATE_BYTES: usize = MAX_CATALOG_TOTAL_BYTES
    + MAX_RECOVERED_AUDIT_BYTES
    + MAX_CAPTURE_FILES * (32 + 4 + 102)
    + MAX_CATALOG_OBJECTS * (32 + 4)
    + MAX_SERVICE_PROGRESS
    + 4096;

/// The native proof has exactly one phase and never retains both full forms.
pub enum BackupVerificationNativeState {
    Metadata(Box<BackupCaptureVerification>),
    Catalog(CatalogSnapshot),
}

/// Native state and the bounded semantic cursor protected by the same owner.
pub struct BackupVerificationProgress {
    pub native: BackupVerificationNativeState,
    pub semantic: Vec<u8>,
}

#[path = "verification_continuation_storage.rs"]
mod storage;
pub use storage::{BackupVerificationBinding, BackupVerificationReference};

fn corrupt() -> CatalogFailure {
    fail(CatalogFailureCode::IntegrityCorruption)
}

fn append(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CatalogFailure> {
    let length = output.len().checked_add(value.len()).ok_or_else(corrupt)?;
    if length > MAX_STATE_BYTES {
        return Err(fail(CatalogFailureCode::LimitExceeded));
    }
    if length > output.capacity() {
        return Err(fail(CatalogFailureCode::LimitExceeded));
    }
    output.extend_from_slice(value);
    Ok(())
}

fn count(output: &mut Vec<u8>, value: usize) -> Result<(), CatalogFailure> {
    append(
        output,
        &u32::try_from(value).map_err(|_| corrupt())?.to_be_bytes(),
    )
}

fn blob(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CatalogFailure> {
    count(output, value.len())?;
    append(output, value)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], CatalogFailure> {
        let (value, rest) = self.0.split_at_checked(length).ok_or_else(corrupt)?;
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CatalogFailure> {
        self.take(N)?.try_into().map_err(|_| corrupt())
    }
    fn count(&mut self, maximum: usize) -> Result<usize, CatalogFailure> {
        let value = usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| corrupt())?;
        if value > maximum {
            return Err(corrupt());
        }
        Ok(value)
    }
    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], CatalogFailure> {
        let length = self.count(maximum)?;
        self.take(length)
    }
}

impl BackupVerificationProgress {
    fn source_basis(&self) -> Result<([u8; 32], u64, FormatEpoch, u64), CatalogFailure> {
        Ok(match &self.native {
            BackupVerificationNativeState::Metadata(state) => {
                (state.catalog, state.generation, state.epoch, state.audit)
            },
            BackupVerificationNativeState::Catalog(snapshot) => (
                snapshot.identity().to_bytes(),
                snapshot.number(),
                snapshot.0.format_epoch.ok_or_else(corrupt)?,
                snapshot.governance_audit_frontier(),
            ),
        })
    }
    fn validate_source(&self, base: &BackupCaptureVerification) -> Result<(), CatalogFailure> {
        if self.source_basis()? != (base.catalog, base.generation, base.epoch, base.audit) {
            return Err(corrupt());
        }
        if let BackupVerificationNativeState::Metadata(state) = &self.native
            && (state.instance != base.instance
                || state.capture != base.capture
                || state.files != base.files)
        {
            return Err(corrupt());
        }
        Ok(())
    }
    fn catalog_memory(count: usize, encoded_length: usize) -> Result<u64, CatalogFailure> {
        let bytes = nodes(std::mem::size_of::<(CatalogObjectId, Arc<[u8]>)>(), count)?
            .checked_add(
                count
                    .checked_mul(2 * std::mem::size_of::<usize>())
                    .ok_or_else(corrupt)?,
            )
            .and_then(|bytes| bytes.checked_add(encoded_length))
            .ok_or_else(corrupt)?;
        u64::try_from(bytes).map_err(|_| corrupt())
    }
    fn native_decode_memory(
        bytes: &[u8],
        base: &BackupCaptureVerification,
    ) -> Result<u64, CatalogFailure> {
        let mut input = Reader(bytes);
        input.take(60)?;
        input.blob(MAX_SERVICE_PROGRESS)?;
        match input.array::<1>()? {
            [0] => base.prospective_memory_bytes(),
            [1] => Self::catalog_memory(input.count(MAX_CATALOG_OBJECTS)?, bytes.len()),
            _ => Err(corrupt()),
        }
    }
    fn encoded_length(&self) -> Result<usize, CatalogFailure> {
        let (objects, phase_bytes) = match &self.native {
            BackupVerificationNativeState::Metadata(state) => {
                let checkpoint = state
                    .checkpoint
                    .as_ref()
                    .map_or(0, |value| value.encode().len());
                let mut length = 4usize
                    .checked_mul(4)
                    .and_then(|bytes| bytes.checked_add(checkpoint))
                    .ok_or_else(corrupt)?;
                length = state
                    .accepted
                    .len()
                    .checked_mul(32)
                    .and_then(|bytes| length.checked_add(bytes))
                    .ok_or_else(corrupt)?;
                for record in &state.records {
                    length = length
                        .checked_add(106)
                        .and_then(|bytes| bytes.checked_add(record.intent().len()))
                        .ok_or_else(corrupt)?;
                }
                (&state.objects, length)
            },
            BackupVerificationNativeState::Catalog(snapshot) => (&snapshot.0.objects, 40),
        };
        let length = 69usize
            .checked_add(self.semantic.len())
            .and_then(|bytes| bytes.checked_add(phase_bytes))
            .ok_or_else(corrupt)?;
        let length = objects.values().try_fold(length, |total, value| {
            total
                .checked_add(36)
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or_else(corrupt)
        })?;
        if length > MAX_STATE_BYTES || self.semantic.len() > MAX_SERVICE_PROGRESS {
            return Err(corrupt());
        }
        Ok(length)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, CatalogFailure> {
        if self.semantic.len() > MAX_SERVICE_PROGRESS {
            return Err(corrupt());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.encoded_length()?)
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        append(&mut bytes, MAGIC)?;
        let (identity, generation, epoch, audit) = self.source_basis()?;
        append(&mut bytes, &identity)?;
        append(&mut bytes, &generation.to_be_bytes())?;
        append(&mut bytes, &epoch.value().to_be_bytes())?;
        append(&mut bytes, &audit.to_be_bytes())?;
        blob(&mut bytes, &self.semantic)?;
        let (objects, frontier) = match &self.native {
            BackupVerificationNativeState::Metadata(state) => {
                append(&mut bytes, &[0])?;
                count(&mut bytes, state.next_pending_file()?)?;
                count(&mut bytes, state.accepted.len())?;
                for identity in &state.accepted {
                    append(&mut bytes, identity)?;
                }
                count(&mut bytes, state.records.len())?;
                for record in &state.records {
                    blob(&mut bytes, &crate::catalog::codec::encode_audit(record))?;
                }
                blob(
                    &mut bytes,
                    &state
                        .checkpoint
                        .as_ref()
                        .map_or_else(Vec::new, GovernanceAuditCheckpoint::encode),
                )?;
                (&state.objects, None)
            },
            BackupVerificationNativeState::Catalog(snapshot) => {
                append(&mut bytes, &[1])?;
                (&snapshot.0.objects, Some(&snapshot.0.audit_frontier))
            },
        };
        count(&mut bytes, objects.len())?;
        for (identity, value) in objects {
            append(&mut bytes, &identity.to_bytes())?;
            blob(&mut bytes, value)?;
        }
        if let Some(frontier) = frontier {
            append(&mut bytes, &frontier.position.to_be_bytes())?;
            append(&mut bytes, &frontier.hash)?;
        }
        Ok(bytes)
    }

    pub(super) fn decode(
        bytes: &[u8],
        mut base: BackupCaptureVerification,
    ) -> Result<Self, CatalogFailure> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(corrupt());
        }
        let mut input = Reader(bytes);
        if input.take(8)? != MAGIC {
            return Err(corrupt());
        }
        let source = (
            input.array::<32>()?,
            u64::from_be_bytes(input.array()?),
            u32::from_be_bytes(input.array()?),
            u64::from_be_bytes(input.array()?),
        );
        if source
            != (
                base.catalog,
                base.generation,
                base.epoch.value(),
                base.audit,
            )
        {
            return Err(corrupt());
        }
        let semantic = input.blob(MAX_SERVICE_PROGRESS)?.to_vec();
        let phase = input.array::<1>()?;
        let next = if phase == [0] {
            let next = input.count(base.files.len())?;
            let accepted = input.count(MAX_CAPTURE_FILES)?;
            for _ in 0..accepted {
                if !base.accepted.insert(input.array()?) {
                    return Err(corrupt());
                }
            }
            let records = input.count(MAX_CAPTURE_FILES)?;
            for _ in 0..records {
                let value = input.blob(super::super::super::codec::MAX_AUDIT_RECORD_BYTES)?;
                let record = crate::catalog::codec::decode_audit(value)?;
                base.audit_bytes = base
                    .audit_bytes
                    .checked_add(record.intent().len())
                    .ok_or_else(corrupt)?;
                if base.audit_bytes > MAX_RECOVERED_AUDIT_BYTES {
                    return Err(corrupt());
                }
                base.records.push(record);
            }
            let checkpoint = input.blob(1024)?;
            if !checkpoint.is_empty() {
                base.checkpoint = Some(GovernanceAuditCheckpoint::decode(checkpoint)?);
            }
            Some(next)
        } else if phase == [1] {
            None
        } else {
            return Err(corrupt());
        };
        let objects = input.count(MAX_CATALOG_OBJECTS)?;
        for _ in 0..objects {
            let identity = CatalogObjectId(input.array()?);
            let value = input.blob(types::MAX_CATALOG_OBJECT_BYTES)?;
            base.object_bytes = base
                .object_bytes
                .checked_add(value.len())
                .ok_or_else(corrupt)?;
            if base.object_bytes > MAX_CATALOG_TOTAL_BYTES
                || base.objects.insert(identity, Arc::from(value)).is_some()
            {
                return Err(corrupt());
            }
        }
        let native = if let Some(next) = next {
            if base.next_pending_file()? != next {
                return Err(corrupt());
            }
            BackupVerificationNativeState::Metadata(Box::new(base))
        } else {
            let position = u64::from_be_bytes(input.array()?);
            let hash = input.array()?;
            if position != base.audit {
                return Err(corrupt());
            }
            BackupVerificationNativeState::Catalog(CatalogSnapshot(Arc::new(types::SnapshotData {
                identity: CatalogGenerationId(base.catalog),
                number: base.generation,
                format_epoch: Some(base.epoch),
                objects: base.objects,
                audit_frontier: types::AuditFrontier { position, hash },
            })))
        };
        if !input.0.is_empty() {
            return Err(corrupt());
        }
        Ok(Self { native, semantic })
    }
}

impl BackupCaptureVerification {
    /// Accepted native files must be the exact metadata prefix, never holes.
    pub fn next_pending_file(&self) -> Result<usize, CatalogFailure> {
        let mut pending = None;
        let mut accepted = 0usize;
        for (position, file) in self.files.iter().enumerate() {
            if !matches!(
                file.kind,
                BackupCaptureFileKind::CatalogObject
                    | BackupCaptureFileKind::GovernanceAudit
                    | BackupCaptureFileKind::AuditCheckpoint
            ) {
                continue;
            }
            if self.accepted.contains(&file.identity) {
                if pending.is_some() {
                    return Err(corrupt());
                }
                accepted = accepted.checked_add(1).ok_or_else(corrupt)?;
            } else if pending.is_none() {
                pending = Some(position);
            }
        }
        if accepted != self.accepted.len() {
            return Err(corrupt());
        }
        Ok(pending.unwrap_or(self.files.len()))
    }
}
