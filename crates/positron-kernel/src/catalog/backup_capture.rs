//! Kernel-owned persistent immutable capture. No native paths are accepted.
mod codec;
mod io;
mod preparation;
mod resources;
use super::*;
pub use preparation::{BackupCaptureCustody, BackupCapturePreparation};
pub use resources::BackupCaptureResourceEstimate;
use rustix::fs::{self as unix_fs, Mode, OFlags};
use std::io::{Read, Seek, SeekFrom};
const MAX_CAPTURE_FILES: usize = 65_536;
const MAX_CAPTURE_INDEX_BYTES: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupCaptureFileKind {
    CatalogObject,
    GovernanceAudit,
    AuditCheckpoint,
    Segment,
    SegmentFrontier,
    Index,
}
impl BackupCaptureFileKind {
    fn code(self) -> u8 {
        match self {
            Self::CatalogObject => 1,
            Self::GovernanceAudit => 2,
            Self::AuditCheckpoint => 5,
            Self::SegmentFrontier => 6,
            Self::Segment => 3,
            Self::Index => 4,
        }
    }
}
/// Typed logical destination; restoration derives its canonical layout without
/// trusting paths from the repository or requiring the original capture root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupCaptureFile {
    identity: [u8; 32],
    kind: BackupCaptureFileKind,
    address: [u8; 32],
    size: u64,
    checksum: [u8; 32],
}
impl BackupCaptureFile {
    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }
    pub const fn kind(self) -> BackupCaptureFileKind {
        self.kind
    }
    pub const fn address(self) -> [u8; 32] {
        self.address
    }
    pub(crate) fn storage_name(self) -> String {
        let segment = self
            .address
            .iter()
            .take(16)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        match self.kind {
            BackupCaptureFileKind::Index => String::from("index"),
            BackupCaptureFileKind::Segment => format!("{segment}.segment"),
            BackupCaptureFileKind::SegmentFrontier => format!("{segment}.frontier"),
            _ => io::file_name(self.identity),
        }
    }
    pub const fn checksum(self) -> [u8; 32] {
        self.checksum
    }
    pub const fn size(self) -> u64 {
        self.size
    }
    pub(crate) fn new(
        kind: BackupCaptureFileKind,
        address: [u8; 32],
        size: u64,
    ) -> Result<Self, CatalogFailure> {
        if address == [0; 32] || size == 0 {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let mut hash = Sha256::new();
        hash.update(b"positron-backup-logical-file-v1\0");
        hash.update([kind.code()]);
        hash.update(address);
        Ok(Self {
            identity: hash.finalize().into(),
            kind,
            address,
            size,
            checksum: [0; 32],
        })
    }
}
/// A Governance-sanitized Catalog object retaining its original authenticated
/// address. The original set must equal the pinned generation's complete set.
pub struct BackupCatalogObject {
    original: CatalogObjectId,
    object: CatalogObject,
}
impl BackupCatalogObject {
    pub const fn original_identity(&self) -> CatalogObjectId {
        self.original
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.object.plaintext
    }
    pub fn new(original: CatalogObjectId, object: CatalogObject) -> Self {
        Self { original, object }
    }
}
/// Private captured ciphertext is independent of
/// later live Catalog publication and physical retention reclamation.
pub struct BackupCapture {
    directory: File,
    operation: [u8; 16],
    request: [u8; 32],
    generation: u64,
    catalog: [u8; 32],
    epoch: FormatEpoch,
    audit: u64,
    files: Vec<BackupCaptureFile>,
}
impl std::fmt::Debug for BackupCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupCapture")
            .field("generation", &self.generation)
            .field("files", &self.files.len())
            .finish()
    }
}
impl BackupCapture {
    /// Heap retained by the authenticated file inventory while Repository I/O runs.
    pub fn retained_memory_bytes(&self) -> Result<u64, CatalogFailure> {
        self.files
            .capacity()
            .checked_mul(std::mem::size_of::<BackupCaptureFile>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
    }

    /// Bounded operation-owned presence inspection without reopening Catalog.
    pub fn exists(
        authority: &crate::StorageKernelResourceAuthority,
        operation: [u8; 16],
    ) -> Result<bool, CatalogFailure> {
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| fail(CatalogFailureCode::ResourceAdmissionRefused))?;
        io::capture_exists(&volume._root, operation)
    }

    pub const fn catalog_generation(&self) -> u64 {
        self.generation
    }
    pub const fn catalog_identity(&self) -> [u8; 32] {
        self.catalog
    }
    pub const fn format_epoch(&self) -> FormatEpoch {
        self.epoch
    }
    pub const fn audit_frontier(&self) -> u64 {
        self.audit
    }
    pub fn files(&self) -> &[BackupCaptureFile] {
        &self.files
    }
    pub fn read(
        &self,
        identity: [u8; 32],
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, CatalogFailure> {
        if length > 4 * 1024 * 1024 {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let descriptor = self
            .files
            .iter()
            .find(|file| file.identity == identity)
            .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?;
        if offset
            .checked_add(length)
            .is_none_or(|end| end > descriptor.size)
        {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let mut file = io::open(&self.directory, &descriptor.storage_name())?;
        if file.metadata().map_err(io::error)?.len() != descriptor.size {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        file.seek(SeekFrom::Start(offset)).map_err(io::error)?;
        let mut bytes = vec![0; length as usize];
        file.read_exact(&mut bytes).map_err(io::error)?;
        Ok(bytes)
    }
}
impl Catalog<'_> {
    /// Current private captures retain wrapping references until exact cleanup.
    pub fn has_backup_capture_references(&self) -> Result<bool, CatalogFailure> {
        io::has_captures(&self.export_output_root()?)
    }
    pub fn backup_capture_registry_checkpoint(
        &self,
        capture: &BackupCapture,
    ) -> Result<Vec<u8>, CatalogFailure> {
        let bytes = io::read(&capture.directory, "registry", 4 * 1024 * 1024 + 48 + 315)?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let plaintext = storage::artifact::open_backup_capture(
            &secret,
            self.instance,
            codec::registry_identity(capture.operation, capture.request),
            capture.epoch,
            &bytes,
        )?;
        if plaintext.get(..8) != Some(b"POSBCR01")
            || plaintext.get(8..16) != Some(capture.generation.to_be_bytes().as_slice())
            || plaintext.get(16..48) != Some(capture.catalog.as_slice())
        {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        plaintext
            .get(48..)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))
    }
    /// Deletes at most 32 private files. Failed deletion preserves the managed
    /// reference; callers retain cleanup work until this returns true.
    pub fn release_backup_capture(
        &self,
        operation: [u8; 16],
        request: [u8; 32],
    ) -> Result<bool, CatalogFailure> {
        let root = self.export_output_root()?;
        if !io::capture_exists(&root, operation)? {
            return Ok(true);
        }
        let directory = io::capture_directory(&root, operation, false)?;
        if io::exists(&directory, "index")? {
            self.open_backup_capture(operation, request)?;
        }
        io::release(&root, operation)
    }
    /// Captures one fully rolled Catalog state under the existing admitted
    /// Maintenance grant. The Runtime Catalog gate spans rolling and this call.
    pub fn prepare_backup_capture(
        &self,
        execution: &MaintenanceExecution<'_>,
        operation: [u8; 16],
        request: [u8; 32],
        basis: &CatalogSnapshot,
        sanitized: &[BackupCatalogObject],
        custody: BackupCaptureCustody,
    ) -> Result<BackupCapturePreparation, CatalogFailure> {
        if operation == [0; 16]
            || request == [0; 32]
            || execution.task().class() != MaintenanceTaskClass::BackupSnapshot
            || sanitized.len() != basis.object_count()
            || custody.instance != self.instance
        {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let grant = execution.reservation().granted();
        let metadata_bytes = sanitized.iter().try_fold(0u64, |sum, object| {
            sum.checked_add(object.object.plaintext_len() as u64)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        let state = self
            .state
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        if state.current.identity() != basis.identity() {
            return Err(fail(CatalogFailureCode::StaleGeneration));
        }
        let audit_bytes = state.audit.iter().try_fold(0u64, |sum, record| {
            sum.checked_add(record.intent().len() as u64 + 102)
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        let checkpoint_bytes = state
            .audit_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.encode().len() as u64);
        let metadata_count = sanitized
            .len()
            .checked_add(state.audit.len())
            .and_then(|count| count.checked_add(usize::from(state.audit_checkpoint.is_some())))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let registry_bytes = custody
            .registry
            .as_ref()
            .map_or(0, |bytes| bytes.len() as u64 + 48);
        let plaintext = metadata_bytes
            .checked_add(audit_bytes)
            .and_then(|bytes| bytes.checked_add(checkpoint_bytes))
            .and_then(|bytes| bytes.checked_add(registry_bytes))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let estimated_files = metadata_count
            .checked_add(
                basis
                    .object_count()
                    .checked_mul(2)
                    .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?,
            )
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        let required_memory = plaintext
            .checked_mul(2)
            .and_then(|bytes| {
                bytes.checked_add((112 + estimated_files as u64 * 105) * 6 + 4 * 1024 * 1024)
            })
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        if grant.get(ResourceDimension::MemoryBytes) < required_memory
            || grant.get(ResourceDimension::FileDescriptors) < 4
        {
            return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
        }
        let epoch = basis
            .format_epoch()
            .ok_or_else(|| fail(CatalogFailureCode::UnsupportedFormat))?;
        let held = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let binding = codec::index_identity(operation, request);
        if !held.wrapping.same_route(&custody.secret.wrapping)
            || held.opaque_digest(b"backup-capture-custody", &binding)?
                != custody
                    .secret
                    .opaque_digest(b"backup-capture-custody", &binding)?
            || crate::data_protection::DataProtection::authenticate(&held.wrapping.key, &binding)
                .map_err(|_| fail(CatalogFailureCode::AuthenticationFailed))?
                != crate::data_protection::DataProtection::authenticate(
                    &custody.secret.wrapping.key,
                    &binding,
                )
                .map_err(|_| fail(CatalogFailureCode::AuthenticationFailed))?
        {
            return Err(fail(CatalogFailureCode::AuthenticationFailed));
        }
        drop(held);
        let originals = sanitized
            .iter()
            .map(|object| object.original)
            .collect::<std::collections::BTreeSet<_>>();
        if originals.len() != basis.object_count()
            || originals.iter().any(|original| {
                !basis
                    .object_identities()
                    .any(|identity| identity == *original)
            })
        {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let _barrier = self
            .authority
            .snapshot_barrier()
            .read()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let volume = self
            .authority
            .primary_data_volume()
            .ok_or_else(|| fail(CatalogFailureCode::ResourceAdmissionRefused))?;
        let (sources, verification) = crate::active_segment_ledger::backup_segment_sources(
            volume,
            basis,
            custody.instance,
            custody.keys,
            grant
                .get(ResourceDimension::FileDescriptors)
                .saturating_sub(4),
        )?;
        let source_bytes = sources.iter().try_fold(0u64, |sum, (file, _)| {
            sum.checked_add(file.size())
                .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))
        })?;
        let count = metadata_count
            .checked_add(sources.len())
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        if count > MAX_CAPTURE_FILES {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let index_bytes = (112usize)
            .checked_add(
                count
                    .checked_mul(105)
                    .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?,
            )
            .and_then(|bytes| bytes.checked_add(327))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        if index_bytes > MAX_CAPTURE_INDEX_BYTES {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let disk = plaintext
            .checked_add(
                (metadata_count as u64 + u64::from(custody.registry.is_some()))
                    .checked_mul(315)
                    .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?,
            )
            .and_then(|bytes| bytes.checked_add(source_bytes))
            .and_then(|bytes| bytes.checked_add(index_bytes as u64))
            .ok_or_else(|| fail(CatalogFailureCode::LimitExceeded))?;
        if grant.get(ResourceDimension::DiskHeadroomBytes) < disk {
            return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
        }
        // No capture directories or file bytes exist before complete admission.
        let directory = io::capture_directory(&self.export_output_root()?, operation, true)?;
        if io::exists(&directory, "index")? {
            return self
                .open_backup_capture(operation, request)
                .map(BackupCapturePreparation::ready);
        }
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(metadata_count)
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        for object in sanitized {
            metadata.push((
                BackupCaptureFile::new(
                    BackupCaptureFileKind::CatalogObject,
                    object.original.to_bytes(),
                    object.object.plaintext_len() as u64 + 315,
                )?,
                object.object.plaintext.clone(),
            ));
        }
        for record in &state.audit {
            let plaintext = super::codec::encode_audit(record);
            metadata.push((
                BackupCaptureFile::new(
                    BackupCaptureFileKind::GovernanceAudit,
                    record.record_hash(),
                    plaintext.len() as u64 + 315,
                )?,
                plaintext,
            ));
        }
        if let Some(checkpoint) = &state.audit_checkpoint {
            let plaintext = checkpoint.encode();
            metadata.push((
                BackupCaptureFile::new(
                    BackupCaptureFileKind::AuditCheckpoint,
                    checkpoint.record_hash(),
                    plaintext.len() as u64 + 315,
                )?,
                plaintext,
            ));
        }
        drop(state);
        let mut files = Vec::new();
        files
            .try_reserve_exact(count)
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        files.extend(metadata.iter().map(|(file, _)| *file));
        files.extend(sources.iter().map(|(file, _)| *file));
        files.sort_by_key(|file| file.identity);
        let capture = BackupCapture {
            directory,
            operation,
            request,
            generation: basis.number(),
            catalog: basis.identity().to_bytes(),
            epoch,
            audit: basis.governance_audit_frontier(),
            files,
        };
        Ok(BackupCapturePreparation::pending(
            capture,
            metadata,
            sources,
            custody.secret,
            verification,
            custody.registry,
        ))
    }
    pub fn open_backup_capture(
        &self,
        operation: [u8; 16],
        request: [u8; 32],
    ) -> Result<BackupCapture, CatalogFailure> {
        let directory = io::capture_directory(&self.export_output_root()?, operation, false)?;
        let bytes = io::read(&directory, "index", MAX_CAPTURE_INDEX_BYTES)?;
        if bytes.get(..8) != Some(b"POSBCI01") {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let epoch = FormatEpoch::new(u32::from_be_bytes(
            bytes
                .get(8..12)
                .and_then(|field| field.try_into().ok())
                .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?,
        ))?;
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let plaintext = storage::artifact::open_backup_capture(
            &secret,
            self.instance,
            codec::index_identity(operation, request),
            epoch,
            bytes
                .get(12..)
                .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?,
        )?;
        let mut capture = BackupCapture::decode(directory, &plaintext, operation, request, epoch)?;
        capture.add_index(bytes.len() as u64, Sha256::digest(&bytes).into())?;
        Ok(capture)
    }
    pub fn resume_backup_capture(
        &self,
        operation: [u8; 16],
        request: [u8; 32],
    ) -> Result<Option<BackupCapture>, CatalogFailure> {
        let root = self.export_output_root()?;
        if !io::capture_exists(&root, operation)? {
            return Ok(None);
        }
        let directory = io::capture_directory(&root, operation, false)?;
        if !io::exists(&directory, "index")? {
            return Ok(None);
        }
        self.open_backup_capture(operation, request).map(Some)
    }
}
fn fail(code: CatalogFailureCode) -> CatalogFailure {
    CatalogFailure::new(code)
}
