use super::*;
pub(super) fn registry_identity(operation: [u8; 16], request: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron-backup-capture-registry-v1\0");
    hash.update(operation);
    hash.update(request);
    hash.finalize().into()
}
pub(super) fn index_identity(operation: [u8; 16], request: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron-backup-capture-index-v1\0");
    hash.update(operation);
    hash.update(request);
    hash.finalize().into()
}
struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CatalogFailure> {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CatalogFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| fail(CatalogFailureCode::IntegrityCorruption))
    }
    fn u64(&mut self) -> Result<u64, CatalogFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}
impl BackupCapture {
    pub(super) fn add_index(
        &mut self,
        size: u64,
        checksum: [u8; 32],
    ) -> Result<(), CatalogFailure> {
        let mut descriptor = BackupCaptureFile::new(
            BackupCaptureFileKind::Index,
            index_identity(self.operation, self.request),
            size,
        )?;
        descriptor.checksum = checksum;
        self.files.push(descriptor);
        self.files.sort_by_key(|file| file.identity);
        Ok(())
    }
    pub fn index_file(&self) -> Result<BackupCaptureFile, CatalogFailure> {
        self.files
            .iter()
            .find(|file| file.kind == BackupCaptureFileKind::Index)
            .copied()
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, CatalogFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(112 + 105 * self.files.len())
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        bytes.extend_from_slice(b"POSBCP01");
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.request);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.catalog);
        bytes.extend_from_slice(&self.epoch.value().to_be_bytes());
        bytes.extend_from_slice(&self.audit.to_be_bytes());
        bytes.extend_from_slice(&(self.files.len() as u32).to_be_bytes());
        for file in &self.files {
            bytes.extend_from_slice(&file.identity);
            bytes.push(file.kind.code());
            bytes.extend_from_slice(&file.address);
            bytes.extend_from_slice(&file.size.to_be_bytes());
            bytes.extend_from_slice(&file.checksum);
        }
        if bytes.len() > MAX_CAPTURE_INDEX_BYTES - 512 {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        Ok(bytes)
    }
    pub(super) fn decode(
        directory: File,
        bytes: &[u8],
        operation: [u8; 16],
        request: [u8; 32],
        epoch: FormatEpoch,
    ) -> Result<Self, CatalogFailure> {
        let mut decoder = Decoder(bytes);
        if decoder.take(8)? != b"POSBCP01"
            || decoder.array::<16>()? != operation
            || decoder.array::<32>()? != request
        {
            return Err(fail(CatalogFailureCode::AuthenticationFailed));
        }
        let generation = decoder.u64()?;
        let catalog = decoder.array()?;
        let encoded_epoch = u32::from_be_bytes(decoder.array()?);
        let audit = decoder.u64()?;
        if generation == 0 || catalog == [0; 32] || encoded_epoch != epoch.value() {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        let count = u32::from_be_bytes(decoder.array()?) as usize;
        if count > MAX_CAPTURE_FILES {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        let mut files = Vec::new();
        files
            .try_reserve_exact(count)
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        for _ in 0..count {
            let identity = decoder.array()?;
            let kind = match decoder.take(1)? {
                [1] => BackupCaptureFileKind::CatalogObject,
                [2] => BackupCaptureFileKind::GovernanceAudit,
                [3] => BackupCaptureFileKind::Segment,
                [5] => BackupCaptureFileKind::AuditCheckpoint,
                [6] => BackupCaptureFileKind::SegmentFrontier,
                _ => return Err(fail(CatalogFailureCode::IntegrityCorruption)),
            };
            let mut file = BackupCaptureFile::new(kind, decoder.array()?, decoder.u64()?)?;
            file.checksum = decoder.array()?;
            if file.checksum == [0; 32] {
                return Err(fail(CatalogFailureCode::IntegrityCorruption));
            }
            if file.identity != identity
                || files
                    .last()
                    .is_some_and(|last: &BackupCaptureFile| last.identity >= identity)
            {
                return Err(fail(CatalogFailureCode::IntegrityCorruption));
            }
            files.push(file);
        }
        if !decoder.0.is_empty() {
            return Err(fail(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(Self {
            directory,
            operation,
            request,
            generation,
            catalog,
            epoch,
            audit,
            files,
        })
    }
}
