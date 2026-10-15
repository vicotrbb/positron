//! Volatile admitted staging. No mutable Catalog authority leaves preparation.
use super::*;
use std::{
    collections::VecDeque,
    io::{Cursor, Write},
};
/// Narrow owned protection and tenant-segment capabilities from verified
/// bootstrap custody. Raw keys never become captured or uploaded objects.
pub struct BackupCaptureCustody {
    pub(super) instance: InstanceId,
    pub(super) secret: CatalogSecret,
    pub(super) keys: Vec<(crate::SegmentScope, crate::SegmentProtectionKey)>,
    pub(super) registry: Option<Vec<u8>>,
}
impl BackupCaptureCustody {
    pub fn new(
        instance: InstanceId,
        secret: CatalogSecret,
        keys: Vec<(crate::SegmentScope, crate::SegmentProtectionKey)>,
    ) -> Result<Self, CatalogFailure> {
        if keys.len() > 4096
            || keys.iter().enumerate().any(|(index, (scope, _))| {
                keys.get(..index)
                    .is_some_and(|prior| prior.iter().any(|(other, _)| other == scope))
            })
        {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        Ok(Self {
            instance,
            secret,
            keys,
            registry: None,
        })
    }
    /// Retains only protected Registry envelopes and their typed recovery
    /// context. This private checkpoint never enters the immutable upload set.
    pub fn with_registry_checkpoint(mut self, bytes: Vec<u8>) -> Result<Self, CatalogFailure> {
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err(fail(CatalogFailureCode::LimitExceeded));
        }
        self.registry = Some(bytes);
        Ok(self)
    }
}
impl std::fmt::Debug for BackupCaptureCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupCaptureCustody { <redacted> }")
    }
}
enum Input {
    Plaintext(Vec<u8>),
    Protected(Cursor<Vec<u8>>),
    Ciphertext(File),
}
struct Source {
    descriptor: BackupCaptureFile,
    input: Input,
    private: bool,
}
pub struct BackupCapturePreparation {
    capture: Option<BackupCapture>,
    sources: VecDeque<Source>,
    output: Option<File>,
    copied: u64,
    hash: Sha256,
    secret: Option<CatalogSecret>,
    verification: Option<crate::active_segment_ledger::BackupSegmentVerification>,
    staging_prepared: bool,
}
impl std::fmt::Debug for BackupCapturePreparation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupCapturePreparation")
            .field("remaining_files", &self.sources.len())
            .finish()
    }
}
impl BackupCapturePreparation {
    pub(super) fn ready(capture: BackupCapture) -> Self {
        Self {
            capture: Some(capture),
            sources: VecDeque::new(),
            output: None,
            copied: 0,
            hash: Sha256::new(),
            secret: None,
            verification: None,
            staging_prepared: true,
        }
    }
    pub(super) fn pending(
        capture: BackupCapture,
        metadata: Vec<(BackupCaptureFile, Vec<u8>)>,
        files: Vec<(BackupCaptureFile, File)>,
        secret: CatalogSecret,
        verification: crate::active_segment_ledger::BackupSegmentVerification,
        registry: Option<Vec<u8>>,
    ) -> Self {
        let mut sources: VecDeque<_> = metadata
            .into_iter()
            .map(|(descriptor, bytes)| Source {
                descriptor,
                input: Input::Plaintext(bytes),
                private: false,
            })
            .chain(files.into_iter().map(|(descriptor, file)| Source {
                descriptor,
                input: Input::Ciphertext(file),
                private: false,
            }))
            .collect();
        if let Some(bytes) = registry {
            let mut plaintext = b"POSBCR01".to_vec();
            plaintext.extend_from_slice(&capture.generation.to_be_bytes());
            plaintext.extend_from_slice(&capture.catalog);
            plaintext.extend_from_slice(&bytes);
            let address = codec::registry_identity(capture.operation, capture.request);
            sources.push_front(Source {
                descriptor: BackupCaptureFile {
                    identity: address,
                    kind: BackupCaptureFileKind::CatalogObject,
                    address,
                    size: plaintext.len() as u64 + 315,
                    checksum: [0; 32],
                },
                input: Input::Plaintext(plaintext),
                private: true,
            });
        }
        Self {
            capture: Some(capture),
            sources,
            output: None,
            copied: 0,
            hash: Sha256::new(),
            secret: Some(secret),
            verification: Some(verification),
            staging_prepared: false,
        }
    }
    /// Stages at most the byte budget and 32 files, or authenticates one bounded
    /// captured segment. All encryption, copies and file syncs occur outside
    /// the online Catalog gate. An error invalidates this volatile preparation.
    pub fn copy_step(&mut self, budget: u64) -> Result<Option<BackupCapture>, CatalogFailure> {
        let outcome = self.step(budget);
        if outcome.is_err() {
            self.capture = None;
            self.sources.clear();
            self.output = None;
            self.secret = None;
            self.verification = None;
        }
        outcome
    }
    fn step(&mut self, budget: u64) -> Result<Option<BackupCapture>, CatalogFailure> {
        if budget == 0 || budget > 4 * 1024 * 1024 {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let capture = self
            .capture
            .as_mut()
            .ok_or_else(|| fail(CatalogFailureCode::InvalidInput))?;
        if self.secret.is_none() {
            return Ok(self.capture.take());
        }
        if !self.staging_prepared {
            if !io::clear_incomplete(&capture.directory)? {
                return Ok(None);
            }
            self.staging_prepared = true;
        }
        let mut remaining = budget;
        let mut completed = 0;
        while remaining > 0 && completed < 32 {
            let Some(source) = self.sources.front_mut() else {
                break;
            };
            if let Input::Plaintext(plaintext) = &source.input {
                let secret = self
                    .secret
                    .as_ref()
                    .ok_or_else(|| fail(CatalogFailureCode::AuthenticationFailed))?;
                let protected = storage::artifact::protect_backup_capture(
                    secret,
                    self.verification
                        .as_ref()
                        .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?
                        .instance(),
                    source.descriptor.address,
                    capture.epoch,
                    plaintext,
                )?;
                if protected.len() as u64 != source.descriptor.size {
                    return Err(fail(CatalogFailureCode::IntegrityCorruption));
                }
                source.input = Input::Protected(Cursor::new(protected));
            }
            if self.output.is_none() {
                self.output = Some(
                    unix_fs::openat(
                        &capture.directory,
                        if source.private {
                            String::from("registry")
                        } else {
                            source.descriptor.storage_name()
                        },
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::RUSR | Mode::WUSR,
                    )
                    .map(File::from)
                    .map_err(|_| fail(CatalogFailureCode::StorageUnavailable))?,
                );
            }
            let amount = (source.descriptor.size - self.copied)
                .min(remaining)
                .min(65536);
            let mut buffer = vec![0; amount as usize];
            match &mut source.input {
                Input::Ciphertext(file) => file.read_exact(&mut buffer).map_err(io::error)?,
                Input::Protected(bytes) => bytes.read_exact(&mut buffer).map_err(io::error)?,
                Input::Plaintext(_) => return Err(fail(CatalogFailureCode::IntegrityCorruption)),
            }
            let output = self
                .output
                .as_mut()
                .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
            output.write_all(&buffer).map_err(io::error)?;
            self.hash.update(&buffer);
            self.copied += amount;
            remaining -= amount;
            if self.copied == source.descriptor.size {
                output.sync_all().map_err(io::error)?;
                let checksum = std::mem::replace(&mut self.hash, Sha256::new())
                    .finalize()
                    .into();
                if !source.private {
                    let descriptor = capture
                        .files
                        .iter_mut()
                        .find(|file| file.identity == source.descriptor.identity)
                        .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
                    descriptor.checksum = checksum;
                }
                self.output = None;
                self.sources.pop_front();
                self.copied = 0;
                completed += 1;
            }
        }
        if !self.sources.is_empty() {
            return Ok(None);
        }
        let verification = self
            .verification
            .as_mut()
            .ok_or_else(|| fail(CatalogFailureCode::IntegrityCorruption))?;
        if !verification.verify_next(&capture.directory)? {
            return Ok(None);
        }
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| fail(CatalogFailureCode::AuthenticationFailed))?;
        let plaintext = capture.encode()?;
        let index = storage::artifact::protect_backup_capture(
            secret,
            verification.instance(),
            codec::index_identity(capture.operation, capture.request),
            capture.epoch,
            &plaintext,
        )?;
        let mut frame = b"POSBCI01".to_vec();
        frame.extend_from_slice(&capture.epoch.value().to_be_bytes());
        frame.extend_from_slice(&index);
        io::publish_index(&capture.directory, &frame)?;
        capture.add_index(frame.len() as u64, Sha256::digest(&frame).into())?;
        self.secret = None;
        self.verification = None;
        Ok(self.capture.take())
    }
}
