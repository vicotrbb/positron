//! Immutable continuation artifacts remain subordinate to Maintenance publication.
use super::*;
use crate::{
    MaintenanceCoordinator, MaintenanceExecution, RepositoryOperationBinding, ResourceAmounts,
    ResourceDimension,
};
use zeroize::Zeroizing;

/// Both verification ownership and the immutable source are authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupVerificationBinding {
    pub operation: [u8; 16],
    pub intent: [u8; 32],
    pub capture_operation: [u8; 16],
    pub capture_request: [u8; 32],
    pub manifest: [u8; 32],
    pub index: [u8; 32],
    pub registry: [u8; 32],
}

/// Only this small authenticated reference enters the existing checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupVerificationReference {
    pub identity: [u8; 32],
    pub sequence: u64,
    pub predecessor: [u8; 32],
}

impl BackupVerificationBinding {
    fn bytes(self) -> Result<Vec<u8>, CatalogFailure> {
        if self.operation == self.capture_operation
            || self.operation == [0; 16]
            || self.capture_operation == [0; 16]
            || [
                self.intent,
                self.capture_request,
                self.manifest,
                self.index,
                self.registry,
            ]
            .contains(&[0; 32])
        {
            return Err(fail(CatalogFailureCode::InvalidInput));
        }
        let mut bytes = b"POSBVB01".to_vec();
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.intent);
        bytes.extend_from_slice(&self.capture_operation);
        for value in [
            self.capture_request,
            self.manifest,
            self.index,
            self.registry,
        ] {
            bytes.extend_from_slice(&value);
        }
        Ok(bytes)
    }
    fn owner_identity(self) -> Result<[u8; 32], CatalogFailure> {
        let owner =
            RepositoryOperationBinding::new(self.operation, self.intent).map_err(|_| corrupt())?;
        Ok(owner_identity(owner))
    }
}

const BINDING_BYTES: usize = 200;
const STATE_PREFIX_BYTES: usize = BINDING_BYTES + 8 + 32;
const PROTECTION_BYTES: usize = crate::catalog::storage::artifact::BACKUP_CAPTURE_OVERHEAD_BYTES;

fn continuation_resources(
    state_bytes: usize,
    native: u64,
    index_bytes: usize,
) -> Result<ResourceAmounts, CatalogFailure> {
    if index_bytes > MAX_CAPTURE_INDEX_BYTES || state_bytes > MAX_STATE_BYTES {
        return Err(corrupt());
    }
    let inventory = (index_bytes / 105)
        .checked_mul(2 * std::mem::size_of::<BackupCaptureFile>())
        .ok_or_else(corrupt)?;
    let index_peak = index_bytes
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(inventory))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<BackupCaptureVerification>()))
        .ok_or_else(corrupt)?;
    let protected = state_bytes
        .checked_add(STATE_PREFIX_BYTES)
        .and_then(|bytes| bytes.checked_add(PROTECTION_BYTES))
        .ok_or_else(corrupt)?;
    let memory = u64::try_from(protected)
        .map_err(|_| corrupt())?
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(native))
        .and_then(|bytes| bytes.checked_add(index_peak as u64))
        .ok_or_else(corrupt)?;
    let disk = u64::try_from(protected)
        .map_err(|_| corrupt())?
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add((BINDING_BYTES + PROTECTION_BYTES) as u64))
        .ok_or_else(corrupt)?;
    Ok(ResourceAmounts::new([
        memory, 0, 0, 0, 0, 0, 0, 0, 0, 0, disk,
    ]))
}

impl BackupVerificationProgress {
    /// Allocation-free bound covers retained native state, signed-index opening and codec/AEAD copies.
    pub fn continuation_resources(&self, index: &[u8]) -> Result<ResourceAmounts, CatalogFailure> {
        let length = self.encoded_length()?;
        let native = match &self.native {
            BackupVerificationNativeState::Metadata(state) => state.prospective_memory_bytes()?,
            BackupVerificationNativeState::Catalog(snapshot) => {
                Self::catalog_memory(snapshot.object_count(), length)?
            },
        };
        continuation_resources(length, native, index.len())
    }
}

impl Catalog<'_> {
    /// Writes and syncs a proposal; it is progress only after its checkpoint commits.
    pub fn persist_backup_verification_continuation(
        &self,
        coordinator: &MaintenanceCoordinator,
        execution: &mut MaintenanceExecution<'_>,
        binding: BackupVerificationBinding,
        predecessor: Option<BackupVerificationReference>,
        index: &[u8],
        progress: &BackupVerificationProgress,
    ) -> Result<BackupVerificationReference, CatalogFailure> {
        let owner = RepositoryOperationBinding::from_execution(execution)
            .map_err(|_| fail(CatalogFailureCode::InvalidInput))?;
        if owner.operation_id() != binding.operation || owner.intent_digest() != binding.intent {
            return Err(corrupt());
        }
        let authoritative = owner
            .current_backup_verification_reference(coordinator, execution)
            .map_err(|_| fail(CatalogFailureCode::InvalidInput))?;
        if authoritative != predecessor {
            return Err(corrupt());
        }
        let resources = progress.continuation_resources(index)?;
        for dimension in [
            ResourceDimension::MemoryBytes,
            ResourceDimension::DiskHeadroomBytes,
        ] {
            if execution.task().reservations().get(dimension) < resources.get(dimension) {
                return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
            }
        }
        if index.len() > MAX_CAPTURE_INDEX_BYTES
            || <[u8; 32]>::from(Sha256::digest(index)) != binding.index
        {
            return Err(corrupt());
        }
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let base = BackupCaptureVerification::open(
            self.instance,
            &secret,
            binding.capture_operation,
            binding.capture_request,
            index,
        )?;
        progress.validate_source(&base)?;
        drop(base);
        let sequence = predecessor
            .map_or(Some(1), |value| value.sequence.checked_add(1))
            .ok_or_else(corrupt)?;
        let previous = predecessor.map_or([0; 32], |value| value.identity);
        let mut plaintext = Zeroizing::new(binding.bytes()?);
        let encoded_state = Zeroizing::new(progress.encode()?);
        plaintext
            .try_reserve_exact(
                40usize
                    .checked_add(encoded_state.len())
                    .ok_or_else(corrupt)?,
            )
            .map_err(|_| fail(CatalogFailureCode::LimitExceeded))?;
        plaintext.extend_from_slice(&sequence.to_be_bytes());
        plaintext.extend_from_slice(&previous);
        plaintext.extend_from_slice(&encoded_state);
        let identity: [u8; 32] = Sha256::digest(&plaintext).into();
        let root = self.export_output_root()?;
        let directory = super::super::super::io::capture_directory(&root, binding.operation, true)?;
        let owner_identity = binding.owner_identity()?;
        if !super::super::super::io::exists(&directory, "index")? {
            if authoritative.is_some() {
                return Err(corrupt());
            }
            if !super::super::super::io::clear_incomplete(&directory)? {
                return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
            }
            let index = crate::catalog::storage::artifact::protect_backup_capture(
                &secret,
                self.instance,
                owner_identity,
                FormatEpoch::CATALOG_V2,
                &binding.bytes()?,
            )?;
            super::super::super::io::publish_index(&directory, &index)?;
        }
        authenticate_owner(&directory, &secret, self.instance, binding)?;
        if let Some(previous) = predecessor {
            if previous.identity == [0; 32] || previous.sequence == 0 {
                return Err(corrupt());
            }
            let file = super::super::super::io::open(
                &directory,
                &super::super::super::io::file_name(previous.identity),
            )?;
            let prior_bytes = file
                .metadata()
                .map_err(super::super::super::io::error)?
                .len();
            let current_bytes = u64::try_from(plaintext.len())
                .map_err(|_| corrupt())?
                .checked_add(PROTECTION_BYTES as u64)
                .ok_or_else(corrupt)?;
            let disk = prior_bytes
                .checked_add(current_bytes.checked_mul(2).ok_or_else(corrupt)?)
                .and_then(|bytes| bytes.checked_add((BINDING_BYTES + PROTECTION_BYTES) as u64))
                .ok_or_else(corrupt)?;
            if execution
                .task()
                .reservations()
                .get(ResourceDimension::DiskHeadroomBytes)
                < disk
            {
                return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
            }
        }
        if !super::super::super::io::retain_verification_generations(
            &directory,
            predecessor.map(|value| value.identity),
            identity,
        )? {
            return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
        }
        let name = super::super::super::io::file_name(identity);
        let mut reusable = false;
        if super::super::super::io::exists(&directory, &name)? {
            let existing = (|| {
                let encoded =
                    super::super::super::io::read(&directory, &name, MAX_STATE_BYTES + 1024)?;
                crate::catalog::storage::artifact::open_backup_capture(
                    &secret,
                    self.instance,
                    identity,
                    FormatEpoch::CATALOG_V2,
                    &encoded,
                )
                .map(Zeroizing::new)
            })();
            match existing {
                Ok(old) => {
                    if old.as_slice() != plaintext.as_slice() {
                        return Err(corrupt());
                    }
                    reusable = true;
                },
                Err(failure) => {
                    if authoritative.is_some_and(|current| current.identity == identity) {
                        return Err(failure);
                    }
                    super::super::super::io::discard_unpublished_verification_file(
                        &directory, identity,
                    )?;
                },
            }
        }
        if !reusable {
            let encoded = crate::catalog::storage::artifact::protect_backup_capture(
                &secret,
                self.instance,
                identity,
                FormatEpoch::CATALOG_V2,
                &plaintext,
            )?;
            super::super::super::io::write(&directory, &name, &encoded)?;
        }
        Ok(BackupVerificationReference {
            identity,
            sequence,
            predecessor: previous,
        })
    }

    /// Restores only the exact artifact referenced by authenticated Maintenance.
    pub fn resume_backup_verification_continuation(
        &self,
        binding: BackupVerificationBinding,
        reference: BackupVerificationReference,
        index: &[u8],
        admitted: ResourceAmounts,
    ) -> Result<BackupVerificationProgress, CatalogFailure> {
        if reference.sequence == 0
            || reference.identity == [0; 32]
            || Sha256::digest(index).as_slice() != binding.index
        {
            return Err(corrupt());
        }
        let secret = self
            .secret
            .lock()
            .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
        let directory = super::super::super::io::capture_directory(
            &self.export_output_root()?,
            binding.operation,
            false,
        )?;
        authenticate_owner(&directory, &secret, self.instance, binding)?;
        let name = super::super::super::io::file_name(reference.identity);
        let file = super::super::super::io::open(&directory, &name)?;
        let length = file
            .metadata()
            .map_err(super::super::super::io::error)?
            .len();
        let state_bytes = usize::try_from(length)
            .ok()
            .and_then(|bytes| bytes.checked_sub(STATE_PREFIX_BYTES + PROTECTION_BYTES))
            .ok_or_else(corrupt)?;
        let opening = continuation_resources(state_bytes, 0, index.len())?;
        if admitted.get(ResourceDimension::MemoryBytes)
            < opening.get(ResourceDimension::MemoryBytes)
        {
            return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
        }
        drop(file);
        let encoded = super::super::super::io::read(&directory, &name, MAX_STATE_BYTES + 1024)?;
        let plaintext = Zeroizing::new(crate::catalog::storage::artifact::open_backup_capture(
            &secret,
            self.instance,
            reference.identity,
            FormatEpoch::CATALOG_V2,
            &encoded,
        )?);
        if <[u8; 32]>::from(Sha256::digest(&plaintext)) != reference.identity {
            return Err(corrupt());
        }
        let mut input = Reader(&plaintext);
        if input.take(binding.bytes()?.len())? != binding.bytes()?
            || u64::from_be_bytes(input.array()?) != reference.sequence
            || input.array::<32>()? != reference.predecessor
        {
            return Err(corrupt());
        }
        let base = BackupCaptureVerification::open(
            self.instance,
            &secret,
            binding.capture_operation,
            binding.capture_request,
            index,
        )?;
        let native = BackupVerificationProgress::native_decode_memory(input.0, &base)?;
        let required = continuation_resources(input.0.len(), native, index.len())?;
        if admitted.get(ResourceDimension::MemoryBytes)
            < required.get(ResourceDimension::MemoryBytes)
        {
            return Err(fail(CatalogFailureCode::ResourceAdmissionRefused));
        }
        let restored = BackupVerificationProgress::decode(input.0, base)?;
        Ok(restored)
    }
}

fn owner_identity(owner: RepositoryOperationBinding) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"positron-backup-verification-owner-v1\0");
    hash.update(owner.operation_id());
    hash.update(owner.intent_digest());
    hash.finalize().into()
}

fn read_owner(
    directory: &File,
    secret: &CatalogSecret,
    instance: InstanceId,
    owner: RepositoryOperationBinding,
) -> Result<BackupVerificationBinding, CatalogFailure> {
    let encoded =
        super::super::super::io::read(directory, "index", BINDING_BYTES + PROTECTION_BYTES)?;
    let plaintext = Zeroizing::new(crate::catalog::storage::artifact::open_backup_capture(
        secret,
        instance,
        owner_identity(owner),
        FormatEpoch::CATALOG_V2,
        &encoded,
    )?);
    let mut input = Reader(&plaintext);
    if input.take(8)? != b"POSBVB01" {
        return Err(corrupt());
    }
    let binding = BackupVerificationBinding {
        operation: input.array()?,
        intent: input.array()?,
        capture_operation: input.array()?,
        capture_request: input.array()?,
        manifest: input.array()?,
        index: input.array()?,
        registry: input.array()?,
    };
    if !input.0.is_empty()
        || binding.operation != owner.operation_id()
        || binding.intent != owner.intent_digest()
    {
        return Err(corrupt());
    }
    binding.bytes()?;
    Ok(binding)
}

fn authenticate_owner(
    directory: &File,
    secret: &CatalogSecret,
    instance: InstanceId,
    binding: BackupVerificationBinding,
) -> Result<(), CatalogFailure> {
    let owner = RepositoryOperationBinding::new(binding.operation, binding.intent)
        .map_err(|_| corrupt())?;
    if read_owner(directory, secret, instance, owner)? != binding {
        return Err(corrupt());
    }
    Ok(())
}

impl Catalog<'_> {
    /// Terminal cleanup retains the wrapping-key fence until the last private
    /// file and its exact authenticated owner directory have been removed.
    pub fn release_backup_verification_continuation(
        &self,
        coordinator: &MaintenanceCoordinator,
        execution: &mut MaintenanceExecution<'_>,
        owner: RepositoryOperationBinding,
    ) -> Result<bool, CatalogFailure> {
        if RepositoryOperationBinding::from_execution(execution).map_err(|_| corrupt())? != owner
            || owner
                .current_backup_verification_reference(coordinator, execution)
                .map_err(|_| corrupt())?
                .is_some()
        {
            return Err(corrupt());
        }
        let root = self.export_output_root()?;
        if !super::super::super::io::capture_exists(&root, owner.operation_id())? {
            return Ok(true);
        }
        let directory =
            super::super::super::io::capture_directory(&root, owner.operation_id(), false)?;
        if super::super::super::io::exists(&directory, "index")? {
            let secret = self
                .secret
                .lock()
                .map_err(|_| fail(CatalogFailureCode::ConcurrentWriter))?;
            read_owner(&directory, &secret, self.instance, owner)?;
        }
        super::super::super::io::release(&root, owner.operation_id())
    }
}
