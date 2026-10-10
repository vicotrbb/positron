//! Source binding for the existing envelope-verification checkpoint owner.
use super::{MaintenanceTask, MaintenanceTaskClass, decode_record, record};
use crate::data_protection::DataProtection;
use crate::{CatalogFailure, CatalogFailureCode, CatalogSnapshot};

impl CatalogSnapshot {
    /// Binds every authenticated object except this exact handler's own durable
    /// record. The immutable task contract must match; another record, unknown
    /// reference, or source mutation is never excluded. Callers admit inspection
    /// before parsing and pin this exact basis through checkpoint publication.
    pub fn envelope_verification_source_identity(
        &self,
        instance: crate::InstanceId,
        task: &MaintenanceTask,
    ) -> Result<[u8; 32], CatalogFailure> {
        if task.class != MaintenanceTaskClass::EnvelopeVerification
            || task.scope.tenant_id().is_none()
            || !task.inputs.is_empty()
            || !task.outputs.is_empty()
            || task.integrity_scrub_source.is_some()
        {
            return Err(CatalogFailure::new(CatalogFailureCode::InvalidInput));
        }
        let mut digest = DataProtection::begin_hash()
            .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
        digest.update(b"Positron EnvelopeVerification source v1");
        digest.update(&instance.to_bytes());
        digest.update(
            &self
                .format_epoch()
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?
                .value()
                .to_be_bytes(),
        );
        digest.update(&task.identity.to_bytes());
        digest.update(
            &task
                .scope
                .tenant_id()
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::InvalidInput))?
                .to_bytes(),
        );
        digest.update(&task.preconditions.catalog_generation.to_be_bytes());
        digest.update(&task.preconditions.resource_generation.to_be_bytes());
        let mut found = false;
        for identity in self.object_identities() {
            let bytes = self
                .object(identity)?
                .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
            if record::record_identity(bytes)
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?
                == Some(task.identity)
            {
                let state = decode_record(bytes)
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
                if found || state.task != *task {
                    return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
                }
                found = true;
            } else {
                digest.update(&identity.to_bytes());
            }
        }
        if !found {
            return Err(CatalogFailure::new(CatalogFailureCode::IntegrityCorruption));
        }
        Ok(digest.finalize())
    }
}
