use std::collections::BTreeMap;
use std::fmt::{Formatter, Result as FormatResult};
use std::sync::Arc;

use super::{
    CatalogFailure, CatalogFailureCode, CatalogGenerationId, CatalogObjectId, FormatEpoch,
};

#[derive(Clone)]
pub struct CatalogSnapshot(pub(in crate::catalog) Arc<SnapshotData>);

pub(in crate::catalog) struct SnapshotData {
    pub(in crate::catalog) identity: CatalogGenerationId,
    pub(in crate::catalog) number: u64,
    pub(in crate::catalog) format_epoch: Option<FormatEpoch>,
    pub(in crate::catalog) objects: BTreeMap<CatalogObjectId, Arc<[u8]>>,
    pub(in crate::catalog) audit_frontier: AuditFrontier,
}

impl CatalogSnapshot {
    pub(in crate::catalog) fn origin() -> Self {
        Self(Arc::new(SnapshotData {
            identity: CatalogGenerationId::ORIGIN,
            number: 0,
            format_epoch: None,
            objects: BTreeMap::new(),
            audit_frontier: AuditFrontier::ORIGIN,
        }))
    }

    #[must_use]
    pub fn identity(&self) -> CatalogGenerationId {
        self.0.identity
    }
    #[must_use]
    pub fn number(&self) -> u64 {
        self.0.number
    }
    #[must_use]
    pub fn format_epoch(&self) -> Option<FormatEpoch> {
        self.0.format_epoch
    }
    pub fn object(&self, identity: CatalogObjectId) -> Result<Option<&[u8]>, CatalogFailure> {
        Ok(self.0.objects.get(&identity).map(AsRef::as_ref))
    }

    /// Compares two authenticated catalog states while excluding one exact
    /// maintenance task record. An online operation may advance only its own
    /// durable coordinator record around an immutable observation; every
    /// other object remains part of its pinned authority.
    pub fn same_except_maintenance_task(
        &self,
        successor: &Self,
        task: crate::MaintenanceTaskId,
    ) -> Result<bool, CatalogFailure> {
        self.same_except_maintenance_tasks(successor, &[task])
    }

    /// Compares two authenticated Catalog states while excluding only the
    /// supplied durable maintenance records. Callers derive this bounded
    /// allowlist from their authenticated operation lineage; every other
    /// record, including foreign maintenance work and non-maintenance
    /// authority, remains part of the compare-and-swap basis.
    pub fn same_except_maintenance_tasks(
        &self,
        successor: &Self,
        permitted_tasks: &[crate::MaintenanceTaskId],
    ) -> Result<bool, CatalogFailure> {
        fn retained<'snapshot>(
            snapshot: &'snapshot CatalogSnapshot,
            permitted_tasks: &[crate::MaintenanceTaskId],
        ) -> Result<Vec<(CatalogObjectId, &'snapshot [u8])>, CatalogFailure> {
            let mut objects = Vec::new();
            objects
                .try_reserve(snapshot.0.objects.len())
                .map_err(|_| CatalogFailure::new(CatalogFailureCode::LimitExceeded))?;
            for (identity, object) in &snapshot.0.objects {
                let record = crate::maintenance::durable_task_record_identity(object)
                    .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
                if !record.is_some_and(|record| permitted_tasks.contains(&record)) {
                    objects.push((*identity, object.as_ref()));
                }
            }
            Ok(objects)
        }

        Ok(retained(self, permitted_tasks)? == retained(successor, permitted_tasks)?)
    }
    pub(crate) fn plaintext_objects(&self) -> impl Iterator<Item = &[u8]> {
        self.0.objects.values().map(AsRef::as_ref)
    }
    pub(crate) fn plaintext_object_count(&self) -> usize {
        self.0.objects.len()
    }
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.0.objects.len()
    }
    #[must_use]
    pub fn governance_audit_frontier(&self) -> u64 {
        self.0.audit_frontier.position
    }
}

impl std::fmt::Debug for CatalogSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FormatResult {
        formatter
            .debug_struct("CatalogSnapshot")
            .field("identity", &self.0.identity)
            .field("number", &self.0.number)
            .field("format_epoch", &self.0.format_epoch)
            .field("object_count", &self.0.objects.len())
            .field("audit_frontier", &self.0.audit_frontier.position)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::catalog) struct AuditFrontier {
    pub(in crate::catalog) position: u64,
    pub(in crate::catalog) hash: [u8; 32],
}

impl AuditFrontier {
    pub(in crate::catalog) const ORIGIN: Self = Self {
        position: 0,
        hash: [0; 32],
    };
}
