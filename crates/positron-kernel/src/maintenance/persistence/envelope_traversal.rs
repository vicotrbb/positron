//! The admitted handler derives progress only from actual target-only traversal.
use super::super::*;
use crate::{
    ActiveSegmentLedger, Catalog, CatalogSnapshot, InstanceId, IntegrityCancellation,
    IntegrityScrubBudget, IntegrityVerificationOutcome, IntegrityVerificationRequest,
    SegmentProtectionKey, SegmentScope, TransactionId,
};

/// Publication identity and optional owning audit for an admitted traversal.
pub struct EnvelopeVerificationPublication {
    pub(super) epoch: u64,
    transaction: TransactionId,
    pub(super) audit: Option<crate::AuditIntent>,
}
impl EnvelopeVerificationPublication {
    pub fn new(epoch: u64, transaction: TransactionId, audit: Option<crate::AuditIntent>) -> Self {
        Self {
            epoch,
            transaction,
            audit,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeVerificationProgress {
    complete: bool,
    examined: usize,
}
impl EnvelopeVerificationProgress {
    pub const fn is_complete(self) -> bool {
        self.complete
    }
    pub const fn examined_segments(self) -> usize {
        self.examined
    }
}
struct Traversal {
    source: [u8; 32],
    scopes: Vec<SegmentScope>,
    current: Option<SegmentScope>,
    previous: Option<EnvelopeVerificationCheckpoint>,
}
impl MaintenanceExecution<'_> {
    fn envelope_traversal(
        &self,
        basis: &CatalogSnapshot,
        instance: InstanceId,
        epoch: u64,
    ) -> Result<Traversal, MaintenanceFailure> {
        if self.task.class != MaintenanceTaskClass::EnvelopeVerification
            || self.task.reservations != crate::integrity_scrub_resource_claim()
            || self.task.trigger != MaintenanceTrigger::Event
            || self.task.preconditions.resource_generation != 1
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let tenant = self
            .task
            .scope
            .tenant_id()
            .ok_or(MaintenanceFailure::InvalidInput)?;
        if self.task.scope != MaintenanceScope::tenant(tenant) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let source = basis
            .envelope_verification_source_identity(instance, &self.task)
            .map_err(|_| MaintenanceFailure::PreconditionFailed)?;
        let previous = self
            .checkpoint
            .as_ref()
            .map(|checkpoint| {
                EnvelopeVerificationCheckpoint::from_checkpoint(checkpoint, instance, tenant, epoch)
            })
            .transpose()?;
        if previous
            .is_some_and(|progress| progress.is_complete() || progress.source_identity() != source)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let mut scopes = Vec::new();
        for signal in [SignalKind::Logs, SignalKind::Traces] {
            let found = basis
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|_| MaintenanceFailure::CatalogUnavailable)?;
            scopes
                .try_reserve(found.len())
                .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
            scopes.extend(found);
        }
        let current = previous
            .and_then(|progress| progress.scope())
            .or_else(|| scopes.first().copied());
        if current.is_some_and(|scope| !scopes.contains(&scope)) {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(Traversal {
            source,
            scopes,
            current,
            previous,
        })
    }
    /// Selects the canonical scope under the execution's existing full grant.
    pub fn next_envelope_verification_scope(
        &self,
        basis: &CatalogSnapshot,
        instance: InstanceId,
        epoch: u64,
    ) -> Result<Option<SegmentScope>, MaintenanceFailure> {
        Ok(self.envelope_traversal(basis, instance, epoch)?.current)
    }
    /// Verifies at most one immutable segment using a capability with exactly
    /// the target epoch, then atomically persists derived progress. Caller bytes
    /// and success flags cannot supply a completed proof through this interface.
    pub fn verify_and_checkpoint_envelope_at_basis(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        basis: &CatalogSnapshot,
        protection: Option<SegmentProtectionKey>,
        publication: EnvelopeVerificationPublication,
    ) -> Result<EnvelopeVerificationProgress, MaintenanceFailure> {
        let epoch = publication.epoch;
        let traversal = self.envelope_traversal(basis, catalog.instance(), epoch)?;
        let tenant = self
            .task
            .scope
            .tenant_id()
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let mut examined = 0;
        let (next_scope, continuation) = match traversal.current {
            Some(scope) => {
                let protection = protection.ok_or(MaintenanceFailure::InvalidInput)?;
                if !protection.is_only_epoch(epoch) {
                    return Err(MaintenanceFailure::PreconditionFailed);
                }
                let index = traversal
                    .scopes
                    .iter()
                    .position(|candidate| *candidate == scope)
                    .ok_or(MaintenanceFailure::PreconditionFailed)?;
                let cancellation = IntegrityCancellation::new();
                let report = ActiveSegmentLedger::verify_snapshot_integrity(
                    catalog.resource_authority(),
                    basis,
                    catalog.instance(),
                    IntegrityVerificationRequest::new(
                        scope,
                        protection,
                        IntegrityScrubBudget::new(1)
                            .map_err(|_| MaintenanceFailure::InvalidInput)?,
                        &cancellation,
                        publication.transaction,
                        traversal
                            .previous
                            .and_then(|progress| progress.continuation()),
                    ),
                )
                .map_err(|_| MaintenanceFailure::CatalogUnavailable)?;
                examined = report.examined_segments();
                match report.outcome() {
                    IntegrityVerificationOutcome::Verified => {
                        (traversal.scopes.get(index + 1).copied(), None)
                    },
                    IntegrityVerificationOutcome::Incomplete if report.continuation().is_some() => {
                        (Some(scope), report.continuation())
                    },
                    _ => return Err(MaintenanceFailure::PreconditionFailed),
                }
            },
            None if protection.is_none() => (None, None),
            None => return Err(MaintenanceFailure::InvalidInput),
        };
        let progress = EnvelopeVerificationCheckpoint::new(
            catalog.instance(),
            tenant,
            epoch,
            traversal.source,
            next_scope,
            continuation,
        )?;
        let sequence = self.checkpoint.as_ref().map_or(Ok(1), |previous| {
            previous
                .sequence
                .checked_add(1)
                .ok_or(MaintenanceFailure::CapacityExceeded)
        })?;
        self.checkpoint_envelope_verification_at_basis(
            coordinator,
            catalog,
            basis,
            publication,
            progress.checkpoint(sequence)?,
        )?;
        Ok(EnvelopeVerificationProgress {
            complete: progress.is_complete(),
            examined,
        })
    }
}
