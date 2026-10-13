use std::collections::BTreeSet;

use super::format::SegmentState;
use super::publication::publish_exact_scope_segments_with_task_replacement;
use super::retention_publication::metadata_binding;
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode, SnapshotProtection};
use crate::{MaintenanceCoordinator, MaintenanceExecution, MaintenanceTaskClass};

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Checks the surviving continuity marker after the dedicated reclamation
    /// completion owner atomically removed the other input metadata bindings.
    /// The caller holds the snapshot barrier and authenticated Catalog basis.
    pub(crate) fn completed_reclamation_references_absent(
        authority: &crate::StorageKernelResourceAuthority,
        basis: &crate::CatalogSnapshot,
        task: &crate::MaintenanceTask,
    ) -> Result<bool, LedgerFailure> {
        let crate::MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } = task.scope()
        else {
            return Ok(false);
        };
        if task.trigger() != crate::MaintenanceTrigger::Event
            || task.preconditions().resource_generation() != 1
            || task.preconditions().catalog_generation() >= basis.number()
            || task.reservations() != super::retention_publication::retention_publication_claim()?
            || task.source_binding().is_some()
        {
            return Ok(false);
        }
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        let storage = super::storage::LedgerStorage::open_observed(volume)?;
        let scope = super::SegmentScope::new(tenant, signal, shard);
        let metadata = storage.catalog_segments(basis, scope)?;
        let mut marker = None;
        for candidate in metadata {
            if task
                .inputs()
                .contains(&metadata_binding(&storage, candidate)?)
                && (candidate.state != SegmentState::Retired || marker.replace(candidate).is_some())
            {
                return Ok(false);
            }
        }
        match marker {
            Some(marker) => storage.retired_files_absent(marker),
            None => Ok(false),
        }
    }

    /// Reclaims the exact retired metadata bound to one durable Reclamation
    /// task. A protected input remains durably queued for the same descriptor.
    pub fn complete_running_retention_reclamation_task(
        &self,
        coordinator: &MaintenanceCoordinator,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<(), LedgerFailure> {
        let expected = execution.task();
        if expected.class() != MaintenanceTaskClass::RetentionReclamation
            || expected.scope()
                != crate::MaintenanceScope::segment(
                    self.scope.tenant_id(),
                    self.scope.signal_kind(),
                    self.scope.shard_id(),
                )
            || expected.inputs().is_empty()
            || !expected.outputs().is_empty()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let mut durable_record = None;
        for bytes in basis.plaintext_objects() {
            if crate::maintenance::durable_task_record_identity(bytes)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?
                == Some(expected.identity())
                && durable_record.replace(bytes).is_some()
            {
                return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
            }
        }
        let durable_record = durable_record
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        if let Ok(completion) = execution
            .reconcile_running_retention_reclamation_completion(coordinator, durable_record)
        {
            let metadata = self.storage.catalog_segments(&basis, self.scope)?;
            let expected_inputs = expected.inputs().iter().copied().collect::<BTreeSet<_>>();
            let continuity = metadata
                .iter()
                .filter(|candidate| candidate.state == SegmentState::Retired)
                .try_fold(0_usize, |count, candidate| {
                    let binding = metadata_binding(&self.storage, *candidate)?;
                    Ok::<_, LedgerFailure>(count + usize::from(expected_inputs.contains(&binding)))
                })?;
            if continuity != 1 {
                return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
            }
            completion
                .install_reconciled(coordinator)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
            return Ok(());
        }
        let metadata = self.storage.catalog_segments(&basis, self.scope)?;
        let expected_inputs = expected.inputs().iter().copied().collect::<BTreeSet<_>>();
        let mut retired = Vec::new();
        for candidate in metadata
            .iter()
            .filter(|candidate| candidate.state == SegmentState::Retired)
        {
            if expected_inputs.contains(&metadata_binding(&self.storage, *candidate)?) {
                retired.push(*candidate);
            }
        }
        if retired.len() != expected_inputs.len() {
            return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
        }
        let _barrier = SnapshotProtection::write_barrier(self.authority.snapshot_barrier())?;
        // A forward wall-clock discontinuity may be discovered while sampling
        // the lease clock.  Check the authority again after that sample: an
        // uncertain time must retain every durable matching lease rather than
        // treating a jumped observation as an expiry decision.
        let now = self.retention_time.and_then(|authority| {
            let sampled = authority.lease_time(self.scope).ok()?;
            (authority.status().state() == crate::LifecycleClockState::Certain).then_some(sampled)
        });
        let leased = super::snapshot_lease::active_segments(&basis, self.scope, now.unwrap_or(0))?;
        let quarantined = super::integrity::quarantined_segment_ids(&basis, self.scope)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        let in_process = retired.iter().try_fold(false, |protected, segment| {
            SnapshotProtection::is_protected(&self.authority.snapshot_protection(), segment.id)
                .map(|current| protected || current)
        })?;
        if in_process
            || retired.iter().any(|segment| leased.contains(&segment.id))
            || retired
                .iter()
                .any(|segment| quarantined.contains(&segment.id))
        {
            execution
                .requeue_running_retention_reclamation_and_persist(
                    coordinator,
                    self.catalog,
                    durable_record,
                )
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
            return Ok(());
        }
        let completion = execution
            .prepare_running_retention_reclamation_completion(coordinator, durable_record)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        let terminal = match completion.catalog_object() {
            Ok(object) => object,
            Err(_) => {
                completion
                    .discard(coordinator)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
                return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
            },
        };
        let mut physically_mutated = false;
        for candidate in &retired {
            match self.storage.reclaim_retired(*candidate) {
                Ok(changed) => physically_mutated |= changed,
                Err(failure) => {
                    completion
                        .discard(coordinator)
                        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
                    return Err(if physically_mutated {
                        LedgerFailure::post_mutation(failure.code())
                    } else {
                        failure
                    });
                },
            }
        }
        let continuity = retired
            .iter()
            .max_by_key(|candidate| candidate.base_position)
            .copied();
        let retired_ids = retired
            .iter()
            .map(|candidate| candidate.id)
            .collect::<BTreeSet<_>>();
        let mut remaining = metadata;
        remaining.retain(|candidate| !retired_ids.contains(&candidate.id));
        if let Some(marker) = continuity {
            remaining.push(marker);
        }
        if let Err(failure) = publish_exact_scope_segments_with_task_replacement(
            self.catalog,
            &basis,
            &self.storage,
            self.scope,
            &remaining,
            expected.identity(),
            terminal,
        ) {
            completion
                .discard(coordinator)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
            return Err(if physically_mutated {
                LedgerFailure::post_mutation(failure.code())
            } else {
                failure
            });
        }
        completion
            .install(coordinator)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))
    }
}
