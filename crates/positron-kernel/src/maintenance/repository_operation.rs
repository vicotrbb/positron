//! Persisted association and resource admission for Repository-owned work.
use super::*;

const MAGIC: &[u8; 8] = b"REPBND01";

/// A reference-free association with one Administration operation. The Runtime
/// verifies this digest against the accepted operation before dispatching work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryOperationBinding {
    operation: [u8; 16],
    intent: [u8; 32],
}

impl RepositoryOperationBinding {
    /// Reads the latest persisted handler payload while this exact dispatch
    /// still owns the task. The execution's initial checkpoint may be older.
    pub fn current_backup_progress(
        self,
        coordinator: &MaintenanceCoordinator,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<(u64, Vec<u8>), MaintenanceFailure> {
        if Self::from_execution(execution)? != self
            || execution.dispatch.coordinator_id != coordinator.coordinator_id
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&execution.task.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(execution.dispatch)
            || task.task != execution.task
            || Self::from_task(&task.task, task.checkpoint.as_ref())? != self
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let checkpoint = task
            .checkpoint
            .as_ref()
            .ok_or(MaintenanceFailure::PreconditionFailed)?;
        let progress = checkpoint
            .opaque_progress()
            .get(56..)
            .filter(|bytes| bytes.len() <= MAX_CHECKPOINT_BYTES - 56)
            .ok_or(MaintenanceFailure::PreconditionFailed)?;
        Ok((checkpoint.sequence(), progress.to_vec()))
    }

    /// Whether this exact accepted intent still has a live Backup maintenance owner.
    /// Read authenticated records individually without restoring coordinator state.
    pub fn has_live_backup_owner(
        self,
        snapshot: &crate::CatalogSnapshot,
    ) -> Result<bool, MaintenanceFailure> {
        let mut live = false;
        let mut matched = false;
        for bytes in snapshot.plaintext_objects() {
            if record::record_identity(bytes)?.is_none() {
                continue;
            }
            let state = decode_record(bytes)?;
            if !matches!(
                state.task.class,
                MaintenanceTaskClass::BackupSnapshot | MaintenanceTaskClass::RepositoryCleanup
            ) {
                continue;
            }
            let binding = Self::from_task(&state.task, state.checkpoint.as_ref())?;
            if binding == self {
                if matched {
                    return Err(MaintenanceFailure::CatalogUnavailable);
                }
                matched = true;
                live = matches!(
                    state.phase,
                    MaintenanceTaskPhase::Queued
                        | MaintenanceTaskPhase::Running
                        | MaintenanceTaskPhase::Deferred
                );
            }
        }
        Ok(live)
    }

    pub fn new(operation: [u8; 16], intent: [u8; 32]) -> Result<Self, MaintenanceFailure> {
        if operation.iter().all(|byte| *byte == 0) || intent.iter().all(|byte| *byte == 0) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self { operation, intent })
    }
    pub fn operation_id(self) -> [u8; 16] {
        self.operation
    }
    pub fn intent_digest(self) -> [u8; 32] {
        self.intent
    }

    pub fn from_execution(
        execution: &MaintenanceExecution<'_>,
    ) -> Result<Self, MaintenanceFailure> {
        if matches!(
            &execution.reservation,
            MaintenanceReservation::RequeuedOrdinary(_)
                | MaintenanceReservation::RequeuedNative(_)
                | MaintenanceReservation::Inactive
        ) {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Self::from_task(&execution.task, execution.checkpoint.as_ref())
    }

    pub(super) fn from_task(
        task: &MaintenanceTask,
        checkpoint: Option<&MaintenanceCheckpoint>,
    ) -> Result<Self, MaintenanceFailure> {
        if !matches!(
            task.class,
            MaintenanceTaskClass::RepositoryVerification
                | MaintenanceTaskClass::BackupSnapshot
                | MaintenanceTaskClass::RepositoryCleanup
        ) || task.scope != MaintenanceScope::System
            || !task.inputs.is_empty()
            || !task.outputs.is_empty()
            || task.integrity_scrub_source.is_some()
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let checkpoint = checkpoint.ok_or(MaintenanceFailure::PreconditionFailed)?;
        let bytes = checkpoint.opaque_progress();
        let backup = matches!(
            task.class,
            MaintenanceTaskClass::BackupSnapshot | MaintenanceTaskClass::RepositoryCleanup
        );
        if (!backup && checkpoint.sequence() != 1)
            || checkpoint.completed_inputs() != 0
            || bytes.len() < 56
            || (!backup && bytes.len() != 56)
            || !bytes.starts_with(MAGIC)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let operation = bytes
            .get(8..24)
            .and_then(|value| value.try_into().ok())
            .ok_or(MaintenanceFailure::PreconditionFailed)?;
        let intent = bytes
            .get(24..56)
            .and_then(|value| value.try_into().ok())
            .ok_or(MaintenanceFailure::PreconditionFailed)?;
        let binding = Self::new(operation, intent)?;
        if task.identity.to_bytes() != binding.operation {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(binding)
    }
    pub fn backup_checkpoint(
        self,
        sequence: u64,
        progress: &[u8],
    ) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
        if sequence < 2 || progress.len() > MAX_CHECKPOINT_BYTES - 56 {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut bytes = self.checkpoint()?.opaque_progress().to_vec();
        bytes.extend_from_slice(progress);
        MaintenanceCheckpoint::new(sequence, 0, bytes)
    }
    pub fn backup_progress<'execution>(
        self,
        execution: &'execution MaintenanceExecution<'_>,
    ) -> Result<&'execution [u8], MaintenanceFailure> {
        if !matches!(
            execution.task.class,
            MaintenanceTaskClass::BackupSnapshot | MaintenanceTaskClass::RepositoryCleanup
        ) || Self::from_execution(execution)? != self
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        execution
            .checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.opaque_progress().get(56..))
            .ok_or(MaintenanceFailure::PreconditionFailed)
    }
    fn checkpoint(self) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
        let mut bytes = Vec::with_capacity(56);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.intent);
        MaintenanceCheckpoint::new(1, 0, bytes)
    }
}

impl MaintenanceCoordinator {
    /// Persists the stable task-to-operation association before any provider I/O.
    pub fn submit_repository_operation_and_persist(
        &self,
        catalog: &crate::Catalog<'_>,
        binding: RepositoryOperationBinding,
        preconditions: MaintenancePreconditions,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        self.submit_repository_operation_with_resources_and_persist(
            catalog,
            binding,
            preconditions,
            ResourceAmounts::new([131_072, 1, 1, 0, 1, 0, 1, 1, 1, 4, 16_384]),
            now,
        )
    }

    /// Declares the provider's bounded peak on the same persisted task authority.
    pub fn submit_repository_operation_with_resources_and_persist(
        &self,
        catalog: &crate::Catalog<'_>,
        binding: RepositoryOperationBinding,
        preconditions: MaintenancePreconditions,
        resources: ResourceAmounts,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        self.submit_repository_bound_task(
            catalog,
            binding,
            preconditions,
            resources,
            now,
            MaintenanceTaskClass::RepositoryVerification,
        )
    }
    /// The same durable association owns restartable Backup work and its grant.
    pub fn submit_backup_operation_with_resources_and_persist(
        &self,
        catalog: &crate::Catalog<'_>,
        binding: RepositoryOperationBinding,
        preconditions: MaintenancePreconditions,
        resources: ResourceAmounts,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        self.submit_repository_bound_task(
            catalog,
            binding,
            preconditions,
            resources,
            now,
            MaintenanceTaskClass::BackupSnapshot,
        )
    }
    /// Uses the same binding and admission authority for retained Backup cleanup.
    pub fn submit_backup_retention_operation_with_resources_and_persist(
        &self,
        catalog: &crate::Catalog<'_>,
        binding: RepositoryOperationBinding,
        preconditions: MaintenancePreconditions,
        resources: ResourceAmounts,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        self.submit_repository_bound_task(
            catalog,
            binding,
            preconditions,
            resources,
            now,
            MaintenanceTaskClass::RepositoryCleanup,
        )
    }
    fn submit_repository_bound_task(
        &self,
        catalog: &crate::Catalog<'_>,
        binding: RepositoryOperationBinding,
        preconditions: MaintenancePreconditions,
        resources: ResourceAmounts,
        now: u64,
        class: MaintenanceTaskClass,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        if matches!(
            class,
            MaintenanceTaskClass::BackupSnapshot | MaintenanceTaskClass::RepositoryCleanup
        ) && (resources.get(ResourceDimension::MemoryBytes) < 4 * 1024 * 1024
            || resources.get(ResourceDimension::FileDescriptors) < 8)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let floor = ResourceAmounts::new([131_072, 1, 1, 0, 1, 0, 1, 1, 1, 4, 16_384]);
        if crate::ResourceDimension::ALL
            .iter()
            .any(|dimension| resources.get(*dimension) < floor.get(*dimension))
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let task = MaintenanceTask::with_contract(
            MaintenanceTaskId::new(binding.operation)?,
            class,
            MaintenanceScope::System,
            MaintenanceTrigger::Event,
            preconditions,
            Vec::new(),
            Vec::new(),
            // Catalog retains its own grant; provider work owns this peak.
            resources,
        )?;
        self.submit_bound_operation(catalog, task, binding.checkpoint()?, now)
    }
}

impl MaintenanceExecution<'_> {
    /// Retrieves the already transferred owner for another attempt of this exact task.
    pub fn retained_repository_resources(
        &self,
        binding: RepositoryOperationBinding,
    ) -> Result<Option<std::sync::Arc<crate::NativeAwsResources>>, MaintenanceFailure> {
        if RepositoryOperationBinding::from_execution(self)? != binding {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(match &self.reservation {
            MaintenanceReservation::NativeRepository(resources) => Some(resources.clone()),
            MaintenanceReservation::Ordinary(_)
            | MaintenanceReservation::Recovery(_)
            | MaintenanceReservation::RequeuedOrdinary(_)
            | MaintenanceReservation::RequeuedNative(_)
            | MaintenanceReservation::Inactive => None,
        })
    }

    /// Retains the existing task grant in both the execution and native
    /// workers. Completion publication remains admitted, and cancellation
    /// cannot release capacity while a worker still owns it.
    pub fn transfer_repository_resources(
        &mut self,
        binding: RepositoryOperationBinding,
    ) -> Result<std::sync::Arc<crate::NativeAwsResources>, MaintenanceFailure> {
        if RepositoryOperationBinding::from_execution(self)? != binding {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let MaintenanceReservation::Ordinary(reservation) = &mut self.reservation else {
            return Err(MaintenanceFailure::InvalidTransition);
        };
        let grant = reservation
            .transfer_from_borrow()
            .ok_or(MaintenanceFailure::InvalidTransition)?;
        let resources = crate::NativeAwsResources::new(grant);
        self.reservation = MaintenanceReservation::NativeRepository(resources.clone());
        Ok(resources)
    }
}

impl MaintenanceExecution<'_> {
    /// Persists a larger declared peak and the exact current checkpoint before
    /// relinquishing dispatch authority. The old grant remains charged until
    /// this execution is dropped. Drop retained work before the next admission.
    pub fn requeue_backup_with_resources_and_persist(
        &mut self,
        coordinator: &MaintenanceCoordinator,
        catalog: &crate::Catalog<'_>,
        binding: RepositoryOperationBinding,
        resources: ResourceAmounts,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        if !matches!(
            self.task.class,
            MaintenanceTaskClass::BackupSnapshot | MaintenanceTaskClass::RepositoryCleanup
        ) || RepositoryOperationBinding::from_execution(self)? != binding
            || ResourceDimension::ALL
                .iter()
                .any(|dimension| resources.get(*dimension) < self.task.reservations.get(*dimension))
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        match &self.reservation {
            MaintenanceReservation::Ordinary(reservation) if reservation.is_active() => {},
            MaintenanceReservation::NativeRepository(owner)
                if Arc::strong_count(owner) == 1 && !owner.busy() => {},
            _ => return Err(MaintenanceFailure::PreconditionFailed),
        }
        coordinator
            .requeue_backup_with_resources_dispatch(catalog, self, binding, resources, now)?;
        // No fallible work follows publication. The temporary empty state is
        // never exposed, and the backing reservation stays live throughout.
        self.reservation =
            match std::mem::replace(&mut self.reservation, MaintenanceReservation::Inactive) {
                MaintenanceReservation::Ordinary(reservation) => {
                    MaintenanceReservation::RequeuedOrdinary(reservation)
                },
                MaintenanceReservation::NativeRepository(owner) => {
                    MaintenanceReservation::RequeuedNative(owner)
                },
                other => other,
            };
        Ok(())
    }
}
