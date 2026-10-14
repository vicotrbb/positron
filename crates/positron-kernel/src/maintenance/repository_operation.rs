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
        Self::from_task(&execution.task, execution.checkpoint.as_ref())
    }

    pub(super) fn from_task(
        task: &MaintenanceTask,
        checkpoint: Option<&MaintenanceCheckpoint>,
    ) -> Result<Self, MaintenanceFailure> {
        if task.class != MaintenanceTaskClass::RepositoryVerification
            || task.scope != MaintenanceScope::System
            || !task.inputs.is_empty()
            || !task.outputs.is_empty()
            || task.integrity_scrub_source.is_some()
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let checkpoint = checkpoint.ok_or(MaintenanceFailure::PreconditionFailed)?;
        let bytes = checkpoint.opaque_progress();
        if checkpoint.sequence() != 1
            || checkpoint.completed_inputs() != 0
            || bytes.len() != 56
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
        let floor = ResourceAmounts::new([131_072, 1, 1, 0, 1, 0, 1, 1, 1, 4, 16_384]);
        if crate::ResourceDimension::ALL
            .iter()
            .any(|dimension| resources.get(*dimension) < floor.get(*dimension))
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let task = MaintenanceTask::with_contract(
            MaintenanceTaskId::new(binding.operation)?,
            MaintenanceTaskClass::RepositoryVerification,
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
            MaintenanceReservation::Ordinary(_) | MaintenanceReservation::Recovery(_) => None,
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
