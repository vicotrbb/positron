//! The coordinator owns dispatch; the root Catalog journal owns migration phases.
use super::*;

const MAGIC: &[u8; 8] = b"RPMBND01";

/// A reference-free association with one Administration operation. The Runtime
/// verifies this digest against the accepted operation before dispatching work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootProviderMigrationBinding {
    operation: [u8; 16],
    intent: [u8; 32],
}

impl RootProviderMigrationBinding {
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
        if task.class != MaintenanceTaskClass::Migration
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
    pub fn submit_root_provider_migration_and_persist(
        &self,
        catalog: &crate::Catalog<'_>,
        binding: RootProviderMigrationBinding,
        preconditions: MaintenancePreconditions,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        let task = MaintenanceTask::with_contract(
            MaintenanceTaskId::new(binding.operation)?,
            MaintenanceTaskClass::Migration,
            MaintenanceScope::System,
            MaintenanceTrigger::Event,
            preconditions,
            Vec::new(),
            Vec::new(),
            // Bounded task/parameter decoding and dispatch. Native custody and
            // Catalog publication retain their independently admitted grants.
            ResourceAmounts::new([16_384, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0]),
        )?;
        self.submit_root_migration(catalog, task, binding.checkpoint()?, now)
    }
}
