//! Closed persisted Upgrade states and evidence ordering.
use super::*;

pub(super) fn legal_state(operation: &DurableOperation) -> bool {
    let (Some(parameters), Some(progress)) =
        (operation.upgrade_parameters(), operation.upgrade_progress)
    else {
        return false;
    };
    if operation.request.operation_request_digest != Some(parameters.intent_digest())
        || operation.backup_evidence.is_some()
        || operation.repository_parameters.is_some()
        || operation.key_provider_migration_parameters.is_some()
        || operation.repository_policy.is_some()
        || (progress.stage.code() >= 3) != progress.drain.is_some()
        || (progress.stage.code() >= 4 && progress.snapshot.is_none())
        || (progress.snapshot.is_some() && progress.drain.is_none())
    {
        return false;
    }
    if progress.report.is_some() != (operation.status == DurableOperationStatus::Succeeded) {
        return false;
    }
    if let (Some(drain), Some(snapshot)) = (progress.drain, progress.snapshot)
        && (snapshot.receipt().catalog_generation() < drain.catalog_generation()
            || snapshot.operation_id() == operation.operation_id()
            || snapshot.verification_operation_id() == operation.operation_id()
            || snapshot.operation_id() == snapshot.verification_operation_id())
    {
        return false;
    }
    let published = progress.stage.code() >= 5;
    if progress.rollback.is_some()
        && (operation.status != DurableOperationStatus::Failed || !published)
    {
        return false;
    }
    if operation.boundary
        != if published {
            DurableOperationBoundary::CatalogGenerationPublished
        } else {
            DurableOperationBoundary::NotCrossed
        }
    {
        return false;
    }
    match operation.status {
        DurableOperationStatus::Pending => {
            progress.stage == UpgradeStage::Preflight
                && progress.drain.is_none()
                && progress.snapshot.is_none()
                && operation.phase == DurableOperationPhase::Accepted
                && operation.progress_percent == 0
                && operation.completed_at_unix_seconds.is_none()
                && operation.terminal_error.is_none()
                && operation.cancellation_idempotency.is_none()
                && operation.cancellation == DurableOperationCancellation::AllowedBeforeDrain
                && operation.retry == DurableOperationRetry::InspectByOperationId
        },
        DurableOperationStatus::Running => {
            progress.stage != UpgradeStage::Succeeded
                && operation.phase == progress.stage.phase()
                && operation.progress_percent == progress.stage.progress()
                && operation.completed_at_unix_seconds.is_none()
                && operation.terminal_error.is_none()
                && operation.cancellation_idempotency.is_none()
                && operation.cancellation
                    == if published {
                        DurableOperationCancellation::NotAllowedAfterDrain
                    } else {
                        DurableOperationCancellation::AllowedBeforeDrain
                    }
                && operation.retry == DurableOperationRetry::InspectByOperationId
        },
        DurableOperationStatus::Succeeded => {
            progress.stage == UpgradeStage::Succeeded
                && operation.phase == DurableOperationPhase::Published
                && operation.progress_percent == 100
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.terminal_error.is_none()
                && operation.cancellation_idempotency.is_none()
                && operation.cancellation == DurableOperationCancellation::NotAllowedAfterDrain
                && operation.retry == DurableOperationRetry::Never
        },
        DurableOperationStatus::Failed => {
            progress.stage != UpgradeStage::Succeeded
                && operation.phase == progress.stage.phase()
                && operation.progress_percent == progress.stage.progress()
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.terminal_error.is_some()
                && operation.cancellation_idempotency.is_none()
                && operation.cancellation
                    == if published {
                        DurableOperationCancellation::NotAllowedAfterDrain
                    } else {
                        DurableOperationCancellation::AllowedBeforeDrain
                    }
                && operation.retry == DurableOperationRetry::Never
        },
        DurableOperationStatus::Cancelled => {
            !published
                && operation.phase == DurableOperationPhase::Cancelled
                && operation.progress_percent == 0
                && operation.completed_at_unix_seconds == Some(operation.updated_at_unix_seconds)
                && operation.terminal_error.is_none()
                && operation.cancellation_idempotency.is_some()
                && operation.cancellation == DurableOperationCancellation::Cancelled
                && operation.retry == DurableOperationRetry::Never
        },
    }
}
