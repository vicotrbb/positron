//! Bounded test-support context for stalled exclusive offline turns.
use super::{Administration, DurableOperation, OfflineUpgradeSession, UpgradeFailure, open};
use positron_kernel::MaintenanceTaskId;
use sha2::Digest;

pub(super) struct Context {
    children: Result<[String; 2], &'static str>,
    clock: String,
}

pub(super) fn capture(session: &OfflineUpgradeSession) -> Context {
    Context {
        children: children(session),
        clock: format!(
            "state={:?} now={:?}",
            session.instance.retention_time.status().state(),
            session
                .instance
                .retention_time
                .inspect_governance_now_seconds()
        ),
    }
}

fn children(session: &OfflineUpgradeSession) -> Result<[String; 2], &'static str> {
    let keys = [
        Administration::upgrade_snapshot_key(session.id).map_err(|_| "snapshot_key_unavailable")?,
        Administration::upgrade_snapshot_verification_key(session.id)
            .map_err(|_| "verification_key_unavailable")?,
    ];
    let catalog = open(&session.instance).map_err(|_| "catalog_open_unavailable")?;
    let snapshot = catalog.pin().map_err(|_| "catalog_pin_unavailable")?;
    let mut children = [String::new(), String::new()];
    for (output, key) in children.iter_mut().zip(keys) {
        let operation = Administration::inspect_snapshot_by_idempotency(&snapshot, key)
            .map_err(|_| "child_read_unavailable")?;
        *output = match operation {
            Some(operation) => child(session, &operation),
            None => "absent".into(),
        };
    }
    Ok(children)
}

fn child(session: &OfflineUpgradeSession, operation: &DurableOperation) -> String {
    let task = MaintenanceTaskId::new(operation.operation_id().to_bytes())
        .ok()
        .and_then(|id| session.instance.maintenance_coordinator().status(id).ok());
    let task = task.map_or_else(
        || "task_unavailable".into(),
        |task| {
            let checkpoint = task.checkpoint().map(|checkpoint| {
                let bytes = checkpoint.opaque_progress();
                let digest = sha2::Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                format!(
                    "sequence={} len={} sha256={digest}",
                    checkpoint.sequence(),
                    bytes.len()
                )
            });
            format!(
                "phase={:?} reservations={:?} last_progress={:?} checkpoint={checkpoint:?}",
                task.phase(),
                task.task().reservations(),
                task.last_progress_at()
            )
        },
    );
    format!(
        "kind={:?} phase={:?} status={:?} revision={} updated={} {task}",
        operation.kind(),
        operation.phase(),
        operation.status(),
        operation.revision(),
        operation.updated_at_unix_seconds()
    )
}

pub(super) fn report(
    session: &OfflineUpgradeSession,
    before: Context,
    result: &Result<DurableOperation, UpgradeFailure>,
) {
    let after = capture(session);
    if result.is_err() || before.children == after.children {
        let outcome = result.as_ref().map(|_| ()).map_err(|failure| *failure);
        eprintln!(
            "offline_upgrade_turn outcome={outcome:?} before_children={:?} before_clock={} after_children={:?} after_clock={}",
            before.children, before.clock, after.children, after.clock
        );
    }
}
