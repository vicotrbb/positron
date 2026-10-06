use positron_api::maintenance::{
    MaintenanceControlResponse, MaintenancePauseRequest, MaintenanceResumeRequest,
    MaintenanceRunRequest, MaintenanceRunResponse,
};
use positron_domain::{identity::TenantId, routing::VirtualShardId};
use positron_governance::{
    Identity, MaintenanceRunAuditRequest, maintenance_control_audit_intent,
    maintenance_run_audit_intent,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, MaintenanceScope, MaintenanceTaskClass, SegmentScope,
};

use crate::ServiceHandle;

use super::maintenance_api::{
    MaintenanceServiceFailure, administrative_key, control_acknowledgement, control_failure,
    maintenance_control_replay, maintenance_run_replay, maintenance_task_id, signal,
    source_failure, task_acknowledgement, task_identity,
};

impl ServiceHandle {
    pub(crate) fn run_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceRunResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceRunRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let tenant = TenantId::parse_canonical(request.tenant())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let signal = signal(request.signal()).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let shard = VirtualShardId::new(request.shard())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let task_identity = maintenance_task_id(actor.principal_id(), idempotency)?;
        let now = self.maintenance_status_now()?;
        let instance = &self.instance;
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance
                .key
                .catalog_secret(instance.instance)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        if let Some(response) = maintenance_run_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            task_identity,
            tenant,
            signal,
            shard,
        )? {
            return Ok(response);
        }
        let snapshot = catalog
            .pin()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let identity = Identity::open(&snapshot)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let scope = SegmentScope::new(tenant, signal, shard);
        let expected_scope = MaintenanceScope::segment(tenant, signal, shard);
        if !snapshot
            .reachable_ledger_scopes(tenant, signal)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
            .into_iter()
            .any(|candidate| candidate == scope)
        {
            return Err(MaintenanceServiceFailure::SourceUnavailable);
        }
        let coordinator = instance.maintenance_coordinator();
        match coordinator.status(task_identity) {
            Ok(status)
                if status.task().class() == MaintenanceTaskClass::Compaction
                    && status.task().scope() == expected_scope =>
            {
                return Ok(MaintenanceRunResponse {
                    resource_generation: status.task().preconditions().resource_generation(),
                    task: task_acknowledgement(status),
                });
            },
            Ok(_) => return Err(MaintenanceServiceFailure::IdempotencyConflict),
            Err(positron_kernel::MaintenanceFailure::UnknownTask) => {},
            Err(_) => return Err(MaintenanceServiceFailure::AdministrationUnavailable),
        }
        let key = super::tenant_segment_key(instance, &identity, scope)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let bucket = ledger.sealed_compaction_bucket().map_err(source_failure)?;
        let task = ledger
            .prepare_compaction_task(bucket, task_identity)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let audit = maintenance_run_audit_intent(MaintenanceRunAuditRequest {
            actor: actor.principal_id(),
            idempotency_key: idempotency,
            task: task_identity,
            tenant,
            signal,
            shard: shard.value(),
            resource_generation: task.task().preconditions().resource_generation(),
            submitted_at_unix_seconds: now,
        })
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let submitted = task
            .submit_and_persist_audited(coordinator, &catalog, now, audit)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let status = coordinator
            .status(submitted.identity())
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        drop(ledger);
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceRunResponse {
            resource_generation: status.task().preconditions().resource_generation(),
            task: task_acknowledgement(status),
        })
    }

    pub(crate) fn pause_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceControlResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenancePauseRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let identity =
            task_identity(request.identity()).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let catalog = self.open_maintenance_catalog()?;
        let now = self.maintenance_status_now()?;
        if let Some(audit) = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            true,
            request.resource_generation(),
            request.duration_seconds(),
        )? {
            let status = self
                .instance
                .maintenance_coordinator()
                .status(identity)
                .map_err(control_failure)?;
            return Ok(control_acknowledgement(status, &audit));
        }
        let until = now
            .checked_add(request.duration_seconds())
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let audit = maintenance_control_audit_intent(
            actor.principal_id(),
            idempotency,
            identity,
            true,
            request.resource_generation(),
            request.duration_seconds(),
            Some(until),
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let coordinator = self.instance.maintenance_coordinator();
        coordinator
            .pause_and_persist_audited(
                &catalog,
                identity,
                request.resource_generation(),
                until,
                now,
                audit,
            )
            .map_err(control_failure)?;
        let status = coordinator.status(identity).map_err(control_failure)?;
        let audit = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            true,
            request.resource_generation(),
            request.duration_seconds(),
        )?
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(control_acknowledgement(status, &audit))
    }

    pub(crate) fn resume_maintenance(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceControlResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceResumeRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let identity =
            task_identity(request.identity()).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let catalog = self.open_maintenance_catalog()?;
        if let Some(audit) = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            false,
            0,
            0,
        )? {
            let status = self
                .instance
                .maintenance_coordinator()
                .status(identity)
                .map_err(control_failure)?;
            return Ok(control_acknowledgement(status, &audit));
        }
        let audit = maintenance_control_audit_intent(
            actor.principal_id(),
            idempotency,
            identity,
            false,
            0,
            0,
            None,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let coordinator = self.instance.maintenance_coordinator();
        coordinator
            .resume_and_persist_audited(&catalog, identity, audit)
            .map_err(control_failure)?;
        let status = coordinator.status(identity).map_err(control_failure)?;
        let audit = maintenance_control_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            identity,
            false,
            0,
            0,
        )?
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(control_acknowledgement(status, &audit))
    }
}
