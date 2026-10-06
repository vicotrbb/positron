use positron_api::maintenance::{MaintenanceWindowRequest, MaintenanceWindowResponse};
use positron_governance::maintenance_window_audit_intent;

use crate::ServiceHandle;

use super::maintenance_api::{
    MaintenanceServiceFailure, administrative_key, control_failure,
    latest_governance_audit_position, maintenance_window_replay, window_class, window_class_names,
};

impl ServiceHandle {
    pub(crate) fn set_maintenance_window(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceWindowResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let actor = self.authorize_system_administration(bearer)?;
        let request = MaintenanceWindowRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let mut deferred = request
            .deferred_classes()
            .iter()
            .map(|class| window_class(class).ok_or(MaintenanceServiceFailure::InvalidRequest))
            .collect::<Result<Vec<_>, _>>()?;
        deferred.sort_unstable();
        let deferred_classes = window_class_names(&deferred);
        let idempotency = administrative_key(request.idempotency_key())
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let catalog = self.open_maintenance_catalog()?;
        if let Some(response) = maintenance_window_replay(
            &catalog,
            actor.principal_id(),
            idempotency,
            request.expected_catalog_generation(),
            &deferred,
            request.duration_seconds(),
        )? {
            return Ok(response);
        }
        let now = self.maintenance_status_now()?;
        let until = now
            .checked_add(request.duration_seconds())
            .ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let audit = maintenance_window_audit_intent(
            actor.principal_id(),
            idempotency,
            request.expected_catalog_generation(),
            &deferred,
            request.duration_seconds(),
            until,
        )
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog_generation = self
            .instance
            .maintenance_coordinator()
            .set_window_and_persist_audited(
                &catalog,
                deferred,
                request.expected_catalog_generation(),
                until,
                now,
                audit,
            )
            .map_err(control_failure)?;
        let audit_position = latest_governance_audit_position(&catalog)?;
        drop(catalog);
        drop(_catalog_operation);
        self.notify_maintenance_worker();
        Ok(MaintenanceWindowResponse {
            deferred_classes,
            until_unix_seconds: until,
            catalog_generation,
            audit_position,
        })
    }
}
