use positron_api::maintenance::{
    MaintenanceExplainRequest, MaintenanceExplainResponse, MaintenanceStatusRequest,
    MaintenanceStatusResponse,
};
use positron_kernel::MaintenanceTaskPhase;

use crate::ServiceHandle;

use super::{
    maintenance_api::{
        MaintenanceServiceFailure, append_status_task_within_response_limit, task_identity,
    },
    maintenance_inspection::task_status_for_coordinator,
    maintenance_verification::integrity_findings,
};

impl ServiceHandle {
    pub(crate) fn maintenance_status(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceStatusResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        self.authorize_system_administration(bearer)?;
        let request = MaintenanceStatusRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let cursor = match request.cursor() {
            Some(value) => {
                Some(task_identity(value).ok_or(MaintenanceServiceFailure::InvalidRequest)?)
            },
            None => None,
        };
        let (clock_uncertain, now) = self.maintenance_inspection_clock()?;
        let statuses = self
            .instance
            .maintenance_coordinator()
            .statuses_with_progress_slo(now, clock_uncertain)
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let mut response = MaintenanceStatusResponse {
            tasks: Vec::with_capacity(request.page_limit()),
            returned: 0,
            total: u32::try_from(statuses.len())
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
            next_cursor: None,
            queued: 0,
            running: 0,
            deferred: 0,
            terminal: 0,
            // Findings are independently bounded evidence and the canonical
            // status contract repeats the complete current set on every task
            // page. Task rows below are trimmed against this exact envelope.
            integrity_findings: integrity_findings(self)?,
        };
        for status in &statuses {
            match status.phase() {
                MaintenanceTaskPhase::Queued => response.queued += 1,
                MaintenanceTaskPhase::Running => response.running += 1,
                MaintenanceTaskPhase::Deferred => response.deferred += 1,
                MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed => response.terminal += 1,
            }
        }
        let page_start = cursor.map_or(0, |cursor| {
            statuses.partition_point(|status| status.task().identity() <= cursor)
        });
        let remaining = statuses.len().saturating_sub(page_start);
        let page_len = remaining.min(request.page_limit());
        let coordinator = self.instance.maintenance_coordinator();
        for status in statuses.into_iter().skip(page_start).take(page_len) {
            let task = task_status_for_coordinator(coordinator, status, now)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
            if !append_status_task_within_response_limit(&mut response, task, remaining)? {
                break;
            }
        }
        response
            .validate()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        Ok(response)
    }

    pub(crate) fn explain_maintenance_task(
        &self,
        bearer: &str,
        body: &[u8],
    ) -> Result<MaintenanceExplainResponse, MaintenanceServiceFailure> {
        let _catalog_operation = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        self.authorize_system_administration(bearer)?;
        let request = MaintenanceExplainRequest::decode(body)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let identity =
            task_identity(&request.identity).ok_or(MaintenanceServiceFailure::InvalidRequest)?;
        let (clock_uncertain, now) = self.maintenance_inspection_clock()?;
        let status = self
            .instance
            .maintenance_coordinator()
            .status_with_progress_slo(identity, now, clock_uncertain)
            .map_err(|_| MaintenanceServiceFailure::TaskUnavailable)?;
        Ok(MaintenanceExplainResponse {
            task: task_status_for_coordinator(self.instance.maintenance_coordinator(), status, now)
                .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?,
        })
    }
}
