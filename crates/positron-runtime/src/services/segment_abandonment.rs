//! Explicit administration, separate from read-only diagnostic collection.
use super::{
    ServiceHandle,
    maintenance_api::{MaintenanceServiceFailure, hex, signal},
    maintenance_verification::{decode_fixed_hex, hex_bytes, integrity_finding_descriptor},
};
use positron_api::maintenance::{SegmentAbandonmentRequest, SegmentAbandonmentResponse};
use positron_domain::{identity::TenantId, routing::VirtualShardId};
use positron_governance::{
    AdministrativeIdempotencyKey, DurableOperationAdministration, DurableOperationFailure,
    DurableOperationKind, DurableOperationRequest, OperationId,
};
use positron_kernel::{
    SegmentAbandonmentPlan, SegmentId, SegmentScope, integrity_quarantine_findings,
};

impl ServiceHandle {
    pub(crate) fn abandon_segment(
        &self,
        bearer: &str,
        bytes: &[u8],
    ) -> Result<SegmentAbandonmentResponse, MaintenanceServiceFailure> {
        // Current durable authorization is required for both new confirmation
        // and every retry or status request.
        let actor = self.authorize_system_administration(bearer)?;
        let input = SegmentAbandonmentRequest::decode(bytes)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let scope = SegmentScope::new(
            TenantId::parse_canonical(&input.tenant)
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?,
            signal(&input.signal).ok_or(MaintenanceServiceFailure::InvalidRequest)?,
            VirtualShardId::new(input.shard)
                .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?,
        );
        let segment = SegmentId::from_bytes(parse_hex(&input.segment)?)
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let _gate = self
            .catalog_operation()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        let catalog = self.open_maintenance_catalog()?;
        let basis = catalog
            .pin()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        if let Some(operation) = input.operation_id {
            let operation = DurableOperationAdministration::inspect_authorized(
                &catalog,
                actor,
                OperationId::from_bytes(parse_hex(&operation)?)
                    .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?,
            )
            .map_err(operation_failure)?
            .ok_or(MaintenanceServiceFailure::SourceUnavailable)?;
            if operation.kind() != DurableOperationKind::SegmentAbandonment
                || operation.target_identity() != Some(segment.to_bytes())
                || operation.request().applicable_tenant() != Some(scope.tenant_id())
            {
                return Err(MaintenanceServiceFailure::SourceUnavailable);
            }
            return abandonment_response(&basis, scope, segment, operation);
        }
        let Some(confirmation) = input.confirmation else {
            let plan = SegmentAbandonmentPlan::preflight(&catalog, &basis, scope, segment)
                .map_err(|failure| {
                    if failure.code() == positron_kernel::IntegrityFailureCode::AmbiguousIntegrity {
                        self.request_integrity_fence();
                        MaintenanceServiceFailure::AdministrationUnavailable
                    } else if failure.code()
                        == positron_kernel::IntegrityFailureCode::FindingCapacity
                    {
                        MaintenanceServiceFailure::AdministrationUnavailable
                    } else {
                        MaintenanceServiceFailure::SourceUnavailable
                    }
                })?;
            return Ok(SegmentAbandonmentResponse {
                catalog_generation: basis.number(),
                status: "preview".into(),
                irreversible_boundary: "not_crossed".into(),
                confirmation: Some(hex_bytes(&plan.confirmation_digest())),
                operation_id: None,
                finding: integrity_finding_descriptor(plan.finding()),
            });
        };
        let idempotency = AdministrativeIdempotencyKey::new(
            TenantId::parse_canonical(
                input
                    .idempotency_key
                    .as_deref()
                    .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
            )
            .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?
            .to_bytes(),
        )
        .map_err(|_| MaintenanceServiceFailure::InvalidRequest)?;
        let request = DurableOperationRequest::segment_abandonment(
            actor.principal_id(),
            scope.tenant_id(),
            idempotency,
            segment.to_bytes(),
            input
                .expected_catalog_generation
                .ok_or(MaintenanceServiceFailure::InvalidRequest)?,
            self.maintenance_status_now()?,
            parse_hex(&confirmation)?,
        )
        .map_err(operation_failure)?;
        let operation =
            DurableOperationAdministration::abandon_segment(&catalog, actor, scope, request)
                .map_err(operation_failure)?;
        let current = catalog
            .pin()
            .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?;
        abandonment_response(&current, scope, segment, operation)
    }
}

fn abandonment_response(
    snapshot: &positron_kernel::CatalogSnapshot,
    scope: SegmentScope,
    segment: SegmentId,
    operation: positron_governance::DurableOperation,
) -> Result<SegmentAbandonmentResponse, MaintenanceServiceFailure> {
    let finding = integrity_quarantine_findings(snapshot)
        .map_err(|_| MaintenanceServiceFailure::AdministrationUnavailable)?
        .into_iter()
        .find(|finding| {
            finding.is_abandoned() && finding.scope() == scope && finding.segment() == segment
        })
        .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?;
    Ok(SegmentAbandonmentResponse {
        catalog_generation: operation
            .request()
            .accepted_generation()
            .checked_add(1)
            .ok_or(MaintenanceServiceFailure::AdministrationUnavailable)?,
        status: "succeeded".into(),
        irreversible_boundary: "catalog_generation_published".into(),
        confirmation: None,
        operation_id: Some(hex(operation.operation_id().to_bytes())),
        finding: integrity_finding_descriptor(finding),
    })
}

fn operation_failure(failure: DurableOperationFailure) -> MaintenanceServiceFailure {
    match failure {
        DurableOperationFailure::Unauthorized => MaintenanceServiceFailure::AuthenticationRejected,
        DurableOperationFailure::IdempotencyConflict => {
            MaintenanceServiceFailure::IdempotencyConflict
        },
        DurableOperationFailure::StaleGeneration => MaintenanceServiceFailure::PreconditionFailed,
        DurableOperationFailure::InvalidInput | DurableOperationFailure::InvalidState => {
            MaintenanceServiceFailure::InvalidRequest
        },
        _ => MaintenanceServiceFailure::AdministrationUnavailable,
    }
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], MaintenanceServiceFailure> {
    decode_fixed_hex(value).ok_or(MaintenanceServiceFailure::InvalidRequest)
}
