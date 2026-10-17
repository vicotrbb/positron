//! Terminal Upgrade authority requires the native owner's signed verification.
use super::upgrade_administration::authorized;
use super::*;
use positron_kernel::upgrade_verification::{UpgradeQueryVerification, UpgradeVerificationReport};
impl DurableOperationAdministration {
    /// Reattaches the exact authenticated first report before a restart may
    /// publish query or maintenance state over its unpublished predecessor.
    pub fn resume_upgrade_verification(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
    ) -> Result<Option<DurableOperation>, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        if operation.status() == DurableOperationStatus::Succeeded {
            return Ok(Some(operation));
        }
        if operation.status() != DurableOperationStatus::Running
            || operation.upgrade_stage() != Some(UpgradeStage::Verifying)
        {
            return Ok(None);
        }
        let mut candidate = operation.succeeded(operation.updated_at_unix_seconds())?;
        let mut progress = candidate
            .upgrade_progress
            .ok_or(DurableOperationFailure::InvalidState)?;
        progress.stage = UpgradeStage::Succeeded;
        candidate.upgrade_progress = Some(progress);
        let transaction = transition_transaction(candidate)?;
        let digest = transition_request_digest(candidate);
        let publication = Self::current_upgrade_publication_snapshot(&snapshot)?
            .ok_or(DurableOperationFailure::InvalidState)?;
        let digest =
            publication_request_digest(candidate, digest, publication.object_identity()?, &[]);
        let prepared = match catalog
            .inspect_prepared(transaction, digest)
            .map_err(map_catalog)?
        {
            positron_kernel::PreparedTransactionInspection::Absent => return Ok(None),
            positron_kernel::PreparedTransactionInspection::Unavailable => {
                return Err(DurableOperationFailure::PersistenceUnavailable);
            },
            positron_kernel::PreparedTransactionInspection::Inspected(prepared) => prepared,
        };
        let proposed =
            find_by_id(&prepared, id)?.ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        if proposed.status() != DurableOperationStatus::Succeeded
            || proposed.request() != operation.request()
        {
            return Err(DurableOperationFailure::PersistenceUnavailable);
        }
        let report_id = proposed
            .upgrade_verification_report()
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let object = prepared
            .object_identities()
            .find(|id| id.to_bytes() == report_id)
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        let report = UpgradeVerificationReport::from_bytes(
            prepared
                .object(object)
                .map_err(map_catalog)?
                .ok_or(DurableOperationFailure::PersistenceUnavailable)?,
        )
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
        verify_report(&snapshot, id, &report)?;
        Self::current_upgrade_publication_snapshot(&prepared)?
            .ok_or(DurableOperationFailure::PersistenceUnavailable)?;
        resume_prepared_operation(catalog, transaction, digest, id)
    }
    pub fn succeed_upgrade(
        catalog: &Catalog<'_>,
        actor: crate::AuthorizedContext,
        id: OperationId,
        report: &UpgradeVerificationReport,
        now: u64,
    ) -> Result<DurableOperation, DurableOperationFailure> {
        let (snapshot, operation) = authorized(catalog, actor, id)?;
        let object = CatalogObject::new(report.bytes().to_vec()).map_err(map_catalog)?;
        let report_id = object.identity().to_bytes();
        if operation.status() == DurableOperationStatus::Succeeded {
            return if operation.upgrade_verification_report() == Some(report_id)
                && snapshot
                    .object(object.identity())
                    .map_err(map_catalog)?
                    .is_some()
            {
                Ok(operation)
            } else {
                Err(DurableOperationFailure::IdempotencyConflict)
            };
        }
        if operation.status() != DurableOperationStatus::Running
            || operation.upgrade_stage() != Some(UpgradeStage::Verifying)
        {
            return Err(DurableOperationFailure::InvalidState);
        }
        if let Some(resumed) = Self::resume_upgrade_verification(catalog, actor, id)? {
            return Ok(resumed);
        }
        verify_report(&snapshot, id, report)?;
        let mut completed = operation.succeeded(now)?;
        let mut progress = completed
            .upgrade_progress
            .ok_or(DurableOperationFailure::InvalidState)?;
        progress.stage = UpgradeStage::Succeeded;
        progress.report = Some(report_id);
        completed.upgrade_progress = Some(progress);
        upgrade_publication::publish_current_with_additions(
            catalog,
            &snapshot,
            completed,
            vec![object],
        )
    }
}
fn verify_report(
    snapshot: &CatalogSnapshot,
    id: OperationId,
    report: &UpgradeVerificationReport,
) -> Result<(), DurableOperationFailure> {
    let publication =
        DurableOperationAdministration::current_upgrade_publication_snapshot(snapshot)?
            .ok_or(DurableOperationFailure::InvalidState)?;
    if publication.operation_id() != id
        || publication.outcome() != UpgradePublicationOutcome::AwaitingVerification
    {
        return Err(DurableOperationFailure::InvalidState);
    }
    let (_, governance) = snapshot.governance_object().map_err(map_catalog)?;
    let integrity = positron_kernel::BootstrapIntegrityIdentity::from_pinned(
        governance.integrity_public_key(),
        governance.integrity_key_fingerprint(),
    )
    .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    report
        .verify(integrity)
        .map_err(|_| DurableOperationFailure::InvalidInput)?;
    let input = report.input();
    if input.instance() != governance.instance()
        || input.operation() != id.to_bytes()
        || input.publication() != publication.object_identity()?
    {
        return Err(DurableOperationFailure::InvalidInput);
    }
    if input.catalog_identity() != snapshot.identity().to_bytes()
        || input.catalog_generation() != snapshot.number()
    {
        return Err(DurableOperationFailure::StaleGeneration);
    }
    let identity = crate::Identity::open(snapshot)
        .map_err(|_| DurableOperationFailure::PersistenceUnavailable)?;
    let query_valid = match input.query() {
        UpgradeQueryVerification::Executed { tenant } => identity
            .query_readable_tenant_ids()
            .any(|id| id.to_bytes() == tenant),
        UpgradeQueryVerification::NotApplicableNoQueryableTenant => {
            identity.query_readable_tenant_ids().next().is_none()
        },
    };
    if !query_valid {
        return Err(DurableOperationFailure::InvalidInput);
    }
    Ok(())
}
