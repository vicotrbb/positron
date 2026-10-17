//! Preserve an authenticated Upgrade recovery predecessor during rejected startup.
use super::*;
use positron_governance::{
    DurableOperationAdministration as Administration, DurableOperationStatus, UpgradeStage,
};
use positron_kernel::{Catalog, TransactionId};

pub(super) fn preserve_drain(
    instance: &crate::InitializedInstance,
) -> Result<bool, BootstrapFailure> {
    let unavailable = || BootstrapFailure::new(BootstrapFailureCode::CatalogUnavailable);
    // Each authenticated Catalog read releases its bounded recovery claim before
    // the next one; do not retain an open Catalog across marker/frontier reads.
    let record = instance.graceful_shutdown_record()?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())?;
    let publication =
        Administration::current_upgrade_publication(&catalog).map_err(|_| unavailable())?;
    // A newer accepted Upgrade supersedes the previous installed release intent.
    let active =
        Administration::next_upgrade_operation(&catalog, None).map_err(|_| unavailable())?;
    let operation = match active {
        Some(operation) => Some(operation),
        None => match publication {
            Some(publication) => Administration::inspect(&catalog, publication.operation_id())
                .map_err(|_| unavailable())?,
            None => None,
        },
    };
    let publication = publication.filter(|publication| {
        operation.is_none_or(|operation| publication.operation_id() == operation.operation_id())
    });
    if operation.is_none() && publication.is_none() {
        return Ok(false);
    }
    let evidence = publication
        .map(|publication| publication.drain())
        .or_else(|| operation.and_then(|operation| operation.upgrade_drain_evidence()));
    let record = match record {
        Some(record) => record,
        None if evidence.is_none() => return Ok(false),
        None => return Err(unavailable()),
    };
    let committed = catalog
        .confirm_committed_transaction(
            TransactionId::new(record.transaction()).map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    // Once the selected release is verified (or explicitly rolled back), an
    // ordinary Serving lifetime may have produced a newer genuine Drain. A
    // rejected artifact must preserve that latest quiescent predecessor rather
    // than reinterpret it as the Upgrade's original rollback snapshot.
    if active.is_none()
        && publication.is_some_and(|publication| {
            publication.verification_report().is_some() || publication.is_rollback()
        })
    {
        if catalog.pin().map_err(|_| unavailable())?.identity() != committed.snapshot().identity()
            || committed.number() != record.catalog_generation()
            || committed.predecessor().to_bytes() != record.predecessor()
        {
            return Err(unavailable());
        }
        drop(committed);
        drop(catalog);
        instance.verify_graceful_shutdown_frontiers(&record)?;
        return Ok(true);
    }
    if let Some(operation) = operation {
        let final_operation = Administration::inspect_snapshot_by_idempotency(
            committed.snapshot(),
            operation.request().idempotency_key(),
        )
        .map_err(|_| unavailable())?;
        let Some(final_operation) = final_operation else {
            return if evidence.is_none() {
                Ok(false)
            } else {
                Err(unavailable())
            };
        };
        if evidence.is_none()
            && (final_operation.upgrade_stage() != Some(UpgradeStage::Draining)
                || catalog.pin().map_err(|_| unavailable())?.identity()
                    != committed.snapshot().identity())
        {
            return Ok(false);
        }
        if final_operation.operation_id() != operation.operation_id()
            || final_operation.target_identity() != Some(instance.instance.to_bytes())
            || final_operation.upgrade_stage() != Some(UpgradeStage::Draining)
            || final_operation.status() != DurableOperationStatus::Running
            || committed.number() != record.catalog_generation()
            || committed.predecessor().to_bytes() != record.predecessor()
        {
            return Err(unavailable());
        }
    }
    match evidence {
        Some(evidence)
            if evidence.marker_identity() == record.marker_identity()
                && evidence.transaction() == record.transaction()
                && evidence.catalog_identity() == committed.snapshot().identity().to_bytes()
                && evidence.catalog_generation() == committed.number() => {},
        None if operation
            .is_some_and(|operation| operation.upgrade_stage() == Some(UpgradeStage::Draining))
            && catalog.pin().map_err(|_| unavailable())?.identity()
                == committed.snapshot().identity() => {},
        _ => return Err(unavailable()),
    }
    drop(committed);
    drop(catalog);
    instance.verify_graceful_shutdown_frontiers(&record)?;
    Ok(true)
}
