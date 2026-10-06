use super::*;

pub(crate) fn publish_many(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    publish_many_with_expected_catalog(catalog, basis, basis.identity(), remove, add)
}

/// Publishes lease records and one already-encoded coordinator record through
/// the same Catalog transaction. The caller retains the coordinator draft and
/// installs it only after this returns success.
pub(crate) fn publish_many_with_catalog_objects(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
    additional: Vec<CatalogObject>,
    replaced_tasks: &BTreeSet<crate::MaintenanceTaskId>,
    reclaimed_task: Option<crate::MaintenanceTaskId>,
) -> Result<(), LedgerFailure> {
    let capacity = basis
        .object_count()
        .checked_add(add.len())
        .and_then(|count| count.checked_add(additional.len()))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(capacity)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        if decode(bytes)?.is_some_and(|record| remove.contains(&record.identity)) {
            continue;
        }
        if crate::maintenance::durable_task_record_identity(bytes)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            .is_some_and(|identity| replaced_tasks.contains(&identity))
        {
            continue;
        }
        let reclaimed_match = match reclaimed_task {
            Some(identity) => {
                crate::maintenance::durable_task_record_identity(bytes)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
                    == Some(identity)
            },
            None => false,
        };
        if reclaimed_match {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    let additional_ids = additional
        .iter()
        .map(CatalogObject::identity)
        .collect::<Vec<_>>();
    for encoded in &add {
        objects.push(CatalogObject::new(encoded.clone())?);
    }
    objects.extend(additional);
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    match catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            transaction,
            basis
                .format_epoch()
                .unwrap_or(FormatEpoch::new(FORMAT_EPOCH)?),
            objects,
        )?,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(failure) => {
            let code = map_catalog_failure(failure.code());
            if code != LedgerFailureCode::StorageUnavailable {
                return Err(LedgerFailure::new(code));
            }
            catalog
                .refresh_state()
                .map_err(|_| LedgerFailure::ambiguous(code))?;
            let current = catalog.pin().map_err(|_| LedgerFailure::ambiguous(code))?;
            let leases_visible = publication_visible(&current, remove, &add)?;
            let tasks_visible = additional_ids.iter().try_fold(true, |visible, identity| {
                Ok::<_, LedgerFailure>(visible && current.object(*identity)?.is_some())
            })?;
            let reclaimed_absent = match reclaimed_task {
                Some(identity) => !current.plaintext_objects().try_fold(
                    false,
                    |found, bytes| -> Result<_, LedgerFailure> {
                        Ok(found
                            || crate::maintenance::durable_task_record_identity(bytes).map_err(
                                |_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption),
                            )? == Some(identity))
                    },
                )?,
                None => true,
            };
            let replacements_visible = replaced_tasks.iter().try_fold(
                true,
                |visible, task| -> Result<_, LedgerFailure> {
                    let count = current.plaintext_objects().try_fold(
                        0_usize,
                        |count, bytes| -> Result<_, LedgerFailure> {
                            Ok(count
                                + usize::from(
                                    crate::maintenance::durable_task_record_identity(bytes)
                                        .map_err(|_| {
                                            LedgerFailure::new(
                                                LedgerFailureCode::IntegrityCorruption,
                                            )
                                        })?
                                        == Some(*task),
                                ))
                        },
                    )?;
                    Ok(visible && count == 1)
                },
            )?;
            if leases_visible && tasks_visible && reclaimed_absent && replacements_visible {
                Ok(())
            } else {
                Err(LedgerFailure::new(code))
            }
        },
    }
}

/// Atomically removes a lease and replaces only its matching maintenance
/// descriptor. The Catalog remains the sole writer for both records.
pub(crate) fn publish_lease_release_with_task_replacement(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    lease: SnapshotLeaseId,
    task: crate::MaintenanceTaskId,
    replacement: CatalogObject,
) -> Result<(), LedgerFailure> {
    let replacement_identity = replacement.identity();
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(basis.object_count())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        if decode(bytes)?.is_some_and(|record| record.identity == lease) {
            continue;
        }
        if crate::maintenance::durable_task_record_identity(bytes)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            .is_some_and(|identity| identity == task)
        {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    objects.push(replacement);
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    match catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            transaction,
            basis
                .format_epoch()
                .unwrap_or(FormatEpoch::new(FORMAT_EPOCH)?),
            objects,
        )?,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(failure) => {
            let code = map_catalog_failure(failure.code());
            if code != LedgerFailureCode::StorageUnavailable {
                return Err(LedgerFailure::new(code));
            }
            catalog
                .refresh_state()
                .map_err(|_| LedgerFailure::ambiguous(code))?;
            let current = catalog.pin().map_err(|_| LedgerFailure::ambiguous(code))?;
            let lease_removed = !records(&current)?
                .iter()
                .any(|record| record.identity == lease);
            if lease_removed && current.object(replacement_identity)?.is_some() {
                Ok(())
            } else {
                Err(LedgerFailure::new(code))
            }
        },
    }
}

pub(crate) fn publish_lease_replacement_with_task_replacements(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    old_lease: SnapshotLeaseId,
    new_lease: Vec<u8>,
    old_task: crate::MaintenanceTaskId,
    cancelled_task: CatalogObject,
    new_task: CatalogObject,
) -> Result<(), LedgerFailure> {
    let cancelled_task_identity = cancelled_task.identity();
    let new_task_identity = new_task.identity();
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(
            basis
                .object_count()
                .checked_add(3)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        if decode(bytes)?.is_some_and(|record| record.identity == old_lease)
            || crate::maintenance::durable_task_record_identity(bytes)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
                .is_some_and(|identity| identity == old_task)
        {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    objects.push(CatalogObject::new(new_lease.clone())?);
    objects.push(cancelled_task);
    objects.push(new_task);
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    match catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            transaction,
            basis
                .format_epoch()
                .unwrap_or(FormatEpoch::new(FORMAT_EPOCH)?),
            objects,
        )?,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(failure) => {
            let code = map_catalog_failure(failure.code());
            if code != LedgerFailureCode::StorageUnavailable {
                return Err(LedgerFailure::new(code));
            }
            catalog
                .refresh_state()
                .map_err(|_| LedgerFailure::ambiguous(code))?;
            let current = catalog.pin().map_err(|_| LedgerFailure::ambiguous(code))?;
            let old_lease_removed = !records(&current)?
                .iter()
                .any(|record| record.identity == old_lease);
            let new_lease_visible = current
                .plaintext_objects()
                .any(|bytes| bytes == new_lease.as_slice());
            let cancellation_visible = current.object(cancelled_task_identity)?.is_some();
            let submission_visible = current.object(new_task_identity)?.is_some();
            if old_lease_removed && new_lease_visible && cancellation_visible && submission_visible
            {
                Ok(())
            } else {
                Err(LedgerFailure::new(code))
            }
        },
    }
}

pub(crate) fn publish_lease_and_task_removals(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    leases: &BTreeSet<SnapshotLeaseId>,
) -> Result<(), LedgerFailure> {
    let task_ids = leases
        .iter()
        .map(|identity| crate::MaintenanceTaskId::new(identity.to_bytes()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(basis.object_count())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        if decode(bytes)?.is_some_and(|record| leases.contains(&record.identity))
            || crate::maintenance::durable_task_record_identity(bytes)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
                .is_some_and(|identity| task_ids.contains(&identity))
        {
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec())?);
    }
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    catalog
        .commit(
            basis.identity(),
            CatalogProposal::new(
                transaction,
                basis
                    .format_epoch()
                    .unwrap_or(FormatEpoch::new(FORMAT_EPOCH)?),
                objects,
            )?,
            None,
        )
        .map_err(|failure| LedgerFailure::new(map_catalog_failure(failure.code())))?;
    Ok(())
}

pub(crate) fn publish_many_with_expected_catalog(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    expected_catalog: crate::CatalogGenerationId,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
) -> Result<(), LedgerFailure> {
    publish_many_with_expected_catalog_inner(
        catalog,
        basis,
        expected_catalog,
        remove,
        add,
        Vec::new(),
        true,
    )
    .map(|_| ())
}

pub(crate) fn publish_many_with_expected_catalog_snapshot(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    expected_catalog: crate::CatalogGenerationId,
    remove: &BTreeSet<SnapshotLeaseId>,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    publish_many_with_expected_catalog_inner(
        catalog,
        basis,
        expected_catalog,
        remove,
        Vec::new(),
        Vec::new(),
        false,
    )
}

fn publish_many_with_expected_catalog_inner(
    catalog: &crate::Catalog<'_>,
    basis: &crate::CatalogSnapshot,
    expected_catalog: crate::CatalogGenerationId,
    remove: &BTreeSet<SnapshotLeaseId>,
    add: Vec<Vec<u8>>,
    additional: Vec<CatalogObject>,
    reconcile_visible: bool,
) -> Result<crate::CatalogSnapshot, LedgerFailure> {
    let capacity = basis
        .plaintext_objects()
        .count()
        .checked_add(add.len())
        .and_then(|count| count.checked_add(additional.len()))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(capacity)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for bytes in basis.plaintext_objects() {
        if decode(bytes)?.is_none_or(|record| !remove.contains(&record.identity)) {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    for encoded in &add {
        objects.push(CatalogObject::new(encoded.clone())?);
    }
    objects.extend(additional);
    let transaction = TransactionId::new(fresh_identity()?.to_bytes())?;
    match catalog.commit(
        expected_catalog,
        CatalogProposal::new(
            transaction,
            basis
                .format_epoch()
                .unwrap_or(FormatEpoch::new(FORMAT_EPOCH)?),
            objects,
        )?,
        None,
    ) {
        Ok(commit) => Ok(commit.snapshot().clone()),
        Err(failure) => {
            let code = map_catalog_failure(failure.code());
            if code == LedgerFailureCode::StaleGeneration {
                return Err(LedgerFailure::new(code));
            }
            if !reconcile_visible {
                return Err(match code {
                    LedgerFailureCode::StorageUnavailable => LedgerFailure::ambiguous(code),
                    _ => LedgerFailure::new(code),
                });
            }
            if catalog.refresh_state().is_err() {
                return Err(LedgerFailure::ambiguous(code));
            }
            let current = catalog.pin().map_err(|_| LedgerFailure::ambiguous(code))?;
            if publication_visible(&current, remove, &add)? {
                Ok(current)
            } else {
                Err(LedgerFailure::new(code))
            }
        },
    }
}

pub(crate) fn publication_visible(
    snapshot: &crate::CatalogSnapshot,
    remove: &BTreeSet<SnapshotLeaseId>,
    additions: &[Vec<u8>],
) -> Result<bool, LedgerFailure> {
    let published_records = records(snapshot)?;
    for identity in remove {
        let replaced =
            additions
                .iter()
                .try_fold(false, |found, addition| -> Result<bool, LedgerFailure> {
                    if found {
                        return Ok(true);
                    }
                    Ok(decode(addition)?.is_some_and(|record| record.identity == *identity))
                })?;
        if !replaced {
            let remains = published_records
                .iter()
                .any(|record| record.identity == *identity);
            if remains {
                return Ok(false);
            }
        }
    }
    for addition in additions {
        if !snapshot
            .plaintext_objects()
            .any(|published| published == addition.as_slice())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn map_catalog_failure(code: CatalogFailureCode) -> LedgerFailureCode {
    match code {
        CatalogFailureCode::InvalidInput => LedgerFailureCode::InvalidInput,
        CatalogFailureCode::LimitExceeded => LedgerFailureCode::LimitExceeded,
        CatalogFailureCode::StaleGeneration => LedgerFailureCode::StaleGeneration,
        CatalogFailureCode::IdempotencyConflict => LedgerFailureCode::IdempotencyConflict,
        CatalogFailureCode::StorageUnavailable => LedgerFailureCode::StorageUnavailable,
        CatalogFailureCode::IntegrityCorruption => LedgerFailureCode::IntegrityCorruption,
        CatalogFailureCode::AuthenticationFailed => LedgerFailureCode::AuthenticationFailed,
        CatalogFailureCode::ConcurrentWriter => LedgerFailureCode::ConcurrentWriter,
        CatalogFailureCode::ResourceAdmissionRefused => LedgerFailureCode::ResourceAdmissionRefused,
        CatalogFailureCode::UnsupportedFormat => LedgerFailureCode::UnsupportedFormat,
    }
}
